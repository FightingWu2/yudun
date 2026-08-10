import hashlib
from datetime import UTC, datetime, timedelta
from typing import Literal, cast

from pydantic import model_validator

from app.core.canonical import canonical_json
from app.core.ids import source_derived_id
from app.domain.enums import EvidenceSensitivity, SourceType
from app.schemas.base import NonEmptyStr, StrictSchema, UtcDateTime
from app.schemas.evidence import (
    EvidenceReference,
    EvidenceType,
    SyntheticEvidenceLocator,
)

SCENARIO_ID: Literal["scenario_api_key_compromise_v1"] = "scenario_api_key_compromise_v1"
SCENARIO_VERSION = "1.0"


class SyntheticEventBase(StrictSchema):
    synthetic_event_id: str
    source_type: Literal[SourceType.SYNTHETIC] = SourceType.SYNTHETIC
    scenario_id: Literal["scenario_api_key_compromise_v1"] = SCENARIO_ID
    tenant_ref: NonEmptyStr
    event_time: UtcDateTime
    runner_ref: NonEmptyStr
    credential_ref: NonEmptyStr
    content_sha256: str

    @model_validator(mode="after")
    def validate_content_hash(self) -> "SyntheticEventBase":
        if not self.synthetic_event_id.startswith("raw_"):
            raise ValueError("synthetic event uses raw_ source-event identity")
        if len(self.content_sha256) != 64:
            raise ValueError("content_sha256 must be SHA-256")
        return self


class CISecurityEvent(SyntheticEventBase):
    event_type: Literal["CI_SECURITY"] = "CI_SECURITY"
    repository_ref: NonEmptyStr
    workflow_ref: NonEmptyStr
    action_ref: NonEmptyStr
    expected_digest: NonEmptyStr
    observed_digest: NonEmptyStr


class SecretAccessEvent(SyntheticEventBase):
    event_type: Literal["SECRET_ACCESS"] = "SECRET_ACCESS"
    access_method: NonEmptyStr
    result: Literal["SUCCEEDED", "FAILED"]


class CredentialExposureEvent(SyntheticEventBase):
    event_type: Literal["CREDENTIAL_EXPOSURE"] = "CREDENTIAL_EXPOSURE"
    exposure_channel: NonEmptyStr
    result: Literal["EXPOSED", "BLOCKED"]


class CloudAPIAuditEvent(SyntheticEventBase):
    event_type: Literal["CLOUD_API_AUDIT"] = "CLOUD_API_AUDIT"
    source_ref: NonEmptyStr
    expected_source: NonEmptyStr
    api_action: NonEmptyStr
    resource_ref: NonEmptyStr
    result: Literal["SUCCEEDED", "FAILED"]


class ResourceAccessEvent(SyntheticEventBase):
    event_type: Literal["RESOURCE_ACCESS"] = "RESOURCE_ACCESS"
    resource_ref: NonEmptyStr
    sensitivity: Literal["SENSITIVE"]
    operation: Literal["READ"]
    result: Literal["SUCCEEDED", "FAILED"]


class ResourceOperationEvent(SyntheticEventBase):
    event_type: Literal["RESOURCE_OPERATION"] = "RESOURCE_OPERATION"
    resource_ref: NonEmptyStr
    operation: Literal["CREATE"]
    cost_class: Literal["HIGH"]
    result: Literal["SUCCEEDED", "FAILED"]


SyntheticEvent = (
    CISecurityEvent
    | SecretAccessEvent
    | CredentialExposureEvent
    | CloudAPIAuditEvent
    | ResourceAccessEvent
    | ResourceOperationEvent
)


class GoldenPathReplay(StrictSchema):
    run_id: str
    scenario_id: Literal["scenario_api_key_compromise_v1"] = SCENARIO_ID
    events: list[SyntheticEvent]
    evidence: list[EvidenceReference]


class ScenarioReplayStore:
    """Small P0 store whose reset boundary prevents runs from contaminating each other."""

    def __init__(self) -> None:
        self._current: GoldenPathReplay | None = None

    def reset(self) -> None:
        self._current = None

    def replay(self) -> GoldenPathReplay:
        self.reset()
        self._current = replay_golden_path()
        return self._current.model_copy(deep=True)

    def current(self) -> GoldenPathReplay | None:
        return None if self._current is None else self._current.model_copy(deep=True)


def _event(model: type[SyntheticEventBase], event_time: datetime, **payload: str) -> SyntheticEvent:
    source = {
        "scenario_id": SCENARIO_ID,
        "event_type": model.__name__,
        "event_time": event_time,
        **payload,
    }
    content_hash = hashlib.sha256(canonical_json(source).encode()).hexdigest()
    event_id = source_derived_id("raw", source, SCENARIO_VERSION)
    return cast(
        SyntheticEvent,
        model(
            synthetic_event_id=event_id,
            tenant_ref="tenant_demo_cloud_01",
            runner_ref="runner_ci_01",
            credential_ref="credential_ref_demo_ci",
            event_time=event_time,
            content_sha256=content_hash,
            **payload,
        ),
    )


def replay_golden_path() -> GoldenPathReplay:
    start = datetime(2026, 1, 15, 2, 0, tzinfo=UTC)
    events: list[SyntheticEvent] = [
        _event(
            CISecurityEvent,
            start,
            repository_ref="repo_checkout_service",
            workflow_ref="workflow_release",
            action_ref="third_party/action@v3",
            expected_digest="sha256:baseline-digest-ref",
            observed_digest="sha256:changed-digest-ref",
        ),
        _event(
            SecretAccessEvent,
            start + timedelta(seconds=8),
            access_method="CI_ENV",
            result="SUCCEEDED",
        ),
        _event(
            CredentialExposureEvent,
            start + timedelta(seconds=12),
            exposure_channel="MODIFIED_ACTION_OUTPUT",
            result="EXPOSED",
        ),
        _event(
            CloudAPIAuditEvent,
            start + timedelta(minutes=3),
            source_ref="source_external_203_0_113_50",
            expected_source="source_ci_egress",
            api_action="ListSensitiveObjects",
            resource_ref="bucket_customer_export",
            result="SUCCEEDED",
        ),
        _event(
            ResourceAccessEvent,
            start + timedelta(minutes=4),
            resource_ref="bucket_customer_export",
            sensitivity="SENSITIVE",
            operation="READ",
            result="SUCCEEDED",
        ),
        _event(
            ResourceOperationEvent,
            start + timedelta(minutes=5),
            resource_ref="compute_gpu_cluster_unapproved",
            operation="CREATE",
            cost_class="HIGH",
            result="SUCCEEDED",
        ),
    ]
    evidence = []
    for event in events:
        snapshot = event.model_dump(mode="json")
        evidence.append(
            EvidenceReference(
                evidence_id=source_derived_id(
                    "evd", {"event": event.synthetic_event_id}, SCENARIO_VERSION
                ),
                source_type=SourceType.SYNTHETIC,
                source_dataset=SCENARIO_ID,
                source_record_id=event.synthetic_event_id,
                evidence_type=EvidenceType.SYNTHETIC_EVENT,
                locator=SyntheticEvidenceLocator(
                    synthetic_event_id=event.synthetic_event_id,
                    scenario_id=SCENARIO_ID,
                ),
                content_sha256=event.content_sha256,
                summary=f"Synthetic scenario event: {event.event_type}",
                redacted_snapshot=snapshot,
                sensitivity=EvidenceSensitivity.INTERNAL,
                allowed_agent_types=["SILENT_MONITOR_AGENT", "INVESTIGATION_AGENT", "TRACE_AGENT"],
                created_by="SYNTHETIC_SCENARIO_REPLAYER",
                created_at=event.event_time,
            )
        )
    return GoldenPathReplay(
        run_id=source_derived_id("run", {"scenario_id": SCENARIO_ID}, SCENARIO_VERSION),
        events=events,
        evidence=evidence,
    )
