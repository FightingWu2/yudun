from enum import StrEnum
from typing import Annotated, Literal

from pydantic import Field, JsonValue, model_validator

from app.domain.enums import EvidenceSensitivity, SourceType
from app.schemas.base import NonEmptyStr, Sha256, StrictSchema, TimestampedSchema, require_prefix


class EvidenceType(StrEnum):
    PCAP_PACKET = "PCAP_PACKET"
    NETWORK_FLOW = "NETWORK_FLOW"
    HTTP_EVENT = "HTTP_EVENT"
    DNS_EVENT = "DNS_EVENT"
    SYNTHETIC_EVENT = "SYNTHETIC_EVENT"
    MOCK_STATE = "MOCK_STATE"
    EXECUTION_RECEIPT = "EXECUTION_RECEIPT"
    AUDIT_RECORD = "AUDIT_RECORD"


class OfficialEvidenceLocator(StrictSchema):
    locator_type: Literal["OFFICIAL"] = "OFFICIAL"
    capture_id: str
    packet_indexes: list[Annotated[int, Field(ge=1)]] | None = None
    flow_id: str | None = None
    field_path: str | None = None

    @model_validator(mode="after")
    def validate_locator(self) -> "OfficialEvidenceLocator":
        require_prefix(self.capture_id, "cap")
        if self.flow_id is not None:
            require_prefix(self.flow_id, "flw")
        if not self.packet_indexes and self.flow_id is None:
            raise ValueError("OFFICIAL locator requires packet_indexes or flow_id")
        return self


class SyntheticEvidenceLocator(StrictSchema):
    locator_type: Literal["SYNTHETIC"] = "SYNTHETIC"
    synthetic_event_id: NonEmptyStr
    scenario_id: NonEmptyStr
    field_path: str | None = None


class MockEvidenceLocator(StrictSchema):
    locator_type: Literal["MOCK"] = "MOCK"
    state_snapshot_id: str | None = None
    operation_id: NonEmptyStr | None = None
    field_path: str | None = None

    @model_validator(mode="after")
    def validate_locator(self) -> "MockEvidenceLocator":
        if self.state_snapshot_id is None and self.operation_id is None:
            raise ValueError("MOCK locator requires state_snapshot_id or operation_id")
        if self.state_snapshot_id is not None:
            require_prefix(self.state_snapshot_id, "snp")
        return self


class SystemEvidenceLocator(StrictSchema):
    locator_type: Literal["SYSTEM"] = "SYSTEM"
    audit_id: str
    record_type: NonEmptyStr
    field_path: str | None = None

    @model_validator(mode="after")
    def validate_locator(self) -> "SystemEvidenceLocator":
        require_prefix(self.audit_id, "aud")
        return self


EvidenceLocator = Annotated[
    OfficialEvidenceLocator
    | SyntheticEvidenceLocator
    | MockEvidenceLocator
    | SystemEvidenceLocator,
    Field(discriminator="locator_type"),
]


class EvidenceReference(TimestampedSchema):
    evidence_id: str
    incident_id: str | None = None
    source_type: SourceType
    source_dataset: NonEmptyStr
    source_record_id: NonEmptyStr
    evidence_type: EvidenceType
    locator: EvidenceLocator
    content_sha256: Sha256
    summary: NonEmptyStr
    redacted_snapshot: dict[str, JsonValue] | None = None
    sensitivity: EvidenceSensitivity
    allowed_agent_types: list[str] = Field(min_length=1)
    created_by: NonEmptyStr
    supersedes_evidence_id: str | None = None
    correction_reason: str | None = None

    @model_validator(mode="after")
    def validate_evidence(self) -> "EvidenceReference":
        require_prefix(self.evidence_id, "evd")
        if self.incident_id is not None:
            require_prefix(self.incident_id, "inc")
        expected_locator = {
            SourceType.OFFICIAL: OfficialEvidenceLocator,
            SourceType.SYNTHETIC: SyntheticEvidenceLocator,
            SourceType.MOCK: MockEvidenceLocator,
            SourceType.SYSTEM: SystemEvidenceLocator,
        }[self.source_type]
        if not isinstance(self.locator, expected_locator):
            raise ValueError("locator does not match source_type")
        expected_types = {
            SourceType.OFFICIAL: {
                EvidenceType.PCAP_PACKET,
                EvidenceType.NETWORK_FLOW,
                EvidenceType.HTTP_EVENT,
                EvidenceType.DNS_EVENT,
            },
            SourceType.SYNTHETIC: {EvidenceType.SYNTHETIC_EVENT},
            SourceType.MOCK: {EvidenceType.MOCK_STATE, EvidenceType.EXECUTION_RECEIPT},
            SourceType.SYSTEM: {EvidenceType.AUDIT_RECORD, EvidenceType.EXECUTION_RECEIPT},
        }[self.source_type]
        if self.evidence_type not in expected_types:
            raise ValueError("evidence_type does not match source_type")
        if self.supersedes_evidence_id is not None:
            require_prefix(self.supersedes_evidence_id, "evd")
            if not self.correction_reason:
                raise ValueError("correction_reason is required when superseding evidence")
        elif self.correction_reason is not None:
            raise ValueError("correction_reason requires supersedes_evidence_id")
        return self
