from app.core.ids import source_derived_id
from app.domain.enums import Severity, SourceType
from app.schemas.analysis import DetectorRef, DetectorType, SecuritySignal, SignalStatus, SignalType
from app.schemas.evidence import EvidenceReference
from app.synthetic.scenario import (
    CISecurityEvent,
    CloudAPIAuditEvent,
    GoldenPathReplay,
    ResourceAccessEvent,
    ResourceOperationEvent,
)

SYNTHETIC_RULE_VERSION = "1.0"


def run_synthetic_rules(replay: GoldenPathReplay) -> list[SecuritySignal]:
    evidence_by_event = {item.source_record_id: item for item in replay.evidence}
    signals: list[SecuritySignal] = []
    for event in replay.events:
        signal_type: SignalType | None = None
        severity = Severity.HIGH
        rule_id = ""
        reason = ""
        if isinstance(event, CISecurityEvent) and event.observed_digest != event.expected_digest:
            signal_type = SignalType.CI_ACTION_MUTATION
            rule_id = "SYN-CI-001"
            reason = "Observed CI Action digest differs from the governed baseline digest."
        elif (
            isinstance(event, CloudAPIAuditEvent)
            and event.result == "SUCCEEDED"
            and event.source_ref != event.expected_source
        ):
            signal_type = SignalType.ABNORMAL_CLOUD_API
            rule_id = "SYN-API-001"
            reason = "Credential reference succeeded from a source outside the expected CI egress."
            severity = Severity.CRITICAL
        elif isinstance(event, ResourceAccessEvent) and event.result == "SUCCEEDED":
            signal_type = SignalType.SENSITIVE_DATA_ACCESS
            rule_id = "SYN-IMPACT-001"
            reason = "Sensitive resource read succeeded in the synthetic scenario."
            severity = Severity.CRITICAL
        elif isinstance(event, ResourceOperationEvent) and event.result == "SUCCEEDED":
            signal_type = SignalType.HIGH_COST_CREATION
            rule_id = "SYN-IMPACT-001"
            reason = "High-cost resource creation succeeded in the synthetic scenario."
            severity = Severity.CRITICAL
        if signal_type is None:
            continue
        evidence: EvidenceReference = evidence_by_event[event.synthetic_event_id]
        signals.append(
            SecuritySignal(
                signal_id=source_derived_id(
                    "sig",
                    {"rule_id": rule_id, "evidence_id": evidence.evidence_id},
                    SYNTHETIC_RULE_VERSION,
                ),
                signal_type=signal_type,
                severity=severity,
                subject_refs=[event.runner_ref, event.credential_ref],
                trigger_reason=reason,
                detector=DetectorRef(
                    detector_type=DetectorType.RULE,
                    detector_id=rule_id,
                    detector_version=SYNTHETIC_RULE_VERSION,
                ),
                evidence_refs=[evidence.evidence_id],
                source_types=[SourceType.SYNTHETIC],
                status=SignalStatus.OPEN,
                created_at=event.event_time,
            )
        )
    return signals
