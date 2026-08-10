from datetime import UTC, datetime
from typing import Any

import pytest
from app.core.ids import runtime_id, source_derived_id
from app.domain.enums import (
    ApprovalDecision,
    AutomationState,
    ConfidenceLevel,
    EvidenceSensitivity,
    ExecutionStatus,
    FactSupportType,
    IncidentStatus,
    PolicyOutcome,
    Severity,
    SourceType,
    TaskStatus,
    VerificationAssertionType,
)
from app.schemas import (
    ActionRecommendation,
    ActionRequest,
    AgentFinding,
    AgentResult,
    AgentTask,
    ApprovalRecord,
    AssociationRecord,
    AuditRecord,
    CaptureRecord,
    ConfirmedFact,
    DNSEvent,
    EvidenceReference,
    ExecutionResult,
    HTTPEvent,
    NetworkFlow,
    PolicyDecision,
    RawEvent,
    RiskAssessment,
    SecurityIncident,
    SecuritySignal,
    VerificationResult,
)
from app.schemas.action import (
    ActionOperation,
    ActionParameters,
    ActionRequestStatus,
    ActionType,
    ApprovalRequirement,
    OperationResult,
    OperationType,
    PolicyCheck,
    RecommendationType,
    VerificationAssertion,
    VerificationNextStep,
    VerificationObservation,
    VerificationStatus,
)
from app.schemas.agent import AllowedContext, TaskCreator, TaskType
from app.schemas.analysis import DetectorRef, DetectorType, SignalStatus, SignalType
from app.schemas.audit import AuditActorType
from app.schemas.data import (
    ApplicationProtocol,
    CaptureFormat,
    CaptureParseStatus,
    DatasetLocation,
    DnsParseStatus,
    DnsQueryType,
    EventKind,
    EventParseStatus,
    FiveTuple,
    FlowDirection,
    FlowSourceLocation,
    GenericSourceLocation,
    HttpMethod,
    HttpParseStatus,
    RedactionStatus,
    TransportProtocol,
)
from app.schemas.evidence import EvidenceType, OfficialEvidenceLocator
from app.schemas.incident import AssociationBasis, AssociationType, IncidentType
from pydantic import ValidationError

NOW = datetime(2026, 8, 10, tzinfo=UTC)
SHA = "a" * 64


def source_id(prefix: str, value: str) -> str:
    return source_derived_id(prefix, {"fixture": value}, "test-v1")


def build_valid_models() -> list[tuple[type[Any], Any, str]]:
    capture_id = source_id("cap", "capture")
    raw_id = source_id("raw", "packet-1")
    flow_id = source_id("flw", "flow-1")
    evidence_id = source_id("evd", "packet-1")
    incident_id = runtime_id("inc")
    signal_id = runtime_id("sig")
    fact_id = runtime_id("fac")
    task_id = runtime_id("tsk")
    finding_id = runtime_id("fnd")
    recommendation_id = runtime_id("rec")
    action_request_id = runtime_id("arq")
    execution_id = runtime_id("exe")
    snapshot_before = runtime_id("snp")
    snapshot_after = runtime_id("snp")

    location = FlowSourceLocation(capture_id=capture_id, first_packet_index=1, last_packet_index=2)
    evidence = EvidenceReference(
        evidence_id=evidence_id,
        incident_id=incident_id,
        source_type=SourceType.OFFICIAL,
        source_dataset="official_nta",
        source_record_id=raw_id,
        evidence_type=EvidenceType.PCAP_PACKET,
        locator=OfficialEvidenceLocator(capture_id=capture_id, packet_indexes=[1]),
        content_sha256=SHA,
        summary="Packet 1 contains a redacted request",
        sensitivity=EvidenceSensitivity.INTERNAL,
        allowed_agent_types=["INVESTIGATION_AGENT"],
        created_by="EVIDENCE_SERVICE",
        created_at=NOW,
    )
    action_request = ActionRequest(
        action_request_id=action_request_id,
        incident_id=incident_id,
        recommendation_id=recommendation_id,
        action_type=ActionType.CREDENTIAL_CONTAINMENT_PLAN,
        target_ref="credential_ref_demo",
        operations=[
            ActionOperation(
                operation_type=OperationType.FREEZE_OLD_KEY,
                operation_id="op_freeze",
                parameters=ActionParameters(credential_ref="credential_ref_demo"),
            ),
            ActionOperation(
                operation_type=OperationType.CREATE_NEW_KEY_VERSION,
                operation_id="op_create",
                parameters=ActionParameters(credential_ref="credential_ref_demo"),
            ),
            ActionOperation(
                operation_type=OperationType.UPDATE_CI_BINDING,
                operation_id="op_bind",
                parameters=ActionParameters(
                    credential_ref="credential_ref_demo",
                    runner_ref="runner_demo",
                    new_version_ref="version_new",
                ),
            ),
        ],
        reason="Contain confirmed credential abuse",
        fact_refs=[fact_id],
        idempotency_key="idem_fixture",
        status=ActionRequestStatus.DRAFT,
        created_at=NOW,
    )
    assertion = VerificationAssertion(
        assertion_type=VerificationAssertionType.OLD_KEY_DISABLED,
        passed=True,
        observed_value=VerificationObservation(actual=False, expected=False),
        evidence_refs=[evidence_id],
        checked_at=NOW,
    )
    models: list[tuple[type[Any], Any, str]] = [
        (
            CaptureRecord,
            CaptureRecord(
                capture_id=capture_id,
                source_type=SourceType.OFFICIAL,
                source_id="fixture.pcap",
                safe_display_name="fixture.pcap",
                source_location=DatasetLocation(
                    dataset="official_nta", relative_path="samples/fixture.pcap"
                ),
                file_sha256=SHA,
                format=CaptureFormat.PCAP,
                file_size=42,
                parser_version="test-v1",
                parse_status=CaptureParseStatus.PENDING,
                created_at=NOW,
            ),
            "capture_id",
        ),
        (
            RawEvent,
            RawEvent(
                event_id=raw_id,
                capture_id=capture_id,
                source_type=SourceType.OFFICIAL,
                source_id="fixture.pcap#1",
                source_location=GenericSourceLocation(
                    dataset="official_nta", record_ref="fixture.pcap#1"
                ),
                source_timestamp=NOW,
                ingested_at=NOW,
                event_kind=EventKind.PACKET,
                src_ip="192.0.2.1",
                dst_ip="198.51.100.1",
                src_port=12345,
                dst_port=80,
                transport_protocol=TransportProtocol.TCP,
                application_protocol=ApplicationProtocol.HTTP,
                parser_version="test-v1",
                parse_status=EventParseStatus.PARSED,
                redaction_status=RedactionStatus.REDACTED,
                created_at=NOW,
            ),
            "event_id",
        ),
        (
            NetworkFlow,
            NetworkFlow(
                flow_id=flow_id,
                capture_id=capture_id,
                source_type=SourceType.OFFICIAL,
                source_id="fixture-flow",
                source_location=location,
                source_timestamp=NOW,
                five_tuple=FiveTuple(
                    initiator_ip="192.0.2.1",
                    initiator_port=12345,
                    responder_ip="198.51.100.1",
                    responder_port=80,
                    protocol=TransportProtocol.TCP,
                ),
                start_time=NOW,
                end_time=NOW,
                packet_count=2,
                byte_count=128,
                direction=FlowDirection.BIDIRECTIONAL,
                application_protocol=ApplicationProtocol.HTTP,
                raw_event_ids=[raw_id],
                parser_version="test-v1",
                created_at=NOW,
            ),
            "flow_id",
        ),
        (
            HTTPEvent,
            HTTPEvent(
                http_event_id=raw_id,
                flow_id=flow_id,
                capture_id=capture_id,
                source_type=SourceType.OFFICIAL,
                source_id="fixture-http",
                source_location=location,
                source_timestamp=NOW,
                request_packet_range=(1, 1),
                method=HttpMethod.GET,
                scheme="http",
                host="example.test",
                uri_path="/health",
                headers_redacted={"authorization": "[REDACTED]"},
                parse_status=HttpParseStatus.REQUEST_ONLY,
                parser_version="test-v1",
                created_at=NOW,
            ),
            "http_event_id",
        ),
        (
            DNSEvent,
            DNSEvent(
                dns_event_id=raw_id,
                flow_id=flow_id,
                capture_id=capture_id,
                source_type=SourceType.OFFICIAL,
                source_id="fixture-dns",
                source_location=location,
                source_timestamp=NOW,
                src_ip="192.0.2.1",
                src_port=53000,
                dns_server="198.51.100.53",
                query_id=1,
                query_name="example.test",
                query_type=DnsQueryType.A,
                packet_indexes=[1],
                parse_status=DnsParseStatus.QUERY_ONLY,
                parser_version="test-v1",
                created_at=NOW,
            ),
            "dns_event_id",
        ),
        (EvidenceReference, evidence, "evidence_id"),
        (
            SecuritySignal,
            SecuritySignal(
                signal_id=signal_id,
                incident_id=incident_id,
                signal_type=SignalType.NTA_SQLI,
                severity=Severity.HIGH,
                subject_refs=[flow_id],
                trigger_reason="Versioned rule matched normalized structure",
                detector=DetectorRef(
                    detector_type=DetectorType.RULE,
                    detector_id="NTA-SQLI-001",
                    detector_version="1.0",
                ),
                evidence_refs=[evidence_id],
                source_types=[SourceType.OFFICIAL],
                status=SignalStatus.OPEN,
                created_at=NOW,
            ),
            "signal_id",
        ),
        (
            ConfirmedFact,
            ConfirmedFact(
                fact_id=fact_id,
                incident_id=incident_id,
                fact_type="CREDENTIAL_ABUSED",
                subject_refs=["credential_ref_demo"],
                statement="The referenced credential was used from an unexpected source",
                evidence_refs=[evidence_id],
                support_type=FactSupportType.CORROBORATED,
                confidence_level=ConfidenceLevel.HIGH,
                confidence_basis="Two independently referenced events",
                proposed_by="MAIN_AGENT",
                created_at=NOW,
            ),
            "fact_id",
        ),
        (
            RiskAssessment,
            RiskAssessment(
                assessment_id=runtime_id("rsk"),
                incident_id=incident_id,
                severity=Severity.HIGH,
                affected_subjects=["tenant_demo"],
                impact_summary="Credential abuse affects a synthetic tenant resource",
                fact_refs=[fact_id],
                assessed_by="MAIN_AGENT",
                created_at=NOW,
            ),
            "assessment_id",
        ),
        (
            AgentTask,
            AgentTask(
                task_id=task_id,
                incident_id=incident_id,
                task_type=TaskType.INVESTIGATE,
                task_goal="Confirm credential use",
                allowed_context=AllowedContext(signal_refs=[signal_id]),
                evidence_refs=[evidence_id],
                allowed_tools=["get_evidence"],
                expected_output="Structured AgentResult",
                assigned_agent_type="INVESTIGATION_AGENT",
                status=TaskStatus.PENDING,
                created_by=TaskCreator.MAIN_AGENT,
                created_at=NOW,
            ),
            "task_id",
        ),
        (
            AgentFinding,
            AgentFinding(
                finding_id=finding_id,
                incident_id=incident_id,
                task_id=task_id,
                finding_type="CREDENTIAL_USE",
                statement="Evidence indicates synthetic credential use",
                evidence_refs=[evidence_id],
                confidence_level=ConfidenceLevel.MEDIUM,
                created_at=NOW,
            ),
            "finding_id",
        ),
        (
            AgentResult,
            AgentResult(
                result_id=runtime_id("res"),
                task_id=task_id,
                incident_id=incident_id,
                task_status=TaskStatus.COMPLETED,
                findings=[finding_id],
                evidence_refs=[evidence_id],
                confidence_level=ConfidenceLevel.MEDIUM,
                confidence_basis="Evidence was available",
                approval_required=False,
                created_at=NOW,
            ),
            "result_id",
        ),
        (
            SecurityIncident,
            SecurityIncident(
                incident_id=incident_id,
                title="Synthetic API credential incident",
                incident_type=IncidentType.API_CREDENTIAL_COMPROMISE,
                tenant_ref="tenant_demo",
                status=IncidentStatus.INVESTIGATING,
                automation_state=AutomationState.ACTIVE,
                severity=Severity.HIGH,
                signal_refs=[signal_id],
                fact_refs=[fact_id],
                task_refs=[task_id],
                summary="Investigation is active",
                opened_at=NOW,
                updated_at=NOW,
                created_at=NOW,
            ),
            "incident_id",
        ),
        (
            AssociationRecord,
            AssociationRecord(
                association_id=runtime_id("asc"),
                incident_id=incident_id,
                left_object_ref="official_fixture",
                right_object_ref="synthetic_fixture",
                association_type=AssociationType.DEMO_SCENARIO,
                association_basis=AssociationBasis.DEMO_SCENARIO,
                evidence_refs=[evidence_id],
                created_by="SCENARIO_LOADER",
                created_at=NOW,
            ),
            "association_id",
        ),
        (
            ActionRecommendation,
            ActionRecommendation(
                recommendation_id=recommendation_id,
                incident_id=incident_id,
                recommendation_type=RecommendationType.CONTAIN_AND_ROTATE_CREDENTIAL,
                rationale="Confirmed facts support containment",
                fact_refs=[fact_id],
                expected_effect="Old credential becomes inactive",
                business_risks=["CI may be interrupted"],
                created_at=NOW,
            ),
            "recommendation_id",
        ),
        (ActionRequest, action_request, "action_request_id"),
        (
            PolicyDecision,
            PolicyDecision(
                policy_decision_id=runtime_id("pol"),
                action_request_id=action_request_id,
                decision=PolicyOutcome.ALLOW_WITH_APPROVAL,
                policy_version="1.0",
                checks=[PolicyCheck(check_id="action_allowlist", passed=True, reason="Allowed")],
                approval_requirement=ApprovalRequirement.HUMAN_REQUIRED,
                created_at=NOW,
            ),
            "policy_decision_id",
        ),
        (
            ApprovalRecord,
            ApprovalRecord(
                approval_id=runtime_id("apr"),
                action_request_id=action_request_id,
                decision=ApprovalDecision.APPROVED,
                approver_id="approver_demo",
                comment="Approved for fixture",
                request_digest=SHA,
                decided_at=NOW,
            ),
            "approval_id",
        ),
        (
            ExecutionResult,
            ExecutionResult(
                execution_id=execution_id,
                action_request_id=action_request_id,
                operation_results=[
                    OperationResult(
                        operation_id="op_freeze",
                        status=ExecutionStatus.SUCCEEDED,
                        state_snapshot_before=snapshot_before,
                        state_snapshot_after=snapshot_after,
                        receipt_ref="receipt_fixture",
                    )
                ],
                overall_status=ExecutionStatus.SUCCEEDED,
                idempotency_key="idem_fixture",
                started_at=NOW,
                completed_at=NOW,
            ),
            "execution_id",
        ),
        (
            VerificationResult,
            VerificationResult(
                verification_id=runtime_id("ver"),
                incident_id=incident_id,
                execution_id=execution_id,
                assertions=[assertion],
                overall_status=VerificationStatus.PASSED,
                next_step=VerificationNextStep.CLOSE,
                created_at=NOW,
            ),
            "verification_id",
        ),
        (
            AuditRecord,
            AuditRecord(
                audit_id=runtime_id("aud"),
                incident_id=incident_id,
                sequence_no=1,
                actor_type=AuditActorType.SYSTEM,
                actor_id="fixture",
                event_type="FIXTURE_CREATED",
                object_type="EvidenceReference",
                object_id=evidence_id,
                summary="Fixture audit entry",
                payload_redacted={"authorization": "[REDACTED]"},
                occurred_at=NOW,
                record_hash=SHA,
            ),
            "audit_id",
        ),
    ]
    return models


@pytest.mark.parametrize(("schema_type", "instance", "required_field"), build_valid_models())
def test_valid_schema_round_trip(
    schema_type: type[Any], instance: Any, required_field: str
) -> None:
    payload = instance.model_dump(mode="python")
    assert schema_type.model_validate(payload) == instance
    assert required_field in payload


@pytest.mark.parametrize(("schema_type", "instance", "required_field"), build_valid_models())
def test_missing_required_field_is_rejected(
    schema_type: type[Any], instance: Any, required_field: str
) -> None:
    payload = instance.model_dump(mode="python")
    payload.pop(required_field)
    with pytest.raises(ValidationError):
        schema_type.model_validate(payload)


def test_invalid_enum_and_naive_time_are_rejected() -> None:
    _, signal, _ = next(row for row in build_valid_models() if row[0] is SecuritySignal)
    bad_enum = signal.model_dump(mode="python")
    bad_enum["severity"] = "IMPOSSIBLE"
    with pytest.raises(ValidationError):
        SecuritySignal.model_validate(bad_enum)

    _, capture, _ = next(row for row in build_valid_models() if row[0] is CaptureRecord)
    bad_time = capture.model_dump(mode="python")
    bad_time["created_at"] = datetime(2026, 8, 10)
    with pytest.raises(ValidationError, match="naive"):
        CaptureRecord.model_validate(bad_time)


def test_invalid_ip_port_and_path_are_rejected() -> None:
    _, event, _ = next(row for row in build_valid_models() if row[0] is RawEvent)
    bad_ip = event.model_dump(mode="python")
    bad_ip["src_ip"] = "999.1.1.1"
    with pytest.raises(ValidationError):
        RawEvent.model_validate(bad_ip)

    bad_port = event.model_dump(mode="python")
    bad_port["src_port"] = 70000
    with pytest.raises(ValidationError):
        RawEvent.model_validate(bad_port)

    with pytest.raises(ValidationError, match="safe relative"):
        DatasetLocation(dataset="official_nta", relative_path="../secret.pcap")


def test_signal_and_fact_require_evidence() -> None:
    _, signal, _ = next(row for row in build_valid_models() if row[0] is SecuritySignal)
    payload = signal.model_dump(mode="python")
    payload["evidence_refs"] = []
    with pytest.raises(ValidationError):
        SecuritySignal.model_validate(payload)

    _, fact, _ = next(row for row in build_valid_models() if row[0] is ConfirmedFact)
    payload = fact.model_dump(mode="python")
    payload["evidence_refs"] = []
    with pytest.raises(ValidationError):
        ConfirmedFact.model_validate(payload)


def test_wrong_evidence_locator_and_source_type_are_rejected() -> None:
    _, evidence, _ = next(row for row in build_valid_models() if row[0] is EvidenceReference)
    payload = evidence.model_dump(mode="python")
    payload["source_type"] = SourceType.SYNTHETIC
    with pytest.raises(ValidationError, match="locator does not match"):
        EvidenceReference.model_validate(payload)

    with pytest.raises(ValidationError, match="packet_indexes or flow_id"):
        OfficialEvidenceLocator(capture_id=source_id("cap", "empty"))


@pytest.mark.parametrize(
    "secret",
    [
        {"authorization": "Bearer top-secret"},
        {"api_key": "plain-key"},
        {"nested": {"password": "plain-password"}},
    ],
)
def test_plaintext_secret_fields_are_rejected(secret: dict[str, Any]) -> None:
    with pytest.raises(ValidationError, match="sensitive field"):
        GenericSourceLocation(
            dataset="official_nta",
            record_ref="fixture",
            metadata=secret,
        )


def test_plaintext_secret_in_normal_text_is_rejected() -> None:
    _, signal, _ = next(row for row in build_valid_models() if row[0] is SecuritySignal)
    payload = signal.model_dump(mode="python")
    payload["trigger_reason"] = "api_key=plain-key"
    with pytest.raises(ValidationError, match="plaintext secret"):
        SecuritySignal.model_validate(payload)
