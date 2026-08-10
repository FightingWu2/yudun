from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    event,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class PayloadMixin:
    schema_version: Mapped[str] = mapped_column(String(16), nullable=False, default="1.0")
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class CaptureORM(PayloadMixin, Base):
    __tablename__ = "captures"

    capture_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    source_id: Mapped[str] = mapped_column(String(512), nullable=False)
    file_sha256: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    parse_status: Mapped[str] = mapped_column(String(32), nullable=False)


class RawEventORM(PayloadMixin, Base):
    __tablename__ = "raw_events"

    event_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    capture_id: Mapped[str | None] = mapped_column(
        ForeignKey("captures.capture_id", ondelete="RESTRICT"), nullable=True
    )
    source_type: Mapped[str] = mapped_column(String(16), nullable=False)
    event_kind: Mapped[str] = mapped_column(String(32), nullable=False)
    source_timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class NetworkFlowORM(PayloadMixin, Base):
    __tablename__ = "network_flows"

    flow_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    capture_id: Mapped[str] = mapped_column(
        ForeignKey("captures.capture_id", ondelete="RESTRICT"), nullable=False
    )
    start_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    end_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class HTTPEventORM(PayloadMixin, Base):
    __tablename__ = "http_events"

    http_event_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    flow_id: Mapped[str] = mapped_column(
        ForeignKey("network_flows.flow_id", ondelete="RESTRICT"), nullable=False
    )
    capture_id: Mapped[str] = mapped_column(
        ForeignKey("captures.capture_id", ondelete="RESTRICT"), nullable=False
    )
    source_timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class DNSEventORM(PayloadMixin, Base):
    __tablename__ = "dns_events"

    dns_event_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    flow_id: Mapped[str] = mapped_column(
        ForeignKey("network_flows.flow_id", ondelete="RESTRICT"), nullable=False
    )
    capture_id: Mapped[str] = mapped_column(
        ForeignKey("captures.capture_id", ondelete="RESTRICT"), nullable=False
    )
    source_timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class SecurityIncidentORM(PayloadMixin, Base):
    __tablename__ = "security_incidents"

    incident_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_ref: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    automation_state: Mapped[str] = mapped_column(String(32), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    opened_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class IncidentPayloadMixin(PayloadMixin):
    incident_id: Mapped[str] = mapped_column(
        ForeignKey("security_incidents.incident_id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )


class EvidenceORM(PayloadMixin, Base):
    __tablename__ = "evidence_references"

    evidence_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    incident_id: Mapped[str | None] = mapped_column(
        ForeignKey("security_incidents.incident_id", ondelete="RESTRICT"), nullable=True, index=True
    )
    source_type: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    source_record_id: Mapped[str] = mapped_column(String(255), nullable=False)
    evidence_type: Mapped[str] = mapped_column(String(32), nullable=False)
    content_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    sensitivity: Mapped[str] = mapped_column(String(16), nullable=False)
    allowed_agent_types: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    supersedes_evidence_id: Mapped[str | None] = mapped_column(
        ForeignKey("evidence_references.evidence_id", ondelete="RESTRICT"), nullable=True
    )

    __table_args__ = (
        UniqueConstraint(
            "source_type", "source_record_id", "content_sha256", name="uq_evidence_source_content"
        ),
    )


class SecuritySignalORM(IncidentPayloadMixin, Base):
    __tablename__ = "security_signals"

    signal_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    signal_type: Mapped[str] = mapped_column(String(48), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False)


class ConfirmedFactORM(IncidentPayloadMixin, Base):
    __tablename__ = "confirmed_facts"

    fact_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    fact_type: Mapped[str] = mapped_column(String(64), nullable=False)


class RiskAssessmentORM(IncidentPayloadMixin, Base):
    __tablename__ = "risk_assessments"

    assessment_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)


class AgentTaskORM(IncidentPayloadMixin, Base):
    __tablename__ = "agent_tasks"

    task_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    task_type: Mapped[str] = mapped_column(String(24), nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False)
    assigned_agent_type: Mapped[str] = mapped_column(String(64), nullable=False)


class AgentResultORM(IncidentPayloadMixin, Base):
    __tablename__ = "agent_results"

    result_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    task_id: Mapped[str] = mapped_column(
        ForeignKey("agent_tasks.task_id", ondelete="RESTRICT"), nullable=False, index=True
    )
    task_status: Mapped[str] = mapped_column(String(24), nullable=False)


class AgentFindingORM(IncidentPayloadMixin, Base):
    __tablename__ = "agent_findings"

    finding_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    task_id: Mapped[str] = mapped_column(
        ForeignKey("agent_tasks.task_id", ondelete="RESTRICT"), nullable=False, index=True
    )
    finding_type: Mapped[str] = mapped_column(String(64), nullable=False)


class AssociationORM(IncidentPayloadMixin, Base):
    __tablename__ = "associations"

    association_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    association_type: Mapped[str] = mapped_column(String(32), nullable=False)
    association_basis: Mapped[str] = mapped_column(String(32), nullable=False)


class ActionRecommendationORM(IncidentPayloadMixin, Base):
    __tablename__ = "action_recommendations"

    recommendation_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    recommendation_type: Mapped[str] = mapped_column(String(64), nullable=False)


class ActionRequestORM(IncidentPayloadMixin, Base):
    __tablename__ = "action_requests"

    action_request_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    recommendation_id: Mapped[str] = mapped_column(
        ForeignKey("action_recommendations.recommendation_id", ondelete="RESTRICT"), nullable=False
    )
    action_type: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)


class PolicyDecisionORM(PayloadMixin, Base):
    __tablename__ = "policy_decisions"

    policy_decision_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    action_request_id: Mapped[str] = mapped_column(
        ForeignKey("action_requests.action_request_id", ondelete="RESTRICT"),
        nullable=False,
        unique=True,
    )
    decision: Mapped[str] = mapped_column(String(32), nullable=False)


class ApprovalRecordORM(PayloadMixin, Base):
    __tablename__ = "approval_records"

    approval_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    action_request_id: Mapped[str] = mapped_column(
        ForeignKey("action_requests.action_request_id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    decision: Mapped[str] = mapped_column(String(16), nullable=False)
    request_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class PolicyPreAuthorizationORM(PayloadMixin, Base):
    __tablename__ = "policy_preauthorizations"

    preauthorization_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    incident_id: Mapped[str] = mapped_column(
        ForeignKey("security_incidents.incident_id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    action_request_id: Mapped[str] = mapped_column(
        ForeignKey("action_requests.action_request_id", ondelete="RESTRICT"),
        nullable=False,
        unique=True,
    )
    decision: Mapped[str] = mapped_column(String(32), nullable=False)
    run_mode: Mapped[str] = mapped_column(String(32), nullable=False)
    request_digest: Mapped[str] = mapped_column(String(64), nullable=False)


class ExecutionResultORM(PayloadMixin, Base):
    __tablename__ = "execution_results"

    execution_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    action_request_id: Mapped[str] = mapped_column(
        ForeignKey("action_requests.action_request_id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    overall_status: Mapped[str] = mapped_column(String(24), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)


class VerificationResultORM(IncidentPayloadMixin, Base):
    __tablename__ = "verification_results"

    verification_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    execution_id: Mapped[str] = mapped_column(
        ForeignKey("execution_results.execution_id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    overall_status: Mapped[str] = mapped_column(String(24), nullable=False)


class MockScenarioStateORM(PayloadMixin, Base):
    __tablename__ = "mock_scenario_states"

    scenario_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False)


class StateSnapshotORM(PayloadMixin, Base):
    __tablename__ = "state_snapshots"

    snapshot_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    scenario_id: Mapped[str] = mapped_column(
        ForeignKey("mock_scenario_states.scenario_id", ondelete="RESTRICT"), nullable=False
    )
    operation_id: Mapped[str] = mapped_column(String(128), nullable=False)
    phase: Mapped[str] = mapped_column(String(16), nullable=False)


class AuditRecordORM(Base):
    __tablename__ = "audit_records"

    audit_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    incident_id: Mapped[str | None] = mapped_column(
        ForeignKey("security_incidents.incident_id", ondelete="RESTRICT"), nullable=True, index=True
    )
    chain_key: Mapped[str] = mapped_column(String(64), nullable=False)
    sequence_no: Mapped[int] = mapped_column(Integer, nullable=False)
    actor_type: Mapped[str] = mapped_column(String(16), nullable=False)
    actor_id: Mapped[str] = mapped_column(String(255), nullable=False)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    object_type: Mapped[str] = mapped_column(String(64), nullable=False)
    object_id: Mapped[str] = mapped_column(String(255), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    payload_redacted: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    prev_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    record_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    schema_version: Mapped[str] = mapped_column(String(16), nullable=False, default="1.0")

    __table_args__ = (
        UniqueConstraint("chain_key", "sequence_no", name="uq_audit_chain_sequence"),
        Index("ix_audit_chain_order", "chain_key", "sequence_no"),
    )


class AuditMutationError(RuntimeError):
    pass


class EvidenceMutationError(RuntimeError):
    pass


class SnapshotMutationError(RuntimeError):
    pass


@event.listens_for(EvidenceORM, "before_update")
def reject_evidence_update(_mapper: object, _connection: object, _target: EvidenceORM) -> None:
    raise EvidenceMutationError("EvidenceReference is immutable; append a correction")


@event.listens_for(EvidenceORM, "before_delete")
def reject_evidence_delete(_mapper: object, _connection: object, _target: EvidenceORM) -> None:
    raise EvidenceMutationError("EvidenceReference is immutable and cannot be deleted")


@event.listens_for(StateSnapshotORM, "before_update")
def reject_snapshot_update(_mapper: object, _connection: object, _target: StateSnapshotORM) -> None:
    raise SnapshotMutationError("StateSnapshot is immutable")


@event.listens_for(StateSnapshotORM, "before_delete")
def reject_snapshot_delete(_mapper: object, _connection: object, _target: StateSnapshotORM) -> None:
    raise SnapshotMutationError("StateSnapshot is immutable")


@event.listens_for(AuditRecordORM, "before_update")
def reject_audit_update(_mapper: object, _connection: object, _target: AuditRecordORM) -> None:
    raise AuditMutationError("AuditRecord is append-only and cannot be updated")


@event.listens_for(AuditRecordORM, "before_delete")
def reject_audit_delete(_mapper: object, _connection: object, _target: AuditRecordORM) -> None:
    raise AuditMutationError("AuditRecord is append-only and cannot be deleted")
