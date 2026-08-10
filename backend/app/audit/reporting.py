from sqlalchemy import select
from sqlalchemy.orm import Session

from app.agents.contracts import (
    AuditReport,
    ReasoningStage,
    ReasoningTraceNode,
)
from app.audit.service import AuditService
from app.core.errors import DomainError, ErrorCode, InvalidStateTransitionError
from app.core.ids import runtime_id
from app.db.models import (
    ActionRequestORM,
    ConfirmedFactORM,
    EvidenceORM,
    VerificationResultORM,
)
from app.domain.enums import ConfidenceLevel, IncidentStatus, SourceType, TaskStatus
from app.repositories.agents import AgentContractRepository
from app.repositories.audit import AuditRepository
from app.repositories.incidents import IncidentRepository
from app.schemas.agent import AgentFinding, AgentResult, AgentTask
from app.schemas.audit import AuditActorType
from app.services.state import EventStateManager, TransitionContext
from app.tools.registry import AgentType, ToolRegistry

_STAGE_BY_EVENT = {
    "SIGNAL_OBSERVED": ReasoningStage.OBSERVATION,
    "EVIDENCE_CREATED": ReasoningStage.EVIDENCE,
    "MAIN_AGENT_TASK_CREATED": ReasoningStage.TASK,
    "INVESTIGATION_AGENT_COMPLETED": ReasoningStage.FINDING,
    "TRACE_AGENT_COMPLETED": ReasoningStage.FINDING,
    "FACT_PROMOTED": ReasoningStage.FACT,
    "ACTION_RECOMMENDATION_CREATED": ReasoningStage.DECISION,
    "POLICY_DECIDED": ReasoningStage.DECISION,
    "POLICY_PREAUTHORIZATION_DECIDED": ReasoningStage.DECISION,
    "ACTION_APPROVAL_DECIDED": ReasoningStage.DECISION,
    "ACTION_REQUEST_CREATED": ReasoningStage.ACTION,
    "CONTROLLED_EXECUTION_COMPLETED": ReasoningStage.OBSERVATION,
    "VERIFICATION_COMPLETED": ReasoningStage.OBSERVATION,
    "VERIFICATION_REPLAN_REQUIRED": ReasoningStage.REPLAN,
    "MAIN_AGENT_REPLAN": ReasoningStage.REPLAN,
    "STATE_TRANSITIONED": ReasoningStage.DECISION,
}


class ReasoningTraceService:
    def __init__(self, session: Session) -> None:
        self._session = session

    def build(self, incident_id: str) -> list[ReasoningTraceNode]:
        records = AuditRepository(self._session).list_chain(incident_id)
        nodes = []
        for record in records:
            stage = _STAGE_BY_EVENT.get(record.event_type)
            if stage is None:
                continue
            output_refs = record.payload_redacted.get("output_refs", [record.object_id])
            input_refs = record.payload_redacted.get("input_object_refs", [])
            if not isinstance(input_refs, list):
                input_refs = []
            for key in ("evidence_refs", "request_id", "recommendation_id"):
                value = record.payload_redacted.get(key)
                if isinstance(value, list):
                    input_refs.extend(str(item) for item in value)
                elif isinstance(value, str):
                    input_refs.append(value)
            nodes.append(
                ReasoningTraceNode(
                    timestamp=record.occurred_at,
                    stage=stage,
                    actor=record.actor_id,
                    object_type=record.object_type,
                    object_id=record.object_id,
                    summary=record.summary,
                    input_refs=input_refs,
                    output_refs=output_refs if isinstance(output_refs, list) else [],
                    source_type=SourceType.SYSTEM,
                    result=record.event_type,
                )
            )
        return nodes


class AuditAgentService:
    def __init__(self, session: Session, registry: ToolRegistry) -> None:
        self._session = session
        self._registry = registry
        self._contracts = AgentContractRepository(session)

    def generate(self, task: AgentTask) -> tuple[AuditReport, AgentFinding, AgentResult]:
        if task.assigned_agent_type != AgentType.AUDIT_AGENT.value:
            raise DomainError(ErrorCode.PERMISSION_DENIED, "task is not assigned to Audit Agent")
        for tool_id in ("query_audit_records", "generate_report_input"):
            self._registry.authorize(
                incident_id=task.incident_id,
                agent_type=AgentType.AUDIT_AGENT,
                tool_id=tool_id,
                declared_tools=set(task.allowed_tools),
                granted_permissions={"audit:read"},
            )
        fact_refs = list(
            self._session.scalars(
                select(ConfirmedFactORM.fact_id).where(
                    ConfirmedFactORM.incident_id == task.incident_id
                )
            )
        )
        evidence_refs = list(
            self._session.scalars(
                select(EvidenceORM.evidence_id).where(EvidenceORM.incident_id == task.incident_id)
            )
        )
        action_refs = list(
            self._session.scalars(
                select(ActionRequestORM.action_request_id).where(
                    ActionRequestORM.incident_id == task.incident_id
                )
            )
        )
        verification_refs = list(
            self._session.scalars(
                select(VerificationResultORM.verification_id).where(
                    VerificationResultORM.incident_id == task.incident_id
                )
            )
        )
        chain_valid = AuditService(self._session).verify_chain(task.incident_id)
        report = AuditReport(
            incident_id=task.incident_id,
            fact_refs=fact_refs,
            evidence_refs=evidence_refs,
            action_refs=action_refs,
            verification_refs=verification_refs,
            audit_chain_valid=chain_valid,
            summary=(
                f"Structured report: {len(fact_refs)} facts, {len(evidence_refs)} evidence "
                f"references, {len(action_refs)} actions, {len(verification_refs)} verifications."
            ),
        )
        finding = AgentFinding(
            finding_id=runtime_id("fnd"),
            incident_id=task.incident_id,
            task_id=task.task_id,
            finding_type="AUDIT_REPORT",
            statement=report.summary,
            evidence_refs=task.evidence_refs,
            confidence_level=ConfidenceLevel.HIGH,
            limitations=[] if chain_valid else ["Audit hash chain verification failed."],
            metadata={"report": report.model_dump(mode="json")},
        )
        self._contracts.add_finding(finding)
        result = AgentResult(
            result_id=runtime_id("res"),
            task_id=task.task_id,
            incident_id=task.incident_id,
            task_status=TaskStatus.COMPLETED if chain_valid else TaskStatus.MANUAL_REQUIRED,
            findings=[finding.finding_id],
            evidence_refs=task.evidence_refs,
            confidence_level=ConfidenceLevel.HIGH,
            confidence_basis="Deterministic database query and audit hash-chain verification.",
            unresolved_questions=[] if chain_valid else ["Audit integrity must be restored."],
            next_step="CLOSE" if chain_valid else "MANUAL",
            approval_required=False,
        )
        self._contracts.add_result(result)
        AuditService(self._session).append(
            incident_id=task.incident_id,
            actor_type=AuditActorType.AGENT,
            actor_id="AUDIT_AGENT",
            event_type="AUDIT_REPORT_GENERATED",
            object_type="AgentResult",
            object_id=result.result_id,
            summary="Audit Agent generated report from structured system objects",
            payload={
                "output_refs": [result.result_id, finding.finding_id],
                "audit_chain_valid": chain_valid,
            },
        )
        return report, finding, result


class IncidentClosureService:
    def __init__(self, session: Session) -> None:
        self._session = session

    def close(self, incident_id: str, report: AuditReport) -> None:
        incident = IncidentRepository(self._session).get(incident_id)
        if incident is None or incident.status is not IncidentStatus.VERIFIED:
            raise InvalidStateTransitionError("incident must be VERIFIED before close")
        if not report.audit_chain_valid or not AuditService(self._session).verify_chain(
            incident_id
        ):
            raise InvalidStateTransitionError("audit chain must be valid before close")
        EventStateManager(self._session).transition(
            incident_id,
            IncidentStatus.CLOSED,
            TransitionContext(
                audit_complete=True,
                report_generated=True,
                pending_high_risk_actions=0,
            ),
            proposed_by="AUDIT_AGENT",
        )
