from dataclasses import dataclass
from enum import StrEnum

from sqlalchemy.orm import Session

from app.audit.service import AuditService
from app.domain.enums import EvidenceSensitivity
from app.repositories.evidence import EvidenceRepository
from app.schemas.audit import AuditActorType
from app.schemas.evidence import EvidenceReference


class AgentType(StrEnum):
    MAIN_AGENT = "MAIN_AGENT"
    SILENT_MONITOR_AGENT = "SILENT_MONITOR_AGENT"
    INVESTIGATION_AGENT = "INVESTIGATION_AGENT"
    TRACE_AGENT = "TRACE_AGENT"
    OPERATION_AGENT = "OPERATION_AGENT"
    AUDIT_AGENT = "AUDIT_AGENT"


@dataclass(frozen=True, slots=True)
class EvidenceAccessContext:
    actor_id: str
    agent_type: AgentType
    incident_id: str | None


class EvidenceError(RuntimeError):
    pass


class EvidenceNotFound(EvidenceError):
    pass


class EvidenceAccessDenied(EvidenceError):
    pass


class EvidenceCorrectionError(EvidenceError):
    pass


class EvidenceService:
    def __init__(self, session: Session) -> None:
        self._repository = EvidenceRepository(session)
        self._audit = AuditService(session)

    def create(self, evidence: EvidenceReference) -> EvidenceReference:
        created = self._repository.add(evidence)
        self._audit.append(
            incident_id=evidence.incident_id,
            actor_type=AuditActorType.SYSTEM,
            actor_id=evidence.created_by,
            event_type="EVIDENCE_CREATED",
            object_type="EvidenceReference",
            object_id=evidence.evidence_id,
            summary="Evidence reference created",
            payload={
                "source_type": evidence.source_type.value,
                "evidence_type": evidence.evidence_type.value,
                "sensitivity": evidence.sensitivity.value,
            },
        )
        return created

    def get_for_agent(self, evidence_id: str, context: EvidenceAccessContext) -> EvidenceReference:
        evidence = self._repository.get(evidence_id)
        if evidence is None:
            self._audit_denial(evidence_id, context, "EVIDENCE_NOT_FOUND")
            raise EvidenceNotFound("evidence does not exist")

        denial_reason = self._denial_reason(evidence, context)
        if denial_reason is not None:
            self._audit_denial(evidence_id, context, denial_reason, evidence.incident_id)
            raise EvidenceAccessDenied(denial_reason)

        self._audit.append(
            incident_id=evidence.incident_id,
            actor_type=AuditActorType.AGENT,
            actor_id=context.actor_id,
            event_type="EVIDENCE_ACCESSED",
            object_type="EvidenceReference",
            object_id=evidence.evidence_id,
            summary="Authorized evidence access",
            payload={"agent_type": context.agent_type.value},
        )
        return evidence

    def append_correction(
        self,
        *,
        original_id: str,
        correction: EvidenceReference,
        context: EvidenceAccessContext,
    ) -> EvidenceReference:
        original = self.get_for_agent(original_id, context)
        if correction.evidence_id == original.evidence_id:
            raise EvidenceCorrectionError("correction must use a new evidence_id")
        if correction.supersedes_evidence_id != original.evidence_id:
            raise EvidenceCorrectionError("correction must reference the superseded evidence")
        if not correction.correction_reason:
            raise EvidenceCorrectionError("correction_reason is required")
        if correction.source_type is not original.source_type:
            raise EvidenceCorrectionError("correction cannot change source_type")
        if correction.source_dataset != original.source_dataset:
            raise EvidenceCorrectionError("correction cannot change source_dataset")

        created = self._repository.add(correction)
        self._audit.append(
            incident_id=correction.incident_id,
            actor_type=AuditActorType.AGENT,
            actor_id=context.actor_id,
            event_type="EVIDENCE_CORRECTION_APPENDED",
            object_type="EvidenceReference",
            object_id=correction.evidence_id,
            summary="Evidence correction appended without overwriting history",
            payload={
                "supersedes_evidence_id": original.evidence_id,
                "correction_reason": correction.correction_reason,
            },
        )
        return created

    @staticmethod
    def _denial_reason(evidence: EvidenceReference, context: EvidenceAccessContext) -> str | None:
        if evidence.sensitivity is EvidenceSensitivity.SECRET:
            return "SECRET_EVIDENCE_DENIED"
        if evidence.incident_id is not None and context.incident_id != evidence.incident_id:
            return "INCIDENT_SCOPE_DENIED"
        if context.agent_type.value not in evidence.allowed_agent_types:
            return "AGENT_TYPE_DENIED"
        return None

    def _audit_denial(
        self,
        evidence_id: str,
        context: EvidenceAccessContext,
        reason: str,
        incident_id: str | None = None,
    ) -> None:
        self._audit.append(
            incident_id=incident_id,
            actor_type=AuditActorType.AGENT,
            actor_id=context.actor_id,
            event_type="EVIDENCE_ACCESS_DENIED",
            object_type="EvidenceReference",
            object_id=evidence_id,
            summary="Evidence access denied by deterministic ACL",
            payload={"agent_type": context.agent_type.value, "reason": reason},
        )
