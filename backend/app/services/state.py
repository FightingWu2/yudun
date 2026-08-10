from pydantic import Field
from sqlalchemy.orm import Session

from app.audit.service import AuditService
from app.core.errors import InvalidStateTransitionError
from app.core.time import utc_now
from app.domain.enums import IncidentStatus
from app.repositories.incidents import IncidentRepository
from app.schemas.audit import AuditActorType
from app.schemas.base import StrictSchema
from app.schemas.incident import SecurityIncident
from app.services.facts import GoldenPathFactType


class TransitionContext(StrictSchema):
    valid_signal_count: int = Field(default=0, ge=0)
    valid_task_count: int = Field(default=0, ge=0)
    fact_types: set[GoldenPathFactType] = Field(default_factory=set)
    containment_verified: bool = False
    rotation_verified: bool = False
    recovery_assertions_passed: bool = False
    audit_complete: bool = False
    report_generated: bool = False
    pending_high_risk_actions: int = Field(default=0, ge=0)


_NEXT = {
    IncidentStatus.NEW: IncidentStatus.DETECTED,
    IncidentStatus.DETECTED: IncidentStatus.INVESTIGATING,
    IncidentStatus.INVESTIGATING: IncidentStatus.ATTRIBUTED,
    IncidentStatus.ATTRIBUTED: IncidentStatus.CONTAINED,
    IncidentStatus.CONTAINED: IncidentStatus.ROTATED,
    IncidentStatus.ROTATED: IncidentStatus.VERIFIED,
    IncidentStatus.VERIFIED: IncidentStatus.CLOSED,
}


class EventStateManager:
    def __init__(self, session: Session) -> None:
        self._incidents = IncidentRepository(session)
        self._audit = AuditService(session)

    def transition(
        self,
        incident_id: str,
        target: IncidentStatus,
        context: TransitionContext,
        *,
        proposed_by: str,
    ) -> SecurityIncident:
        incident = self._incidents.get(incident_id)
        if incident is None:
            raise ValueError(f"incident not found: {incident_id}")
        reason = self._guard(incident.status, target, context)
        if reason is not None:
            self._audit.append(
                incident_id=incident_id,
                actor_type=AuditActorType.SYSTEM,
                actor_id="EVENT_STATE_MANAGER",
                event_type="STATE_TRANSITION_DENIED",
                object_type="SecurityIncident",
                object_id=incident_id,
                summary=f"Denied {incident.status.value} to {target.value}",
                payload={"reason": reason, "proposed_by": proposed_by},
            )
            raise InvalidStateTransitionError(reason)
        now = utc_now()
        updated = incident.model_copy(
            update={
                "status": target,
                "updated_at": now,
                "closed_at": now if target is IncidentStatus.CLOSED else None,
            }
        )
        result = self._incidents.update(
            updated,
            expected_version=incident.version,
            status_writer="EVENT_STATE_MANAGER",
        )
        self._audit.append(
            incident_id=incident_id,
            actor_type=AuditActorType.SYSTEM,
            actor_id="EVENT_STATE_MANAGER",
            event_type="STATE_TRANSITIONED",
            object_type="SecurityIncident",
            object_id=incident_id,
            summary=f"Transitioned to {target.value}",
            payload={"proposed_by": proposed_by},
        )
        return result

    @staticmethod
    def _guard(
        current: IncidentStatus, target: IncidentStatus, context: TransitionContext
    ) -> str | None:
        if _NEXT.get(current) is not target:
            return f"transition {current.value} to {target.value} is not allowed"
        if target is IncidentStatus.DETECTED and context.valid_signal_count < 1:
            return "at least one evidence-backed signal is required"
        if target is IncidentStatus.INVESTIGATING and context.valid_task_count < 1:
            return "at least one authorized task is required"
        if target is IncidentStatus.ATTRIBUTED and context.fact_types != set(GoldenPathFactType):
            return "all six Golden Path facts are required"
        if target is IncidentStatus.CONTAINED and not context.containment_verified:
            return "approved containment and state readback are required"
        if target is IncidentStatus.ROTATED and not context.rotation_verified:
            return "new credential and CI binding verification are required"
        if target is IncidentStatus.VERIFIED and not context.recovery_assertions_passed:
            return "all recovery assertions must pass"
        if target is IncidentStatus.CLOSED and not (
            context.audit_complete
            and context.report_generated
            and context.pending_high_risk_actions == 0
        ):
            return "complete audit, report, and no pending high-risk action are required"
        return None
