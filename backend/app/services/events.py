from sqlalchemy.orm import Session

from app.core.ids import runtime_id
from app.domain.enums import AutomationState, IncidentStatus
from app.repositories.incidents import IncidentRepository
from app.repositories.signals import SignalRepository
from app.schemas.analysis import SecuritySignal, SignalType
from app.schemas.incident import IncidentType, SecurityIncident


class EventManager:
    def __init__(self, session: Session) -> None:
        self._incidents = IncidentRepository(session)
        self._signals = SignalRepository(session)

    def create_from_ci_signal(self, signal: SecuritySignal, *, tenant_ref: str) -> SecurityIncident:
        if signal.signal_type is not SignalType.CI_ACTION_MUTATION:
            raise ValueError("only CI_ACTION_MUTATION opens the Golden Path incident")
        existing_signal = self._signals.get(signal.signal_id)
        if existing_signal is not None and existing_signal.incident_id is not None:
            existing_incident = self._incidents.get(existing_signal.incident_id)
            if existing_incident is not None:
                return existing_incident
        incident_id = runtime_id("inc")
        linked_signal = signal.model_copy(update={"incident_id": incident_id})
        linked_signal = SecuritySignal.model_validate(linked_signal.model_dump(mode="python"))
        incident = SecurityIncident(
            incident_id=incident_id,
            title="CI Action anomaly and API credential exposure investigation",
            incident_type=IncidentType.API_CREDENTIAL_COMPROMISE,
            tenant_ref=tenant_ref,
            status=IncidentStatus.NEW,
            automation_state=AutomationState.ACTIVE,
            severity=signal.severity,
            signal_refs=[signal.signal_id],
            summary="Synthetic CI Action digest anomaly created an evidence-backed incident.",
            opened_at=signal.created_at,
            updated_at=signal.created_at,
            created_at=signal.created_at,
        )
        self._incidents.add(incident)
        self._signals.add(linked_signal)
        return incident
