from sqlalchemy import select, update
from sqlalchemy.engine import CursorResult
from sqlalchemy.orm import Session

from app.core.errors import ConflictError, PermissionDeniedError
from app.db.models import SecurityIncidentORM
from app.schemas.incident import SecurityIncident


class IncidentRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def add(self, incident: SecurityIncident) -> SecurityIncident:
        row = SecurityIncidentORM(
            incident_id=incident.incident_id,
            tenant_ref=incident.tenant_ref,
            status=incident.status.value,
            automation_state=incident.automation_state.value,
            severity=incident.severity.value,
            version=incident.version,
            opened_at=incident.opened_at,
            updated_at=incident.updated_at,
            schema_version=incident.schema_version,
            payload=incident.model_dump(mode="json"),
            created_at=incident.created_at,
        )
        self._session.add(row)
        self._session.flush()
        return incident

    def get(self, incident_id: str) -> SecurityIncident | None:
        row = self._session.get(SecurityIncidentORM, incident_id)
        return None if row is None else SecurityIncident.model_validate(row.payload)

    def list_by_tenant(self, tenant_ref: str) -> list[SecurityIncident]:
        statement = (
            select(SecurityIncidentORM)
            .where(SecurityIncidentORM.tenant_ref == tenant_ref)
            .order_by(SecurityIncidentORM.opened_at)
        )
        return [
            SecurityIncident.model_validate(row.payload) for row in self._session.scalars(statement)
        ]

    def update(
        self,
        incident: SecurityIncident,
        *,
        expected_version: int,
        status_writer: str | None = None,
    ) -> SecurityIncident:
        current_row = self._session.get(SecurityIncidentORM, incident.incident_id)
        if (
            current_row is not None
            and current_row.status != incident.status.value
            and status_writer != "EVENT_STATE_MANAGER"
        ):
            raise PermissionDeniedError(
                "protected IncidentStatus is writable only by EVENT_STATE_MANAGER"
            )
        next_incident = incident.model_copy(update={"version": expected_version + 1})
        next_incident = SecurityIncident.model_validate(next_incident.model_dump(mode="python"))
        statement = (
            update(SecurityIncidentORM)
            .where(
                SecurityIncidentORM.incident_id == incident.incident_id,
                SecurityIncidentORM.version == expected_version,
            )
            .values(
                tenant_ref=next_incident.tenant_ref,
                status=next_incident.status.value,
                automation_state=next_incident.automation_state.value,
                severity=next_incident.severity.value,
                version=next_incident.version,
                updated_at=next_incident.updated_at,
                payload=next_incident.model_dump(mode="json"),
            )
        )
        result = self._session.execute(statement)
        if not isinstance(result, CursorResult) or result.rowcount != 1:
            raise ConflictError(
                f"incident {incident.incident_id} is not at expected version {expected_version}"
            )
        self._session.flush()
        return next_incident
