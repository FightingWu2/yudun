from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import SecuritySignalORM
from app.schemas.analysis import SecuritySignal


class SignalRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def add(self, signal: SecuritySignal) -> SecuritySignal:
        self._session.add(
            SecuritySignalORM(
                signal_id=signal.signal_id,
                incident_id=signal.incident_id,
                signal_type=signal.signal_type.value,
                severity=signal.severity.value,
                status=signal.status.value,
                schema_version=signal.schema_version,
                payload=signal.model_dump(mode="json"),
                created_at=signal.created_at,
            )
        )
        self._session.flush()
        return signal

    def get(self, signal_id: str) -> SecuritySignal | None:
        row = self._session.get(SecuritySignalORM, signal_id)
        return None if row is None else SecuritySignal.model_validate(row.payload)

    def list_for_incident(self, incident_id: str) -> list[SecuritySignal]:
        statement = select(SecuritySignalORM).where(SecuritySignalORM.incident_id == incident_id)
        return [
            SecuritySignal.model_validate(row.payload) for row in self._session.scalars(statement)
        ]
