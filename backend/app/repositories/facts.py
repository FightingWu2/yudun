from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import ConfirmedFactORM
from app.schemas.analysis import ConfirmedFact


class FactRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def add(self, fact: ConfirmedFact) -> ConfirmedFact:
        row = ConfirmedFactORM(
            fact_id=fact.fact_id,
            incident_id=fact.incident_id,
            fact_type=fact.fact_type,
            schema_version=fact.schema_version,
            payload=fact.model_dump(mode="json"),
            created_at=fact.created_at,
        )
        self._session.add(row)
        self._session.flush()
        return fact

    def list_for_incident(self, incident_id: str) -> list[ConfirmedFact]:
        statement = select(ConfirmedFactORM).where(ConfirmedFactORM.incident_id == incident_id)
        return [
            ConfirmedFact.model_validate(row.payload) for row in self._session.scalars(statement)
        ]
