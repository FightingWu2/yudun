from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import AssociationORM
from app.schemas.incident import AssociationRecord


class AssociationRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def add(self, item: AssociationRecord) -> AssociationRecord:
        self._session.add(
            AssociationORM(
                association_id=item.association_id,
                incident_id=item.incident_id,
                association_type=item.association_type.value,
                association_basis=item.association_basis.value,
                schema_version=item.schema_version,
                payload=item.model_dump(mode="json"),
                created_at=item.created_at,
            )
        )
        self._session.flush()
        return item

    def list_for_incident(self, incident_id: str) -> list[AssociationRecord]:
        rows = self._session.scalars(
            select(AssociationORM)
            .where(AssociationORM.incident_id == incident_id)
            .order_by(AssociationORM.created_at)
        )
        return [AssociationRecord.model_validate(row.payload) for row in rows]
