from datetime import UTC

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import AuditRecordORM
from app.schemas.audit import AuditRecord


class AuditRepository:
    """Append/read-only repository. Audit update and delete are deliberately absent."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def append(self, record: AuditRecord) -> AuditRecord:
        row = AuditRecordORM(
            audit_id=record.audit_id,
            incident_id=record.incident_id,
            chain_key=record.incident_id or "__GLOBAL__",
            sequence_no=record.sequence_no,
            actor_type=record.actor_type.value,
            actor_id=record.actor_id,
            event_type=record.event_type,
            object_type=record.object_type,
            object_id=record.object_id,
            summary=record.summary,
            payload_redacted=record.payload_redacted,
            occurred_at=record.occurred_at,
            prev_hash=record.prev_hash,
            record_hash=record.record_hash,
            schema_version=record.schema_version,
        )
        self._session.add(row)
        self._session.flush()
        return record

    def list_chain(self, incident_id: str | None) -> list[AuditRecord]:
        chain_key = incident_id or "__GLOBAL__"
        statement = (
            select(AuditRecordORM)
            .where(AuditRecordORM.chain_key == chain_key)
            .order_by(AuditRecordORM.sequence_no)
        )
        return [self._to_schema(row) for row in self._session.scalars(statement)]

    @staticmethod
    def _to_schema(row: AuditRecordORM) -> AuditRecord:
        return AuditRecord(
            audit_id=row.audit_id,
            incident_id=row.incident_id,
            sequence_no=row.sequence_no,
            actor_type=row.actor_type,
            actor_id=row.actor_id,
            event_type=row.event_type,
            object_type=row.object_type,
            object_id=row.object_id,
            summary=row.summary,
            payload_redacted=row.payload_redacted,
            occurred_at=row.occurred_at
            if row.occurred_at.tzinfo is not None
            else row.occurred_at.replace(tzinfo=UTC),
            prev_hash=row.prev_hash,
            record_hash=row.record_hash,
            schema_version=row.schema_version,
        )
