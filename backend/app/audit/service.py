import hashlib
from collections.abc import Mapping
from typing import cast

from sqlalchemy.orm import Session

from app.core.canonical import canonical_json
from app.core.ids import runtime_id
from app.core.redaction import redact
from app.core.time import utc_now
from app.repositories.audit import AuditRepository
from app.schemas.audit import AuditActorType, AuditRecord


class AuditService:
    def __init__(self, session: Session) -> None:
        self._repository = AuditRepository(session)

    def append(
        self,
        *,
        incident_id: str | None,
        actor_type: AuditActorType,
        actor_id: str,
        event_type: str,
        object_type: str,
        object_id: str,
        summary: str,
        payload: Mapping[str, object],
    ) -> AuditRecord:
        existing = self._repository.list_chain(incident_id)
        sequence_no = len(existing) + 1
        prev_hash = existing[-1].record_hash if existing else None
        record_data = {
            "schema_version": "1.0",
            "audit_id": runtime_id("aud"),
            "incident_id": incident_id,
            "sequence_no": sequence_no,
            "actor_type": actor_type,
            "actor_id": actor_id,
            "event_type": event_type,
            "object_type": object_type,
            "object_id": object_id,
            "summary": cast(str, redact(summary)),
            "payload_redacted": cast(dict[str, object], redact(payload)),
            "occurred_at": utc_now(),
            "prev_hash": prev_hash,
        }
        record_hash = self._hash(record_data)
        record = AuditRecord(**record_data, record_hash=record_hash)
        return self._repository.append(record)

    def verify_chain(self, incident_id: str | None) -> bool:
        records = self._repository.list_chain(incident_id)
        expected_prev: str | None = None
        for expected_sequence, record in enumerate(records, start=1):
            if record.sequence_no != expected_sequence or record.prev_hash != expected_prev:
                return False
            payload = record.model_dump(mode="python", exclude={"record_hash"})
            if self._hash(payload) != record.record_hash:
                return False
            expected_prev = record.record_hash
        return True

    @staticmethod
    def _hash(value: object) -> str:
        return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()
