from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import EvidenceORM
from app.schemas.evidence import EvidenceReference


class EvidenceRepository:
    """Append/read-only repository. Corrections are separate rows."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def add(self, evidence: EvidenceReference) -> EvidenceReference:
        row = EvidenceORM(
            evidence_id=evidence.evidence_id,
            incident_id=evidence.incident_id,
            source_type=evidence.source_type.value,
            source_record_id=evidence.source_record_id,
            evidence_type=evidence.evidence_type.value,
            content_sha256=evidence.content_sha256,
            sensitivity=evidence.sensitivity.value,
            allowed_agent_types=evidence.allowed_agent_types,
            supersedes_evidence_id=evidence.supersedes_evidence_id,
            schema_version=evidence.schema_version,
            payload=evidence.model_dump(mode="json"),
            created_at=evidence.created_at,
        )
        self._session.add(row)
        self._session.flush()
        return evidence

    def get(self, evidence_id: str) -> EvidenceReference | None:
        row = self._session.get(EvidenceORM, evidence_id)
        return None if row is None else EvidenceReference.model_validate(row.payload)

    def list_corrections(self, evidence_id: str) -> list[EvidenceReference]:
        statement = (
            select(EvidenceORM)
            .where(EvidenceORM.supersedes_evidence_id == evidence_id)
            .order_by(EvidenceORM.created_at)
        )
        return [
            EvidenceReference.model_validate(row.payload)
            for row in self._session.scalars(statement)
        ]
