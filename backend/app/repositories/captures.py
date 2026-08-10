from sqlalchemy.orm import Session

from app.db.models import CaptureORM
from app.schemas.data import CaptureRecord


class CaptureRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def add(self, capture: CaptureRecord) -> CaptureRecord:
        row = CaptureORM(
            capture_id=capture.capture_id,
            source_id=capture.source_id,
            file_sha256=capture.file_sha256,
            parse_status=capture.parse_status.value,
            schema_version=capture.schema_version,
            payload=capture.model_dump(mode="json"),
            created_at=capture.created_at,
        )
        self._session.add(row)
        self._session.flush()
        return capture

    def get(self, capture_id: str) -> CaptureRecord | None:
        row = self._session.get(CaptureORM, capture_id)
        return None if row is None else CaptureRecord.model_validate(row.payload)
