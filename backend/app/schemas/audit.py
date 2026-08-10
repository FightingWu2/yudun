from enum import StrEnum
from typing import Literal

from pydantic import JsonValue, model_validator

from app.schemas.base import NonEmptyStr, Sha256, StrictSchema, UtcDateTime, require_prefix


class AuditActorType(StrEnum):
    HUMAN = "HUMAN"
    AGENT = "AGENT"
    SYSTEM = "SYSTEM"


class AuditRecord(StrictSchema):
    audit_id: str
    incident_id: str | None = None
    sequence_no: int
    actor_type: AuditActorType
    actor_id: NonEmptyStr
    event_type: NonEmptyStr
    object_type: NonEmptyStr
    object_id: NonEmptyStr
    summary: NonEmptyStr
    payload_redacted: dict[str, JsonValue]
    occurred_at: UtcDateTime
    prev_hash: Sha256 | None = None
    record_hash: Sha256
    schema_version: Literal["1.0"] = "1.0"

    @model_validator(mode="after")
    def validate_record(self) -> "AuditRecord":
        require_prefix(self.audit_id, "aud")
        if self.incident_id:
            require_prefix(self.incident_id, "inc")
        if self.sequence_no < 1:
            raise ValueError("sequence_no must be positive")
        return self
