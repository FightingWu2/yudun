from enum import StrEnum

from pydantic import Field, field_validator

from app.schemas.base import NonEmptyStr, StrictSchema, UtcDateTime, require_prefix
from app.schemas.evidence import OfficialEvidenceLocator


class HumanLabel(StrEnum):
    SQL_INJECTION = "SQL_INJECTION"
    COMMAND_INJECTION = "COMMAND_INJECTION"
    WEBSHELL_RCE = "WEBSHELL_RCE"
    DNSLOG = "DNSLOG"
    BACKGROUND = "BACKGROUND"
    NO_MATCH_EXPECTED = "NO_MATCH_EXPECTED"
    AMBIGUOUS = "AMBIGUOUS"
    TLS_OPAQUE = "TLS_OPAQUE"


class ReviewStatus(StrEnum):
    SINGLE_REVIEWED = "SINGLE_REVIEWED"
    DOUBLE_REVIEWED = "DOUBLE_REVIEWED"


class VerifiedSample(StrictSchema):
    sample_id: NonEmptyStr
    capture_id: str
    display_name: NonEmptyStr
    human_label: HumanLabel
    label_basis: NonEmptyStr
    evidence_locator: OfficialEvidenceLocator
    review_status: ReviewStatus
    review_notes: NonEmptyStr
    reviewed_at: UtcDateTime
    reviewer_count: int = Field(ge=1)

    @field_validator("capture_id")
    @classmethod
    def validate_capture_id(cls, value: str) -> str:
        return require_prefix(value, "cap")
