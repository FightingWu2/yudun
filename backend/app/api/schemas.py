from pydantic import Field

from app.domain.enums import ApprovalDecision, RunMode
from app.schemas.base import NonEmptyStr, Sha256, StrictSchema


class ReplayStartRequest(StrictSchema):
    official_capture_id: NonEmptyStr
    synthetic_scenario_id: NonEmptyStr
    run_mode: RunMode = RunMode.PRODUCTION_GUARDED
    force_verification_failure: bool = False
    model_failure: bool = False


class ApprovalRequest(StrictSchema):
    action_request_id: str
    decision: ApprovalDecision
    comment: NonEmptyStr
    expected_digest: Sha256
    request_id: NonEmptyStr = Field(min_length=8, max_length=128)


class ApiError(StrictSchema):
    code: NonEmptyStr
    message: NonEmptyStr
    retryable: bool = False
