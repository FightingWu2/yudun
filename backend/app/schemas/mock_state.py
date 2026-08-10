from enum import StrEnum
from typing import Literal

from pydantic import Field, model_validator

from app.domain.enums import ResourceEnvironment, SourceType
from app.schemas.base import NonEmptyStr, StrictSchema, UtcDateTime, require_prefix


class OldVersionStatus(StrEnum):
    ACTIVE = "ACTIVE"
    FROZEN = "FROZEN"
    REVOKED = "REVOKED"


class NewVersionStatus(StrEnum):
    NOT_CREATED = "NOT_CREATED"
    ACTIVE = "ACTIVE"
    FAILED = "FAILED"


class AttemptResult(StrEnum):
    ALLOWED = "ALLOWED"
    DENIED = "DENIED"
    NONE = "NONE"


class BuildStatus(StrEnum):
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    NOT_RUN = "NOT_RUN"


class CreationResult(StrEnum):
    CREATED = "CREATED"
    DENIED = "DENIED"
    NONE = "NONE"


class CredentialState(StrictSchema):
    credential_ref: NonEmptyStr
    old_version_status: OldVersionStatus
    new_version_status: NewVersionStatus
    active_version_ref: NonEmptyStr
    updated_at: UtcDateTime


class AttackState(StrictSchema):
    malicious_source_ref: NonEmptyStr
    old_key_attempt_enabled: bool
    last_attempt_result: AttemptResult
    last_attempt_at: UtcDateTime | None = None


class CIState(StrictSchema):
    runner_ref: NonEmptyStr
    bound_credential_version_ref: NonEmptyStr
    last_build_status: BuildStatus
    updated_at: UtcDateTime


class ResourceState(StrictSchema):
    high_cost_creation_enabled: bool
    abnormal_resource_count: int = Field(ge=0)
    last_creation_result: CreationResult
    updated_at: UtcDateTime


class MockScenarioState(StrictSchema):
    scenario_id: NonEmptyStr
    source_type: Literal[SourceType.MOCK] = SourceType.MOCK
    resource_environment: Literal[ResourceEnvironment.SANDBOX] = ResourceEnvironment.SANDBOX
    credential: CredentialState
    attack: AttackState
    ci: CIState
    resource: ResourceState
    version: int = Field(ge=1)


class StateSnapshot(StrictSchema):
    snapshot_id: str
    scenario_id: NonEmptyStr
    source_type: Literal[SourceType.MOCK] = SourceType.MOCK
    operation_id: NonEmptyStr
    phase: Literal["BEFORE", "AFTER", "READBACK"]
    state: MockScenarioState
    captured_at: UtcDateTime

    @model_validator(mode="after")
    def validate_id(self) -> "StateSnapshot":
        require_prefix(self.snapshot_id, "snp")
        return self
