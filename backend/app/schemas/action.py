from enum import StrEnum
from typing import Literal

from pydantic import Field, JsonValue, model_validator

from app.domain.enums import (
    ApprovalDecision,
    ExecutionStatus,
    PolicyOutcome,
    PreAuthorizationDecision,
    ResourceEnvironment,
    RunMode,
    VerificationAssertionType,
)
from app.schemas.base import (
    NonEmptyStr,
    Sha256,
    StrictSchema,
    TimestampedSchema,
    UtcDateTime,
    require_prefix,
)


class RecommendationType(StrEnum):
    CONTAIN_AND_ROTATE_CREDENTIAL = "CONTAIN_AND_ROTATE_CREDENTIAL"


class ActionRecommendation(TimestampedSchema):
    recommendation_id: str
    incident_id: str
    recommendation_type: RecommendationType
    rationale: NonEmptyStr
    fact_refs: list[str] = Field(min_length=1)
    expected_effect: NonEmptyStr
    business_risks: list[str] = Field(default_factory=list)
    proposed_by: Literal["MAIN_AGENT"] = "MAIN_AGENT"

    @model_validator(mode="after")
    def validate_refs(self) -> "ActionRecommendation":
        require_prefix(self.recommendation_id, "rec")
        require_prefix(self.incident_id, "inc")
        for fact_id in self.fact_refs:
            require_prefix(fact_id, "fac")
        return self


class ActionType(StrEnum):
    CREDENTIAL_CONTAINMENT_PLAN = "CREDENTIAL_CONTAINMENT_PLAN"


class OperationType(StrEnum):
    FREEZE_OLD_KEY = "FREEZE_OLD_KEY"
    CREATE_NEW_KEY_VERSION = "CREATE_NEW_KEY_VERSION"
    UPDATE_CI_BINDING = "UPDATE_CI_BINDING"


class ActionParameters(StrictSchema):
    credential_ref: NonEmptyStr
    runner_ref: str | None = None
    new_version_ref: str | None = None


class ActionOperation(StrictSchema):
    operation_type: OperationType
    operation_id: NonEmptyStr
    parameters: ActionParameters

    @model_validator(mode="after")
    def validate_parameters(self) -> "ActionOperation":
        if self.operation_type is OperationType.UPDATE_CI_BINDING and (
            not self.parameters.runner_ref or not self.parameters.new_version_ref
        ):
            raise ValueError("UPDATE_CI_BINDING requires runner_ref and new_version_ref")
        return self


class ActionRequestStatus(StrEnum):
    DRAFT = "DRAFT"
    POLICY_PENDING = "POLICY_PENDING"
    POLICY_DENIED = "POLICY_DENIED"
    APPROVAL_PENDING = "APPROVAL_PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXECUTING = "EXECUTING"
    EXECUTED = "EXECUTED"
    FAILED = "FAILED"


class ActionRequest(TimestampedSchema):
    action_request_id: str
    incident_id: str
    recommendation_id: str
    action_type: ActionType
    target_ref: NonEmptyStr
    operations: list[ActionOperation] = Field(min_length=1)
    reason: NonEmptyStr
    fact_refs: list[str] = Field(min_length=1)
    requested_by: Literal["OPERATION_AGENT"] = "OPERATION_AGENT"
    risk_level: Literal["HIGH"] = "HIGH"
    idempotency_key: NonEmptyStr
    status: ActionRequestStatus

    @model_validator(mode="after")
    def validate_request(self) -> "ActionRequest":
        require_prefix(self.action_request_id, "arq")
        require_prefix(self.incident_id, "inc")
        require_prefix(self.recommendation_id, "rec")
        for fact_id in self.fact_refs:
            require_prefix(fact_id, "fac")
        operation_ids = [item.operation_id for item in self.operations]
        if len(operation_ids) != len(set(operation_ids)):
            raise ValueError("operation_id values must be unique")
        expected_order = [
            OperationType.FREEZE_OLD_KEY,
            OperationType.CREATE_NEW_KEY_VERSION,
            OperationType.UPDATE_CI_BINDING,
        ]
        if [item.operation_type for item in self.operations] != expected_order:
            raise ValueError("Golden Path operations must use the frozen safe order")
        return self


class PolicyCheck(StrictSchema):
    check_id: NonEmptyStr
    passed: bool
    reason: NonEmptyStr


class ApprovalRequirement(StrEnum):
    HUMAN_REQUIRED = "HUMAN_REQUIRED"
    POLICY_PREAUTHORIZATION_REQUIRED = "POLICY_PREAUTHORIZATION_REQUIRED"
    NOT_ALLOWED = "NOT_ALLOWED"


class PolicyDecision(TimestampedSchema):
    policy_decision_id: str
    action_request_id: str
    decision: PolicyOutcome
    policy_version: NonEmptyStr
    checks: list[PolicyCheck] = Field(min_length=1)
    approval_requirement: ApprovalRequirement
    decided_by: Literal["POLICY_ENGINE"] = "POLICY_ENGINE"

    @model_validator(mode="after")
    def validate_policy(self) -> "PolicyDecision":
        require_prefix(self.policy_decision_id, "pol")
        require_prefix(self.action_request_id, "arq")
        if (
            self.decision is PolicyOutcome.DENY
            and self.approval_requirement is not ApprovalRequirement.NOT_ALLOWED
        ):
            raise ValueError("DENY policy must use NOT_ALLOWED")
        if (
            self.decision is PolicyOutcome.ALLOW_WITH_APPROVAL
            and self.approval_requirement is not ApprovalRequirement.HUMAN_REQUIRED
        ):
            raise ValueError("allowed high-risk action must require a human")
        if (
            self.decision is PolicyOutcome.ALLOW_WITH_PREAUTHORIZATION
            and self.approval_requirement
            is not ApprovalRequirement.POLICY_PREAUTHORIZATION_REQUIRED
        ):
            raise ValueError("autonomous action must require policy preauthorization")
        return self


class ApprovalRecord(StrictSchema):
    approval_id: str
    action_request_id: str
    decision: ApprovalDecision
    approver_id: NonEmptyStr
    approver_role: Literal["APPROVER"] = "APPROVER"
    comment: NonEmptyStr
    request_digest: Sha256
    decided_at: UtcDateTime

    @model_validator(mode="after")
    def validate_refs(self) -> "ApprovalRecord":
        require_prefix(self.approval_id, "apr")
        require_prefix(self.action_request_id, "arq")
        return self


class PolicyPreAuthorization(TimestampedSchema):
    preauthorization_id: str
    incident_id: str
    action_request_id: str
    run_mode: Literal[RunMode.COMPETITION_AUTONOMOUS]
    scenario_id: NonEmptyStr
    environment: Literal[ResourceEnvironment.SANDBOX]
    policy_version: NonEmptyStr
    allowed_operations: list[OperationType] = Field(min_length=1)
    request_digest: Sha256
    guard_checks: list[PolicyCheck] = Field(min_length=1)
    decision: PreAuthorizationDecision
    created_by: Literal["SYSTEM_POLICY"] = "SYSTEM_POLICY"

    @model_validator(mode="after")
    def validate_preauthorization(self) -> "PolicyPreAuthorization":
        require_prefix(self.preauthorization_id, "paz")
        require_prefix(self.incident_id, "inc")
        require_prefix(self.action_request_id, "arq")
        expected = [
            OperationType.FREEZE_OLD_KEY,
            OperationType.CREATE_NEW_KEY_VERSION,
            OperationType.UPDATE_CI_BINDING,
        ]
        if self.allowed_operations != expected:
            raise ValueError("preauthorization operations must use the frozen safe order")
        if self.decision is PreAuthorizationDecision.AUTO_PREAUTHORIZED and not all(
            item.passed for item in self.guard_checks
        ):
            raise ValueError("AUTO_PREAUTHORIZED requires every guard check to pass")
        return self


class OperationResult(StrictSchema):
    operation_id: NonEmptyStr
    status: ExecutionStatus
    state_snapshot_before: str
    state_snapshot_after: str | None = None
    receipt_ref: NonEmptyStr
    error_code: str | None = None

    @model_validator(mode="after")
    def validate_snapshots(self) -> "OperationResult":
        require_prefix(self.state_snapshot_before, "snp")
        if self.state_snapshot_after:
            require_prefix(self.state_snapshot_after, "snp")
        return self


class ExecutionResult(StrictSchema):
    execution_id: str
    action_request_id: str
    operation_results: list[OperationResult] = Field(min_length=1)
    overall_status: ExecutionStatus
    executor: Literal["SYSTEM_EXECUTOR"] = "SYSTEM_EXECUTOR"
    idempotency_key: NonEmptyStr
    started_at: UtcDateTime
    completed_at: UtcDateTime

    @model_validator(mode="after")
    def validate_execution(self) -> "ExecutionResult":
        require_prefix(self.execution_id, "exe")
        require_prefix(self.action_request_id, "arq")
        if self.completed_at < self.started_at:
            raise ValueError("completed_at must not precede started_at")
        return self


class VerificationObservation(StrictSchema):
    actual: JsonValue
    expected: JsonValue | None = None
    detail: str | None = None


class VerificationAssertion(StrictSchema):
    assertion_type: VerificationAssertionType
    passed: bool
    observed_value: VerificationObservation
    evidence_refs: list[str] = Field(min_length=1)
    checked_at: UtcDateTime

    @model_validator(mode="after")
    def validate_refs(self) -> "VerificationAssertion":
        for evidence_id in self.evidence_refs:
            require_prefix(evidence_id, "evd")
        return self


class VerificationStatus(StrEnum):
    PASSED = "PASSED"
    FAILED = "FAILED"
    INCONCLUSIVE = "INCONCLUSIVE"


class VerificationNextStep(StrEnum):
    CLOSE = "CLOSE"
    REPLAN = "REPLAN"
    MANUAL_REVIEW = "MANUAL_REVIEW"


class VerificationResult(TimestampedSchema):
    verification_id: str
    incident_id: str
    execution_id: str
    assertions: list[VerificationAssertion] = Field(min_length=1)
    overall_status: VerificationStatus
    failed_assertions: list[VerificationAssertionType] = Field(default_factory=list)
    next_step: VerificationNextStep

    @model_validator(mode="after")
    def validate_verification(self) -> "VerificationResult":
        require_prefix(self.verification_id, "ver")
        require_prefix(self.incident_id, "inc")
        require_prefix(self.execution_id, "exe")
        failed = [item.assertion_type for item in self.assertions if not item.passed]
        if set(failed) != set(self.failed_assertions):
            raise ValueError("failed_assertions must match assertion results")
        if self.overall_status is VerificationStatus.PASSED and failed:
            raise ValueError("PASSED verification cannot contain failed assertions")
        if (
            self.next_step is VerificationNextStep.CLOSE
            and self.overall_status is not VerificationStatus.PASSED
        ):
            raise ValueError("only PASSED verification may recommend CLOSE")
        return self
