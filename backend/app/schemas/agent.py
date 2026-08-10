from enum import StrEnum

from pydantic import Field, model_validator

from app.domain.enums import ConfidenceLevel, TaskStatus
from app.schemas.base import (
    NonEmptyStr,
    StrictSchema,
    TimestampedSchema,
    UtcDateTime,
    require_prefix,
)


class TaskType(StrEnum):
    MONITOR = "MONITOR"
    INVESTIGATE = "INVESTIGATE"
    TRACE = "TRACE"
    OPERATE = "OPERATE"
    AUDIT = "AUDIT"


class TaskCreator(StrEnum):
    MAIN_AGENT = "MAIN_AGENT"
    SYSTEM = "SYSTEM"


class AllowedContext(StrictSchema):
    fact_refs: list[str] = Field(default_factory=list)
    signal_refs: list[str] = Field(default_factory=list)
    field_allowlist: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_refs(self) -> "AllowedContext":
        for fact_id in self.fact_refs:
            require_prefix(fact_id, "fac")
        for signal_id in self.signal_refs:
            require_prefix(signal_id, "sig")
        return self


class AgentTask(TimestampedSchema):
    task_id: str
    incident_id: str
    task_type: TaskType
    task_goal: NonEmptyStr
    allowed_context: AllowedContext
    evidence_refs: list[str] = Field(default_factory=list)
    allowed_tools: list[str] = Field(default_factory=list)
    expected_output: NonEmptyStr
    assigned_agent_type: NonEmptyStr
    status: TaskStatus
    attempt: int = Field(default=1, ge=1)
    created_by: TaskCreator
    started_at: UtcDateTime | None = None
    completed_at: UtcDateTime | None = None

    @model_validator(mode="after")
    def validate_task(self) -> "AgentTask":
        require_prefix(self.task_id, "tsk")
        require_prefix(self.incident_id, "inc")
        for evidence_id in self.evidence_refs:
            require_prefix(evidence_id, "evd")
        if self.completed_at and self.started_at and self.completed_at < self.started_at:
            raise ValueError("completed_at must not precede started_at")
        return self


class AgentError(StrictSchema):
    code: NonEmptyStr
    message: NonEmptyStr
    retryable: bool = False


class AgentFinding(TimestampedSchema):
    finding_id: str
    incident_id: str
    task_id: str
    finding_type: NonEmptyStr
    statement: NonEmptyStr
    evidence_refs: list[str] = Field(min_length=1)
    confidence_level: ConfidenceLevel
    limitations: list[str] = Field(default_factory=list)
    # Reference material retrieved by Security Knowledge RAG. These entries
    # never become evidence-backed facts; they are citations only.
    knowledge_refs: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_refs(self) -> "AgentFinding":
        require_prefix(self.finding_id, "fnd")
        require_prefix(self.incident_id, "inc")
        require_prefix(self.task_id, "tsk")
        for evidence_id in self.evidence_refs:
            require_prefix(evidence_id, "evd")
        return self


class AgentResult(TimestampedSchema):
    result_id: str
    task_id: str
    incident_id: str
    task_status: TaskStatus
    findings: list[str] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)
    confidence_level: ConfidenceLevel
    confidence_basis: NonEmptyStr
    unresolved_questions: list[str] = Field(default_factory=list)
    next_step: str | None = None
    approval_required: bool
    model_trace_ref: str | None = None
    errors: list[AgentError] = Field(default_factory=list)
    # Security Knowledge RAG citations surfaced during this result.
    knowledge_refs: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_refs(self) -> "AgentResult":
        require_prefix(self.result_id, "res")
        require_prefix(self.task_id, "tsk")
        require_prefix(self.incident_id, "inc")
        for finding_id in self.findings:
            require_prefix(finding_id, "fnd")
        for evidence_id in self.evidence_refs:
            require_prefix(evidence_id, "evd")
        return self
