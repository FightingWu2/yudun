from enum import StrEnum

from pydantic import Field, model_validator

from app.domain.enums import ConfidenceLevel, SourceType
from app.schemas.agent import TaskType
from app.schemas.base import NonEmptyStr, StrictSchema, UtcDateTime, require_prefix
from app.schemas.incident import AssociationBasis


class InvestigationModelOutput(StrictSchema):
    statement: NonEmptyStr
    evidence_refs: list[str] = Field(min_length=1)
    confidence_level: ConfidenceLevel
    limitations: list[str] = Field(default_factory=list)
    unresolved_questions: list[str] = Field(default_factory=list)
    proposed_fact_types: list[str] = Field(default_factory=list)


class TimelineNode(StrictSchema):
    timestamp: UtcDateTime
    event_type: NonEmptyStr
    source_type: SourceType
    object_ref: NonEmptyStr
    evidence_refs: list[str] = Field(min_length=1)
    association_basis: AssociationBasis
    summary: NonEmptyStr

    @model_validator(mode="after")
    def validate_evidence(self) -> "TimelineNode":
        for evidence_id in self.evidence_refs:
            require_prefix(evidence_id, "evd")
        return self


class Timeline(StrictSchema):
    incident_id: str
    nodes: list[TimelineNode] = Field(min_length=1)
    missing_links: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_incident(self) -> "Timeline":
        require_prefix(self.incident_id, "inc")
        if self.nodes != sorted(self.nodes, key=lambda item: item.timestamp):
            raise ValueError("timeline nodes must use deterministic timestamp order")
        return self


class MainNextAction(StrEnum):
    INVESTIGATE = "INVESTIGATE"
    TRACE = "TRACE"
    RECOMMEND_ACTION = "RECOMMEND_ACTION"
    REPLAN = "REPLAN"
    STOP = "STOP"
    MANUAL = "MANUAL"


class MainPlan(StrictSchema):
    next_action: MainNextAction
    reason_summary: NonEmptyStr
    task_type: TaskType | None = None
    task_goal: str | None = None
    evidence_refs: list[str] = Field(default_factory=list)
    fact_refs: list[str] = Field(default_factory=list)
    requested_tools: list[str] = Field(default_factory=list)
    unresolved_questions: list[str] = Field(default_factory=list)
    stop_reason: str | None = None


class AuditReport(StrictSchema):
    incident_id: str
    fact_refs: list[str]
    evidence_refs: list[str]
    action_refs: list[str]
    verification_refs: list[str]
    audit_chain_valid: bool
    summary: NonEmptyStr


class ReasoningStage(StrEnum):
    OBSERVATION = "OBSERVATION"
    EVIDENCE = "EVIDENCE"
    TASK = "TASK"
    FINDING = "FINDING"
    FACT = "FACT"
    DECISION = "DECISION"
    ACTION = "ACTION"
    REPLAN = "REPLAN"


class ReasoningTraceNode(StrictSchema):
    timestamp: UtcDateTime
    stage: ReasoningStage
    actor: NonEmptyStr
    object_type: NonEmptyStr
    object_id: NonEmptyStr
    summary: NonEmptyStr
    input_refs: list[str] = Field(default_factory=list)
    output_refs: list[str] = Field(default_factory=list)
    source_type: SourceType
    result: NonEmptyStr
