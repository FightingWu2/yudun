from enum import StrEnum

from pydantic import Field, model_validator

from app.domain.enums import AutomationState, IncidentStatus, Severity
from app.schemas.base import NonEmptyStr, TimestampedSchema, UtcDateTime, require_prefix


class IncidentType(StrEnum):
    API_CREDENTIAL_COMPROMISE = "API_CREDENTIAL_COMPROMISE"


class SecurityIncident(TimestampedSchema):
    incident_id: str
    title: NonEmptyStr
    incident_type: IncidentType
    tenant_ref: NonEmptyStr
    status: IncidentStatus
    automation_state: AutomationState
    severity: Severity
    signal_refs: list[str] = Field(default_factory=list)
    fact_refs: list[str] = Field(default_factory=list)
    latest_assessment_ref: str | None = None
    task_refs: list[str] = Field(default_factory=list)
    pending_action_refs: list[str] = Field(default_factory=list)
    parent_incident_id: str | None = None
    summary: NonEmptyStr
    opened_at: UtcDateTime
    updated_at: UtcDateTime
    closed_at: UtcDateTime | None = None
    version: int = Field(default=1, ge=1)

    @model_validator(mode="after")
    def validate_incident(self) -> "SecurityIncident":
        require_prefix(self.incident_id, "inc")
        if self.parent_incident_id:
            require_prefix(self.parent_incident_id, "inc")
        for signal_id in self.signal_refs:
            require_prefix(signal_id, "sig")
        for fact_id in self.fact_refs:
            require_prefix(fact_id, "fac")
        for task_id in self.task_refs:
            require_prefix(task_id, "tsk")
        for action_id in self.pending_action_refs:
            require_prefix(action_id, "arq")
        if self.updated_at < self.opened_at:
            raise ValueError("updated_at must not precede opened_at")
        if self.closed_at and self.closed_at < self.opened_at:
            raise ValueError("closed_at must not precede opened_at")
        if self.status is IncidentStatus.CLOSED and self.closed_at is None:
            raise ValueError("CLOSED incident requires closed_at")
        if self.status is not IncidentStatus.CLOSED and self.closed_at is not None:
            raise ValueError("only CLOSED incident may set closed_at")
        return self


class AssociationType(StrEnum):
    SAME_CREDENTIAL = "SAME_CREDENTIAL"
    SAME_RUNNER = "SAME_RUNNER"
    SAME_SOURCE = "SAME_SOURCE"
    SAME_RESOURCE = "SAME_RESOURCE"
    TEMPORAL_SEQUENCE = "TEMPORAL_SEQUENCE"
    DEMO_SCENARIO = "DEMO_SCENARIO"


class AssociationBasis(StrEnum):
    EXACT_FIELD = "EXACT_FIELD"
    RULE = "RULE"
    HUMAN_CONFIRMED = "HUMAN_CONFIRMED"
    DEMO_SCENARIO = "DEMO_SCENARIO"


class AssociationRecord(TimestampedSchema):
    association_id: str
    incident_id: str
    left_object_ref: NonEmptyStr
    right_object_ref: NonEmptyStr
    association_type: AssociationType
    association_basis: AssociationBasis
    evidence_refs: list[str] = Field(default_factory=list)
    created_by: NonEmptyStr

    @model_validator(mode="after")
    def validate_association(self) -> "AssociationRecord":
        require_prefix(self.association_id, "asc")
        require_prefix(self.incident_id, "inc")
        for evidence_id in self.evidence_refs:
            require_prefix(evidence_id, "evd")
        if (
            self.association_type is AssociationType.DEMO_SCENARIO
            and self.association_basis is not AssociationBasis.DEMO_SCENARIO
        ):
            raise ValueError("DEMO_SCENARIO association must disclose DEMO_SCENARIO basis")
        return self
