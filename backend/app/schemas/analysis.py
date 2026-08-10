from enum import StrEnum

from pydantic import Field, model_validator

from app.domain.enums import ConfidenceLevel, FactSupportType, Severity, SourceType
from app.schemas.base import NonEmptyStr, StrictSchema, TimestampedSchema, require_prefix


class SignalType(StrEnum):
    NTA_SQLI = "NTA_SQLI"
    NTA_CMDI = "NTA_CMDI"
    NTA_WEBSHELL = "NTA_WEBSHELL"
    NTA_DNSLOG = "NTA_DNSLOG"
    CI_ACTION_MUTATION = "CI_ACTION_MUTATION"
    SECRET_READ = "SECRET_READ"
    CREDENTIAL_EXPOSURE = "CREDENTIAL_EXPOSURE"
    ABNORMAL_CLOUD_API = "ABNORMAL_CLOUD_API"
    SENSITIVE_DATA_ACCESS = "SENSITIVE_DATA_ACCESS"
    HIGH_COST_CREATION = "HIGH_COST_CREATION"


class DetectorType(StrEnum):
    RULE = "RULE"
    MODEL = "MODEL"


class SignalStatus(StrEnum):
    OPEN = "OPEN"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    DISMISSED = "DISMISSED"
    PROMOTED = "PROMOTED"


class DetectorRef(StrictSchema):
    detector_type: DetectorType
    detector_id: NonEmptyStr
    detector_version: NonEmptyStr


class SecuritySignal(TimestampedSchema):
    signal_id: str
    incident_id: str | None = None
    signal_type: SignalType
    severity: Severity
    subject_refs: list[str] = Field(min_length=1)
    trigger_reason: NonEmptyStr
    detector: DetectorRef
    evidence_refs: list[str] = Field(min_length=1)
    source_types: list[SourceType] = Field(min_length=1)
    status: SignalStatus

    @model_validator(mode="after")
    def validate_refs(self) -> "SecuritySignal":
        require_prefix(self.signal_id, "sig")
        if self.incident_id is not None:
            require_prefix(self.incident_id, "inc")
        for evidence_id in self.evidence_refs:
            require_prefix(evidence_id, "evd")
        return self


class ConfirmedFact(TimestampedSchema):
    fact_id: str
    incident_id: str
    fact_type: NonEmptyStr
    subject_refs: list[str] = Field(min_length=1)
    statement: NonEmptyStr
    evidence_refs: list[str] = Field(min_length=1)
    support_type: FactSupportType
    confidence_level: ConfidenceLevel
    confidence_basis: NonEmptyStr
    proposed_by: NonEmptyStr
    validated_by: str = "EVENT_STATE_MANAGER"

    @model_validator(mode="after")
    def validate_refs(self) -> "ConfirmedFact":
        require_prefix(self.fact_id, "fac")
        require_prefix(self.incident_id, "inc")
        if self.validated_by != "EVENT_STATE_MANAGER":
            raise ValueError("ConfirmedFact must be validated by EVENT_STATE_MANAGER")
        for evidence_id in self.evidence_refs:
            require_prefix(evidence_id, "evd")
        return self


class RiskAssessment(TimestampedSchema):
    assessment_id: str
    incident_id: str
    severity: Severity
    affected_subjects: list[str] = Field(min_length=1)
    impact_summary: NonEmptyStr
    fact_refs: list[str] = Field(min_length=1)
    unresolved_risks: list[str] = Field(default_factory=list)
    assessed_by: NonEmptyStr

    @model_validator(mode="after")
    def validate_refs(self) -> "RiskAssessment":
        require_prefix(self.assessment_id, "rsk")
        require_prefix(self.incident_id, "inc")
        for fact_id in self.fact_refs:
            require_prefix(fact_id, "fac")
        return self
