from enum import StrEnum

from pydantic import Field

from app.audit.service import AuditService
from app.core.errors import DomainError, ErrorCode
from app.core.ids import runtime_id
from app.domain.enums import ConfidenceLevel, FactSupportType, SourceType
from app.repositories.evidence import EvidenceRepository
from app.repositories.facts import FactRepository
from app.schemas.analysis import ConfirmedFact
from app.schemas.audit import AuditActorType
from app.schemas.base import NonEmptyStr, StrictSchema
from app.schemas.evidence import EvidenceReference


class GoldenPathFactType(StrEnum):
    CI_ACTION_MUTATED = "CI_ACTION_MUTATED"
    SECRET_ACCESSED = "SECRET_ACCESSED"
    CREDENTIAL_EXPOSED = "CREDENTIAL_EXPOSED"
    CREDENTIAL_ABUSED = "CREDENTIAL_ABUSED"
    SENSITIVE_DATA_ACCESSED = "SENSITIVE_DATA_ACCESSED"
    HIGH_COST_RESOURCE_CREATED = "HIGH_COST_RESOURCE_CREATED"


class FactPromotionCandidate(StrictSchema):
    incident_id: str
    fact_type: GoldenPathFactType
    subject_refs: list[NonEmptyStr] = Field(min_length=1)
    statement: NonEmptyStr
    evidence_refs: list[str] = Field(min_length=1)
    proposed_by: NonEmptyStr


_PREREQUISITES = {
    GoldenPathFactType.SECRET_ACCESSED: {GoldenPathFactType.CI_ACTION_MUTATED},
    GoldenPathFactType.CREDENTIAL_EXPOSED: {GoldenPathFactType.SECRET_ACCESSED},
    GoldenPathFactType.CREDENTIAL_ABUSED: {GoldenPathFactType.CREDENTIAL_EXPOSED},
    GoldenPathFactType.SENSITIVE_DATA_ACCESSED: {GoldenPathFactType.CREDENTIAL_ABUSED},
    GoldenPathFactType.HIGH_COST_RESOURCE_CREATED: {GoldenPathFactType.CREDENTIAL_ABUSED},
}


class FactValidator:
    def __init__(
        self,
        evidence: EvidenceRepository,
        facts: FactRepository,
        audit: AuditService | None = None,
    ) -> None:
        self._evidence = evidence
        self._facts = facts
        self._audit = audit

    def promote(self, candidate: FactPromotionCandidate) -> ConfirmedFact:
        evidence = [self._required_evidence(item) for item in candidate.evidence_refs]
        if any(item.incident_id not in {None, candidate.incident_id} for item in evidence):
            raise DomainError(ErrorCode.EVIDENCE_REQUIRED, "evidence belongs to another incident")
        existing = self._facts.list_for_incident(candidate.incident_id)
        existing_types = {GoldenPathFactType(item.fact_type) for item in existing}
        missing = _PREREQUISITES.get(candidate.fact_type, set()) - existing_types
        if missing:
            raise DomainError(
                ErrorCode.EVIDENCE_REQUIRED,
                f"missing prerequisite facts: {sorted(item.value for item in missing)}",
            )
        self._validate_semantics(candidate.fact_type, evidence)
        fact = ConfirmedFact(
            fact_id=runtime_id("fac"),
            incident_id=candidate.incident_id,
            fact_type=candidate.fact_type.value,
            subject_refs=candidate.subject_refs,
            statement=candidate.statement,
            evidence_refs=candidate.evidence_refs,
            support_type=FactSupportType.DIRECT,
            confidence_level=ConfidenceLevel.HIGH,
            confidence_basis="Deterministic validation of typed evidence and prerequisites.",
            proposed_by=candidate.proposed_by,
        )
        created = self._facts.add(fact)
        if self._audit is not None:
            self._audit.append(
                incident_id=fact.incident_id,
                actor_type=AuditActorType.SYSTEM,
                actor_id="EVENT_STATE_MANAGER",
                event_type="FACT_PROMOTED",
                object_type="ConfirmedFact",
                object_id=fact.fact_id,
                summary=f"Promoted evidence-backed fact {fact.fact_type}",
                payload={
                    "evidence_refs": fact.evidence_refs,
                    "proposed_by": fact.proposed_by,
                },
            )
        return created

    def _required_evidence(self, evidence_id: str) -> EvidenceReference:
        item = self._evidence.get(evidence_id)
        if item is None:
            raise DomainError(ErrorCode.EVIDENCE_REQUIRED, f"missing evidence {evidence_id}")
        if item.source_type not in {SourceType.SYNTHETIC, SourceType.SYSTEM, SourceType.MOCK}:
            raise DomainError(
                ErrorCode.EVIDENCE_REQUIRED,
                "official NTA evidence cannot prove the synthetic credential chain",
            )
        return item

    @staticmethod
    def _validate_semantics(
        fact_type: GoldenPathFactType, evidence: list[EvidenceReference]
    ) -> None:
        snapshots = [item.redacted_snapshot or {} for item in evidence]
        event_types = {str(item.get("event_type")) for item in snapshots}
        expected = {
            GoldenPathFactType.CI_ACTION_MUTATED: "CI_SECURITY",
            GoldenPathFactType.SECRET_ACCESSED: "SECRET_ACCESS",
            GoldenPathFactType.CREDENTIAL_EXPOSED: "CREDENTIAL_EXPOSURE",
            GoldenPathFactType.CREDENTIAL_ABUSED: "CLOUD_API_AUDIT",
            GoldenPathFactType.SENSITIVE_DATA_ACCESSED: "RESOURCE_ACCESS",
            GoldenPathFactType.HIGH_COST_RESOURCE_CREATED: "RESOURCE_OPERATION",
        }[fact_type]
        if expected not in event_types:
            raise DomainError(ErrorCode.EVIDENCE_REQUIRED, f"{expected} evidence is required")
        relevant = next(item for item in snapshots if item.get("event_type") == expected)
        checks = {
            GoldenPathFactType.CI_ACTION_MUTATED: (
                relevant.get("expected_digest") != relevant.get("observed_digest")
            ),
            GoldenPathFactType.SECRET_ACCESSED: relevant.get("result") == "SUCCEEDED",
            GoldenPathFactType.CREDENTIAL_EXPOSED: relevant.get("result") == "EXPOSED",
            GoldenPathFactType.CREDENTIAL_ABUSED: (
                relevant.get("result") == "SUCCEEDED"
                and relevant.get("source_ref") != relevant.get("expected_source")
            ),
            GoldenPathFactType.SENSITIVE_DATA_ACCESSED: (
                relevant.get("result") == "SUCCEEDED" and relevant.get("sensitivity") == "SENSITIVE"
            ),
            GoldenPathFactType.HIGH_COST_RESOURCE_CREATED: (
                relevant.get("result") == "SUCCEEDED" and relevant.get("cost_class") == "HIGH"
            ),
        }
        if not checks[fact_type]:
            raise DomainError(ErrorCode.EVIDENCE_REQUIRED, "evidence does not satisfy fact rule")
