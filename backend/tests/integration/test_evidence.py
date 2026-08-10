from datetime import UTC, datetime
from pathlib import Path

import pytest
from app.audit.service import AuditService
from app.core.ids import runtime_id, source_derived_id
from app.db.base import Base
from app.db.models import AuditRecordORM, EvidenceMutationError, EvidenceORM
from app.db.session import create_business_engine, make_session_factory
from app.domain.enums import (
    AutomationState,
    EvidenceSensitivity,
    IncidentStatus,
    Severity,
    SourceType,
)
from app.evidence.service import (
    AgentType,
    EvidenceAccessContext,
    EvidenceAccessDenied,
    EvidenceService,
)
from app.repositories.evidence import EvidenceRepository
from app.repositories.incidents import IncidentRepository
from app.schemas.evidence import (
    EvidenceReference,
    EvidenceType,
    MockEvidenceLocator,
    OfficialEvidenceLocator,
    SyntheticEvidenceLocator,
    SystemEvidenceLocator,
)
from app.schemas.incident import IncidentType, SecurityIncident
from sqlalchemy import select

NOW = datetime(2026, 8, 10, tzinfo=UTC)


def make_factory(tmp_path: Path):  # type: ignore[no-untyped-def]
    engine = create_business_engine(f"sqlite:///{tmp_path / 'evidence.db'}")
    Base.metadata.create_all(engine)
    return engine, make_session_factory(engine)


def make_incident() -> SecurityIncident:
    return SecurityIncident(
        incident_id=runtime_id("inc"),
        title="Evidence fixture incident",
        incident_type=IncidentType.API_CREDENTIAL_COMPROMISE,
        tenant_ref="tenant_fixture",
        status=IncidentStatus.INVESTIGATING,
        automation_state=AutomationState.ACTIVE,
        severity=Severity.HIGH,
        summary="Evidence ACL fixture",
        opened_at=NOW,
        updated_at=NOW,
        created_at=NOW,
    )


def evidence_fixture(
    source_type: SourceType,
    *,
    incident_id: str | None = None,
    sensitivity: EvidenceSensitivity = EvidenceSensitivity.INTERNAL,
    suffix: str = "base",
) -> EvidenceReference:
    if source_type is SourceType.OFFICIAL:
        locator = OfficialEvidenceLocator(
            capture_id=source_derived_id("cap", {"capture": suffix}, "test-v1"),
            packet_indexes=[1, 2],
            flow_id=source_derived_id("flw", {"flow": suffix}, "test-v1"),
        )
        evidence_type = EvidenceType.PCAP_PACKET
    elif source_type is SourceType.SYNTHETIC:
        locator = SyntheticEvidenceLocator(
            synthetic_event_id=f"syn_event_{suffix}",
            scenario_id="scenario_fixture",
            field_path="payload.result",
        )
        evidence_type = EvidenceType.SYNTHETIC_EVENT
    elif source_type is SourceType.MOCK:
        locator = MockEvidenceLocator(
            state_snapshot_id=runtime_id("snp"),
            operation_id=f"operation_{suffix}",
            field_path="credential.status",
        )
        evidence_type = EvidenceType.MOCK_STATE
    else:
        locator = SystemEvidenceLocator(
            audit_id=runtime_id("aud"), record_type="AuditRecord", field_path="event_type"
        )
        evidence_type = EvidenceType.AUDIT_RECORD

    return EvidenceReference(
        evidence_id=source_derived_id(
            "evd", {"source_type": source_type.value, "suffix": suffix}, "test-v1"
        ),
        incident_id=incident_id,
        source_type=source_type,
        source_dataset=f"{source_type.value.lower()}_fixture",
        source_record_id=f"record_{source_type.value.lower()}_{suffix}",
        evidence_type=evidence_type,
        locator=locator,
        content_sha256=(source_type.value + suffix).encode().hex().ljust(64, "0")[:64],
        summary=f"{source_type.value} evidence fixture",
        sensitivity=sensitivity,
        allowed_agent_types=[AgentType.INVESTIGATION_AGENT.value],
        created_by="EVIDENCE_SERVICE",
        created_at=NOW,
    )


def investigation_context(incident_id: str | None = None) -> EvidenceAccessContext:
    return EvidenceAccessContext(
        actor_id="investigator_fixture",
        agent_type=AgentType.INVESTIGATION_AGENT,
        incident_id=incident_id,
    )


@pytest.mark.parametrize("source_type", list(SourceType))
def test_four_source_locators_can_be_created_and_read(
    tmp_path: Path, source_type: SourceType
) -> None:
    _, factory = make_factory(tmp_path)
    evidence = evidence_fixture(source_type)
    with factory.begin() as session:
        service = EvidenceService(session)
        service.create(evidence)
        assert service.get_for_agent(evidence.evidence_id, investigation_context()) == evidence
        assert AuditService(session).verify_chain(None)


def test_acl_allows_authorized_agent_and_denies_unauthorized_agent(tmp_path: Path) -> None:
    _, factory = make_factory(tmp_path)
    incident = make_incident()
    evidence = evidence_fixture(SourceType.SYNTHETIC, incident_id=incident.incident_id)
    with factory.begin() as session:
        IncidentRepository(session).add(incident)
        service = EvidenceService(session)
        service.create(evidence)
        assert (
            service.get_for_agent(evidence.evidence_id, investigation_context(incident.incident_id))
            == evidence
        )
        denied_context = EvidenceAccessContext(
            actor_id="operator_fixture",
            agent_type=AgentType.OPERATION_AGENT,
            incident_id=incident.incident_id,
        )
        with pytest.raises(EvidenceAccessDenied, match="AGENT_TYPE_DENIED"):
            service.get_for_agent(evidence.evidence_id, denied_context)

    with factory() as session:
        denial = session.scalar(
            select(AuditRecordORM).where(AuditRecordORM.event_type == "EVIDENCE_ACCESS_DENIED")
        )
        assert denial is not None
        assert denial.payload_redacted["reason"] == "AGENT_TYPE_DENIED"
        assert AuditService(session).verify_chain(incident.incident_id)


def test_incident_scope_mismatch_is_denied_and_audited(tmp_path: Path) -> None:
    _, factory = make_factory(tmp_path)
    incident = make_incident()
    evidence = evidence_fixture(SourceType.MOCK, incident_id=incident.incident_id)
    with factory.begin() as session:
        IncidentRepository(session).add(incident)
        service = EvidenceService(session)
        service.create(evidence)
        with pytest.raises(EvidenceAccessDenied, match="INCIDENT_SCOPE_DENIED"):
            service.get_for_agent(evidence.evidence_id, investigation_context(runtime_id("inc")))
    with factory() as session:
        assert AuditService(session).verify_chain(incident.incident_id)


def test_secret_evidence_is_denied_even_when_agent_is_allowlisted(tmp_path: Path) -> None:
    _, factory = make_factory(tmp_path)
    evidence = evidence_fixture(
        SourceType.SYSTEM, sensitivity=EvidenceSensitivity.SECRET, suffix="secret"
    )
    with factory.begin() as session:
        service = EvidenceService(session)
        service.create(evidence)
        with pytest.raises(EvidenceAccessDenied, match="SECRET_EVIDENCE_DENIED"):
            service.get_for_agent(evidence.evidence_id, investigation_context())
    with factory() as session:
        assert AuditService(session).verify_chain(None)


def test_correction_appends_new_evidence_without_overwriting_original(tmp_path: Path) -> None:
    _, factory = make_factory(tmp_path)
    original = evidence_fixture(SourceType.OFFICIAL, suffix="original")
    correction = original.model_copy(
        update={
            "evidence_id": source_derived_id("evd", {"correction": 1}, "test-v1"),
            "content_sha256": "b" * 64,
            "summary": "Corrected packet range",
            "locator": OfficialEvidenceLocator(
                capture_id=original.locator.capture_id,  # type: ignore[union-attr]
                packet_indexes=[2],
            ),
            "supersedes_evidence_id": original.evidence_id,
            "correction_reason": "Initial parser selected packet 1 instead of packet 2",
        }
    )
    correction = EvidenceReference.model_validate(correction.model_dump(mode="python"))

    with factory.begin() as session:
        service = EvidenceService(session)
        service.create(original)
        service.append_correction(
            original_id=original.evidence_id,
            correction=correction,
            context=investigation_context(),
        )

    with factory() as session:
        repository = EvidenceRepository(session)
        assert repository.get(original.evidence_id) == original
        assert repository.get(correction.evidence_id) == correction
        assert repository.list_corrections(original.evidence_id) == [correction]
        assert AuditService(session).verify_chain(None)


def test_evidence_orm_update_and_delete_are_rejected(tmp_path: Path) -> None:
    _, factory = make_factory(tmp_path)
    evidence = evidence_fixture(SourceType.SYNTHETIC)
    with factory.begin() as session:
        EvidenceService(session).create(evidence)

    with factory() as session:
        row = session.get(EvidenceORM, evidence.evidence_id)
        assert row is not None
        row.payload = {**row.payload, "summary": "attempted overwrite"}
        with pytest.raises(EvidenceMutationError, match="immutable"):
            session.flush()
        session.rollback()

    with factory() as session:
        row = session.get(EvidenceORM, evidence.evidence_id)
        assert row is not None
        session.delete(row)
        with pytest.raises(EvidenceMutationError, match="immutable"):
            session.flush()
