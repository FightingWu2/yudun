import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from app.audit.service import AuditService
from app.core.errors import (
    ConflictError,
    DomainError,
    InvalidStateTransitionError,
    PermissionDeniedError,
)
from app.core.ids import runtime_id
from app.db.base import Base
from app.db.session import create_business_engine, make_session_factory
from app.detection.rules import DETECTION_RULES, run_detection_rules
from app.domain.enums import (
    AutomationState,
    ConfidenceLevel,
    IncidentStatus,
    Severity,
    TaskStatus,
)
from app.pcap.manifest import scan_capture
from app.pcap.parser import NormalizedCapture, normalize_capture
from app.repositories.agents import AgentContractRepository
from app.repositories.evidence import EvidenceRepository
from app.repositories.facts import FactRepository
from app.repositories.incidents import IncidentRepository
from app.schemas.agent import (
    AgentFinding,
    AgentResult,
    AgentTask,
    AllowedContext,
    TaskCreator,
    TaskType,
)
from app.schemas.data import EventParseStatus
from app.schemas.incident import IncidentType, SecurityIncident
from app.services.events import EventManager
from app.services.facts import FactPromotionCandidate, FactValidator, GoldenPathFactType
from app.services.state import EventStateManager, TransitionContext
from app.synthetic.detection import run_synthetic_rules
from app.synthetic.scenario import SCENARIO_ID, ScenarioReplayStore, replay_golden_path
from app.tools.registry import AgentType, build_default_registry

NOW = datetime(2026, 8, 10, tzinfo=UTC)


def _factory(tmp_path: Path):  # type: ignore[no-untyped-def]
    engine = create_business_engine(f"sqlite:///{tmp_path / 'p0.db'}")
    Base.metadata.create_all(engine)
    return make_session_factory(engine)


def _incident() -> SecurityIncident:
    return SecurityIncident(
        incident_id=runtime_id("inc"),
        title="Golden Path fixture",
        incident_type=IncidentType.API_CREDENTIAL_COMPROMISE,
        tenant_ref="tenant_demo_cloud_01",
        status=IncidentStatus.NEW,
        automation_state=AutomationState.ACTIVE,
        severity=Severity.HIGH,
        summary="Synthetic CI credential compromise fixture",
        opened_at=NOW,
        updated_at=NOW,
    )


def test_verified_sample_set_is_evidence_backed_and_not_ground_truth() -> None:
    payload = json.loads(Path("artifacts/verified_sample_set.json").read_text(encoding="utf-8"))
    assert len(payload["samples"]) >= 30
    assert set(payload["counts"]) == {
        "SQL_INJECTION",
        "COMMAND_INJECTION",
        "WEBSHELL_RCE",
        "DNSLOG",
    }
    assert "not training ground truth" in payload["purpose"]
    assert all(item["review_status"] == "SINGLE_REVIEWED" for item in payload["samples"])
    assert all(item["evidence_locator"]["packet_indexes"] for item in payload["samples"])


@pytest.mark.parametrize("rule", DETECTION_RULES, ids=lambda item: item.rule_id)
def test_detection_rule_matches_a_verified_official_sample(rule) -> None:  # type: ignore[no-untyped-def]
    payload = json.loads(Path("artifacts/verified_sample_set.json").read_text(encoding="utf-8"))
    expected = rule.signal_type.value.removeprefix("NTA_")
    label = {
        "SQLI": "SQL_INJECTION",
        "CMDI": "COMMAND_INJECTION",
        "WEBSHELL": "WEBSHELL_RCE",
    }.get(expected, expected)
    sample = next(item for item in payload["samples"] if item["human_label"] == label)
    root = Path("data/测评中心基线样本nta")
    path = root / sample["display_name"]
    matches = run_detection_rules(normalize_capture(scan_capture(root, path), path))
    selected = [item for item in matches if item.rule.rule_id == rule.rule_id]
    assert selected
    assert all(item.signal.evidence_refs == [item.evidence_id] for item in selected)


@pytest.mark.parametrize(
    "text",
    [
        "GET /docs select your preferred language",
        "GET /search?q=union",
        "malformed %%% payload without governed structure",
        "ordinary background HTTP request",
    ],
)
def test_detection_rules_do_not_promote_ambiguous_background_or_malformed_text(
    text: str,
) -> None:
    normalized = NormalizedCapture(
        capture_id="cap_000000000000000000000000",
        parse_status=EventParseStatus.PARTIAL,
        inspection_text={"raw_000000000000000000000000": text},
    )
    assert run_detection_rules(normalized) == []


def test_synthetic_replay_is_deterministic_resettable_and_secret_free() -> None:
    store = ScenarioReplayStore()
    first = store.replay()
    store.reset()
    assert store.current() is None
    second = store.replay()
    assert first.model_dump(mode="json") == second.model_dump(mode="json")
    assert first.scenario_id == SCENARIO_ID
    assert len(first.events) == len(first.evidence) == 6
    rendered = first.model_dump_json().lower()
    assert "api_key=" not in rendered
    assert all(item.source_type.value == "SYNTHETIC" for item in first.evidence)


def test_synthetic_ci_signal_creates_incident_idempotently(tmp_path: Path) -> None:
    factory = _factory(tmp_path)
    replay = replay_golden_path()
    signals = run_synthetic_rules(replay)
    assert {item.detector.detector_id for item in signals} == {
        "SYN-CI-001",
        "SYN-API-001",
        "SYN-IMPACT-001",
    }
    ci_signal = next(item for item in signals if item.signal_type.value == "CI_ACTION_MUTATION")
    with factory.begin() as session:
        manager = EventManager(session)
        first = manager.create_from_ci_signal(ci_signal, tenant_ref="tenant_demo_cloud_01")
        second = manager.create_from_ci_signal(ci_signal, tenant_ref="tenant_demo_cloud_01")
        assert first == second
        assert first.signal_refs == [ci_signal.signal_id]
        assert first.status is IncidentStatus.NEW


def test_incident_optimistic_lock_rejects_stale_writer(tmp_path: Path) -> None:
    factory = _factory(tmp_path)
    incident = _incident()
    with factory.begin() as session:
        IncidentRepository(session).add(incident)
    with factory() as first_session, factory() as second_session:
        first = IncidentRepository(first_session)
        second = IncidentRepository(second_session)
        first_copy = first.get(incident.incident_id)
        stale_copy = second.get(incident.incident_id)
        assert first_copy is not None and stale_copy is not None
        first.update(first_copy, expected_version=1)
        first_session.commit()
        with pytest.raises(ConflictError):
            second.update(stale_copy, expected_version=1)


def test_incident_repository_denies_direct_protected_status_write(tmp_path: Path) -> None:
    factory = _factory(tmp_path)
    incident = _incident()
    with factory.begin() as session:
        repository = IncidentRepository(session)
        repository.add(incident)
        unauthorized = incident.model_copy(update={"status": IncidentStatus.DETECTED})
        with pytest.raises(PermissionDeniedError):
            repository.update(unauthorized, expected_version=incident.version)


def test_fact_promotion_requires_typed_evidence_and_prerequisites(tmp_path: Path) -> None:
    factory = _factory(tmp_path)
    incident = _incident()
    replay = replay_golden_path()
    evidence_by_type = {
        item.redacted_snapshot["event_type"]: item.model_copy(
            update={"incident_id": incident.incident_id}
        )
        for item in replay.evidence
        if item.redacted_snapshot is not None
    }
    order = [
        (GoldenPathFactType.CI_ACTION_MUTATED, "CI_SECURITY"),
        (GoldenPathFactType.SECRET_ACCESSED, "SECRET_ACCESS"),
        (GoldenPathFactType.CREDENTIAL_EXPOSED, "CREDENTIAL_EXPOSURE"),
        (GoldenPathFactType.CREDENTIAL_ABUSED, "CLOUD_API_AUDIT"),
        (GoldenPathFactType.SENSITIVE_DATA_ACCESSED, "RESOURCE_ACCESS"),
        (GoldenPathFactType.HIGH_COST_RESOURCE_CREATED, "RESOURCE_OPERATION"),
    ]
    with factory.begin() as session:
        IncidentRepository(session).add(incident)
        evidence_repo = EvidenceRepository(session)
        for item in evidence_by_type.values():
            evidence_repo.add(item)
        validator = FactValidator(evidence_repo, FactRepository(session))
        with pytest.raises(DomainError):
            validator.promote(
                FactPromotionCandidate(
                    incident_id=incident.incident_id,
                    fact_type=GoldenPathFactType.CREDENTIAL_ABUSED,
                    subject_refs=["credential_ref_demo_ci"],
                    statement="Candidate must not bypass prerequisites.",
                    evidence_refs=[evidence_by_type["CLOUD_API_AUDIT"].evidence_id],
                    proposed_by="FIXTURE_FINDING",
                )
            )
        for fact_type, event_type in order:
            fact = validator.promote(
                FactPromotionCandidate(
                    incident_id=incident.incident_id,
                    fact_type=fact_type,
                    subject_refs=["credential_ref_demo_ci"],
                    statement=f"Evidence-backed {fact_type.value}",
                    evidence_refs=[evidence_by_type[event_type].evidence_id],
                    proposed_by="FIXTURE_FINDING",
                )
            )
            assert fact.fact_type == fact_type.value


@pytest.mark.parametrize(
    ("current", "target"),
    [
        (IncidentStatus.NEW, IncidentStatus.ROTATED),
        (IncidentStatus.DETECTED, IncidentStatus.CLOSED),
        (IncidentStatus.INVESTIGATING, IncidentStatus.VERIFIED),
        (IncidentStatus.ATTRIBUTED, IncidentStatus.CLOSED),
    ],
)
def test_illegal_state_transitions_are_denied_and_audited(
    tmp_path: Path, current: IncidentStatus, target: IncidentStatus
) -> None:
    factory = _factory(tmp_path)
    incident = _incident().model_copy(update={"status": current})
    with factory.begin() as session:
        IncidentRepository(session).add(incident)
        with pytest.raises(InvalidStateTransitionError):
            EventStateManager(session).transition(
                incident.incident_id,
                target,
                TransitionContext(),
                proposed_by="MAIN_AGENT",
            )
        assert AuditService(session).verify_chain(incident.incident_id)


def test_agent_contract_repository_rejects_unstructured_result(tmp_path: Path) -> None:
    factory = _factory(tmp_path)
    incident = _incident()
    task = AgentTask(
        task_id=runtime_id("tsk"),
        incident_id=incident.incident_id,
        task_type=TaskType.INVESTIGATE,
        task_goal="Validate credential usage",
        allowed_context=AllowedContext(),
        expected_output="Structured findings",
        assigned_agent_type="INVESTIGATION_AGENT",
        status=TaskStatus.PENDING,
        created_by=TaskCreator.MAIN_AGENT,
    )
    finding = AgentFinding(
        finding_id=runtime_id("fnd"),
        incident_id=incident.incident_id,
        task_id=task.task_id,
        finding_type="CREDENTIAL_USAGE",
        statement="Finding remains distinct from fact.",
        evidence_refs=[runtime_id("evd")],
        confidence_level=ConfidenceLevel.HIGH,
    )
    result = AgentResult(
        result_id=runtime_id("res"),
        task_id=task.task_id,
        incident_id=incident.incident_id,
        task_status=TaskStatus.COMPLETED,
        findings=[finding.finding_id],
        evidence_refs=finding.evidence_refs,
        confidence_level=ConfidenceLevel.HIGH,
        confidence_basis="Fixture evidence",
        approval_required=False,
    )
    with factory.begin() as session:
        IncidentRepository(session).add(incident)
        repository = AgentContractRepository(session)
        repository.add_task(task)
        repository.add_finding(finding)
        repository.add_result(result)
        with pytest.raises((TypeError, ValueError)):
            AgentResult.model_validate("free-form model text")


@pytest.mark.parametrize(
    ("agent_type", "tool_id", "declared"),
    [
        (AgentType.MAIN_AGENT, "execute_mock_action_plan", True),
        (AgentType.INVESTIGATION_AGENT, "create_action_request", True),
        (AgentType.OPERATION_AGENT, "execute_mock_action_plan", True),
        (AgentType.AUDIT_AGENT, "mutate_evidence", True),
        (AgentType.INVESTIGATION_AGENT, "get_evidence", False),
    ],
)
def test_tool_acl_denies_and_audits_unauthorized_requests(
    tmp_path: Path, agent_type: AgentType, tool_id: str, declared: bool
) -> None:
    factory = _factory(tmp_path)
    with factory.begin() as session:
        registry = build_default_registry(session)
        with pytest.raises(DomainError):
            registry.authorize(
                incident_id=None,
                agent_type=agent_type,
                tool_id=tool_id,
                declared_tools={tool_id} if declared else set(),
                granted_permissions={
                    "controlled_execution:execute",
                    "action:propose",
                    "evidence:read",
                },
            )
        assert AuditService(session).verify_chain(None)
