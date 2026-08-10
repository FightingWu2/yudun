"""Integration tests: Security Knowledge RAG citations inside AgentRuntime.

The deterministic golden-path run is started with a KnowledgeService; the
Investigation Agent retrieves knowledge reference material and records
``knowledge_refs`` on its Finding, governed by the audited ``search_knowledge``
tool. When no KnowledgeService is wired, the feature degrades to an empty
citation list without raising.
"""

from pathlib import Path

from sqlalchemy import select

from app.agents.model import DeterministicTestModel
from app.audit.service import AuditService
from app.core.ids import runtime_id
from app.db.base import Base
from app.db.models import AgentFindingORM
from app.db.session import create_business_engine, make_session_factory
from app.knowledge.service import KnowledgeService
from app.orchestration.golden_path import GoldenPathWorkflow
from app.synthetic.scenario import replay_golden_path
from app.tools.registry import build_default_registry

_PROJECT_ROOT = Path(__file__).resolve().parents[3]
_KNOWLEDGE_DIR = _PROJECT_ROOT / "data" / "knowledge"


def _factory(tmp_path: Path):  # type: ignore[no-untyped-def]
    engine = create_business_engine(f"sqlite:///{tmp_path / 'business.db'}")
    Base.metadata.create_all(engine)
    return engine, make_session_factory(engine)


def _model(evidence_refs: list[str]) -> DeterministicTestModel:
    return DeterministicTestModel(
        {
            "main-plan-v1": {
                "next_action": "INVESTIGATE",
                "reason_summary": "Investigate authorized evidence before attribution.",
                "task_type": "INVESTIGATE",
                "task_goal": "Determine credential abuse and resource impact.",
                "evidence_refs": evidence_refs,
                "fact_refs": [],
                "requested_tools": [
                    "get_evidence",
                    "query_cloud_audit",
                    "query_resource_events",
                    "search_knowledge",
                ],
                "unresolved_questions": [],
            },
            "investigation-v1": {
                "statement": "Synthetic evidence shows credential abuse and impact.",
                "evidence_refs": evidence_refs,
                "confidence_level": "HIGH",
                "limitations": ["Synthetic scenario only."],
                "unresolved_questions": [],
                "proposed_fact_types": ["CREDENTIAL_ABUSED"],
            },
        }
    )


def _investigation_findings(session):  # type: ignore[no-untyped-def]
    rows = session.scalars(select(AgentFindingORM))
    return [
        dict(row.payload)
        for row in rows
        if row.payload.get("finding_type") == "INVESTIGATION_FINDING"
    ]


def test_investigation_agent_records_knowledge_refs(tmp_path: Path) -> None:
    engine, factory = _factory(tmp_path)
    knowledge = KnowledgeService(engine, _KNOWLEDGE_DIR)
    evidence_refs = [item.evidence_id for item in replay_golden_path().evidence]
    with factory() as session:
        workflow = GoldenPathWorkflow(
            session,
            build_default_registry(session),
            _model(evidence_refs),
            tmp_path / "checkpoints.db",
            knowledge=knowledge,
        )
        paused = workflow.invoke(
            {"run_id": runtime_id("run"), "thread_id": "k-thread"},
            thread_id="k-thread",
        )
        assert paused["__interrupt__"]

        investigation = _investigation_findings(session)[0]
        assert investigation["knowledge_refs"], "Investigation should cite knowledge docs"
        assert all(ref.startswith("kno-") for ref in investigation["knowledge_refs"])

        # search_knowledge must be governed: audited as an allowed tool call.
        audit_chain = AuditService(session).list_chain(investigation["incident_id"])
        granted = [
            record.object_id
            for record in audit_chain
            if record.event_type == "TOOL_ACCESS_GRANTED"
        ]
        assert "search_knowledge" in granted


def test_investigation_without_knowledge_degrades_gracefully(tmp_path: Path) -> None:
    _, factory = _factory(tmp_path)
    evidence_refs = [item.evidence_id for item in replay_golden_path().evidence]
    with factory() as session:
        workflow = GoldenPathWorkflow(
            session,
            build_default_registry(session),
            _model(evidence_refs),
            tmp_path / "checkpoints.db",
        )
        paused = workflow.invoke(
            {"run_id": runtime_id("run"), "thread_id": "k-thread-no"},
            thread_id="k-thread-no",
        )
        assert paused["__interrupt__"]
        investigation = _investigation_findings(session)[0]
        assert investigation["knowledge_refs"] == []
