"""Run the deterministic P0 backend Golden Path and write an auditable report."""

import json
import tempfile
import time
from pathlib import Path

from app.agents.model import DeterministicTestModel
from app.audit.reporting import ReasoningTraceService
from app.audit.service import AuditService
from app.core.ids import runtime_id
from app.db.base import Base
from app.db.session import create_business_engine, make_session_factory
from app.mock.state import MockStateService
from app.orchestration.golden_path import GoldenPathWorkflow
from app.repositories.actions import ActionRepository
from app.repositories.audit import AuditRepository
from app.repositories.incidents import IncidentRepository
from app.synthetic.scenario import SCENARIO_ID, replay_golden_path
from app.tools.registry import build_default_registry


def build_model() -> DeterministicTestModel:
    evidence_refs = [item.evidence_id for item in replay_golden_path().evidence]
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
                ],
                "unresolved_questions": [],
            },
            "investigation-v1": {
                "statement": "Synthetic evidence supports credential abuse and impact.",
                "evidence_refs": evidence_refs,
                "confidence_level": "HIGH",
                "limitations": ["Synthetic scenario only."],
                "unresolved_questions": [],
                "proposed_fact_types": [
                    "CI_ACTION_MUTATED",
                    "SECRET_ACCESSED",
                    "CREDENTIAL_EXPOSED",
                    "CREDENTIAL_ABUSED",
                    "SENSITIVE_DATA_ACCESSED",
                    "HIGH_COST_RESOURCE_CREATED",
                ],
            },
        }
    )


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    artifact = root / "artifacts" / "golden_path_backend_report.json"
    with tempfile.TemporaryDirectory(prefix="yudun_golden_path_") as temp:
        temp_path = Path(temp)
        engine = create_business_engine(f"sqlite:///{temp_path / 'business.db'}")
        Base.metadata.create_all(engine)
        factory = make_session_factory(engine)
        with factory() as session:
            workflow = GoldenPathWorkflow(
                session,
                build_default_registry(session),
                build_model(),
                temp_path / "checkpoints.db",
            )
            start = time.perf_counter()
            paused = workflow.invoke(
                {
                    "run_id": runtime_id("run"),
                    "thread_id": "artifact-golden-thread",
                    "retry_counters": {},
                },
                thread_id="artifact-golden-thread",
            )
            paused_at = time.perf_counter()
            before = MockStateService(session).get(SCENARIO_ID)
            finished = workflow.resume(
                {
                    "decision": "APPROVED",
                    "approver_id": "artifact_human_approver",
                    "comment": "P0 Golden Path regression approval",
                },
                thread_id="artifact-golden-thread",
            )
            completed_at = time.perf_counter()
            after = MockStateService(session).get(SCENARIO_ID)
            incident = IncidentRepository(session).get(finished["incident_id"])
            action_repo = ActionRepository(session)
            request = action_repo.get_request(finished["action_request_id"])
            approval = action_repo.latest_approval(finished["action_request_id"])
            execution = action_repo.get_execution(finished["execution_id"])
            verifications = action_repo.list_verifications(finished["incident_id"])
            verification = verifications[-1]
            trace = ReasoningTraceService(session).build(finished["incident_id"])
            audit_records = AuditRepository(session).list_chain(finished["incident_id"])
            model_calls = [
                {"audit_id": item.audit_id, **item.payload_redacted}
                for item in audit_records
                if item.event_type == "MODEL_CALL_COMPLETED"
            ]
            tool_calls = [
                {
                    "audit_id": item.audit_id,
                    "actor": item.actor_id,
                    "tool_id": item.object_id,
                    "result": item.event_type,
                    "detail": item.payload_redacted,
                }
                for item in audit_records
                if item.event_type in {"TOOL_ACCESS_GRANTED", "TOOL_ACCESS_DENIED"}
            ]
            assert incident is not None
            assert request is not None
            assert approval is not None
            assert execution is not None
            report = {
                "generated_for": "DEV-016-025 deterministic backend regression",
                "provider": "DETERMINISTIC_TEST_MODEL",
                "live_model_validation": "PENDING_NO_CONFIGURATION",
                "incident_id": incident.incident_id,
                "incident_status": incident.status.value,
                "action_request_id": request.action_request_id,
                "approval_id": approval.approval_id,
                "request_digest": approval.request_digest,
                "execution_id": execution.execution_id,
                "verification_id": verification.verification_id,
                "interrupt_observed": bool(paused.get("__interrupt__")),
                "checkpoint_database_separate": (temp_path / "checkpoints.db").exists(),
                "audit_chain_valid": AuditService(session).verify_chain(incident.incident_id),
                "timings_ms": {
                    "pre_approval_graph": round((paused_at - start) * 1000, 3),
                    "approval_resume_to_close": round((completed_at - paused_at) * 1000, 3),
                    "total_excluding_human_wait": round((completed_at - start) * 1000, 3),
                    "mock_execution": round(
                        (execution.completed_at - execution.started_at).total_seconds() * 1000,
                        3,
                    ),
                    "nodes": workflow.node_timings_ms,
                },
                "mock_state": {
                    "before": before.model_dump(mode="json"),
                    "after": after.model_dump(mode="json"),
                },
                "operations": [
                    item.model_dump(mode="json") for item in execution.operation_results
                ],
                "verification": [item.model_dump(mode="json") for item in verification.assertions],
                "model_calls": model_calls,
                "tool_calls": tool_calls,
                "reasoning_trace": [item.model_dump(mode="json") for item in trace],
            }
            artifact.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
            workflow.close()
    print(f"Golden Path report written: {artifact}")


if __name__ == "__main__":
    main()
