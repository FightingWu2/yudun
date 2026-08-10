from pathlib import Path

import pytest
from app.actions.service import PolicyPreAuthorizationService
from app.application.demo import DemoRuntime
from app.core.errors import DomainError
from app.core.ids import runtime_id
from app.db.models import ConfirmedFactORM
from app.domain.enums import RunMode
from app.policies.engine import PolicyEngine
from app.repositories.actions import ActionRepository
from app.schemas.action import ActionRequest, ActionRequestStatus
from app.schemas.mock_state import MockScenarioState
from pydantic import ValidationError
from sqlalchemy import select


def _source(runtime: DemoRuntime) -> tuple[str, str]:
    sources = runtime.sources()
    official = sources["official"]
    synthetic = sources["synthetic"]
    assert isinstance(official, list) and isinstance(synthetic, list)
    return str(official[0]["capture_id"]), str(synthetic[0]["scenario_id"])


def test_autonomous_sandbox_three_runs_close_without_human_approval(tmp_path: Path) -> None:
    runtime = DemoRuntime(Path.cwd(), tmp_path / "runtime", autonomous_enabled=True)
    capture_id, scenario_id = _source(runtime)
    run_ids: set[str] = set()
    incident_ids: set[str] = set()
    for _ in range(3):
        runtime.reset()
        status = runtime.start(
            capture_id=capture_id,
            scenario_id=scenario_id,
            run_mode=RunMode.COMPETITION_AUTONOMOUS,
        )
        assert status["stage"] == "CLOSED"
        assert status["run_mode"] == "COMPETITION_AUTONOMOUS"
        assert isinstance(status["run_id"], str) and status["run_id"] not in run_ids
        assert isinstance(status["incident_id"], str)
        assert status["incident_id"] not in incident_ids
        run_ids.add(status["run_id"])
        incident_ids.add(status["incident_id"])
        bundle = runtime.incident_bundle(status["incident_id"])
        actions = bundle["actions"]
        assert isinstance(actions, dict)
        assert actions["approvals"] == []
        assert len(actions["preauthorizations"]) == 1
        authorization = actions["preauthorizations"][0]
        assert authorization["decision"] == "AUTO_PREAUTHORIZED"
        assert all(item["passed"] for item in authorization["guard_checks"])
        assert len(actions["executions"]) == 1
        assert len(actions["executions"][0]["operation_results"]) == 3
        verification = bundle["verification"]
        assert len(verification) == 1
        assert all(item["passed"] for item in verification[0]["assertions"])
        assert bundle["audit"]["chain_valid"] is True
        assert bundle["incident"]["status"] == "CLOSED"
    runtime.close()


def test_autonomous_requires_explicit_enablement_and_allowlisted_scenario(
    tmp_path: Path,
) -> None:
    runtime = DemoRuntime(Path.cwd(), tmp_path / "disabled", autonomous_enabled=False)
    capture_id, scenario_id = _source(runtime)
    with pytest.raises(DomainError, match="not explicitly enabled"):
        runtime.start(
            capture_id=capture_id,
            scenario_id=scenario_id,
            run_mode=RunMode.COMPETITION_AUTONOMOUS,
        )
    assert runtime.status()["stage"] == "IDLE"
    runtime.close()

    enabled = DemoRuntime(Path.cwd(), tmp_path / "enabled", autonomous_enabled=True)
    with pytest.raises(DomainError, match="not allowlisted"):
        enabled.start(
            capture_id=_source(enabled)[0],
            scenario_id="scenario_not_allowlisted",
            run_mode=RunMode.COMPETITION_AUTONOMOUS,
        )
    assert enabled.status()["stage"] == "IDLE"
    enabled.close()


def test_autonomous_verification_failure_replans_without_approval(tmp_path: Path) -> None:
    runtime = DemoRuntime(Path.cwd(), tmp_path / "runtime", autonomous_enabled=True)
    capture_id, scenario_id = _source(runtime)
    status = runtime.start(
        capture_id=capture_id,
        scenario_id=scenario_id,
        run_mode=RunMode.COMPETITION_AUTONOMOUS,
        force_verification_failure=True,
    )
    assert status["stage"] == "VERIFICATION_FAILED_REPLAN"
    bundle = runtime.incident_bundle(status["incident_id"])
    assert bundle["incident"]["status"] == "ROTATED"
    assert bundle["actions"]["approvals"] == []
    assert len(bundle["actions"]["preauthorizations"]) == 1
    assert bundle["verification"][0]["next_step"] == "REPLAN"
    assert any(item["stage"] == "REPLAN" for item in bundle["reasoning_trace"])
    runtime.close()


def _completed_runtime(tmp_path: Path) -> tuple[DemoRuntime, str, ActionRequest]:
    runtime = DemoRuntime(Path.cwd(), tmp_path, autonomous_enabled=True)
    capture_id, scenario_id = _source(runtime)
    status = runtime.start(
        capture_id=capture_id,
        scenario_id=scenario_id,
        run_mode=RunMode.COMPETITION_AUTONOMOUS,
    )
    bundle = runtime.incident_bundle(str(status["incident_id"]))
    request = ActionRequest.model_validate(bundle["actions"]["requests"][0])  # type: ignore[index]
    return runtime, scenario_id, request


def _clone_request(session, request: ActionRequest, **updates: object) -> ActionRequest:  # type: ignore[no-untyped-def]
    clone = ActionRequest.model_validate(
        request.model_copy(
            update={
                "action_request_id": runtime_id("arq"),
                "idempotency_key": f"autonomous-negative:{runtime_id('run')}",
                "status": ActionRequestStatus.POLICY_PENDING,
                **updates,
            }
        ).model_dump(mode="python")
    )
    ActionRepository(session).add_request(clone)
    PolicyEngine(session).evaluate(clone, run_mode=RunMode.COMPETITION_AUTONOMOUS)
    return clone


def test_autonomous_denies_official_evidence_source(tmp_path: Path) -> None:
    runtime, scenario_id, original = _completed_runtime(tmp_path / "official")
    session = runtime._session  # Test-only access to the isolated runtime transaction.
    assert session is not None
    bundle = runtime.incident_bundle(original.incident_id)
    official_id = bundle["official_evidence"][0]["evidence_id"]  # type: ignore[index]
    fact = session.scalar(
        select(ConfirmedFactORM).where(ConfirmedFactORM.incident_id == original.incident_id)
    )
    assert fact is not None
    fact.payload = {**fact.payload, "evidence_refs": [official_id]}
    session.flush()
    request = _clone_request(session, original)
    decision = PolicyPreAuthorizationService(session, enabled=True).evaluate(
        request,
        run_mode=RunMode.COMPETITION_AUTONOMOUS,
        scenario_id=scenario_id,
    )
    assert decision.decision.value == "DENY"
    assert not next(
        item for item in decision.guard_checks if item.check_id == "SOURCE_SCOPE"
    ).passed
    runtime.close()


def test_autonomous_denies_production_adapter_and_target_mismatch(tmp_path: Path) -> None:
    runtime, scenario_id, original = _completed_runtime(tmp_path / "adapter")
    session = runtime._session
    assert session is not None
    production_request = _clone_request(session, original)
    production = PolicyPreAuthorizationService(
        session,
        enabled=True,
        production_adapter_enabled=True,
    ).evaluate(
        production_request,
        run_mode=RunMode.COMPETITION_AUTONOMOUS,
        scenario_id=scenario_id,
    )
    assert production.decision.value == "DENY"
    assert not next(
        item for item in production.guard_checks if item.check_id == "NO_PRODUCTION_ADAPTER"
    ).passed

    mismatch_request = _clone_request(
        session,
        original,
        target_ref="credential_ref_outside_current_incident",
    )
    mismatch = PolicyPreAuthorizationService(session, enabled=True).evaluate(
        mismatch_request,
        run_mode=RunMode.COMPETITION_AUTONOMOUS,
        scenario_id=scenario_id,
    )
    assert mismatch.decision.value == "DENY"
    assert not next(
        item for item in mismatch.guard_checks if item.check_id == "TARGET_SCOPE"
    ).passed
    runtime.close()


def test_autonomous_rejects_production_environment_unknown_action_and_plaintext_secret(
    tmp_path: Path,
) -> None:
    runtime, _, original = _completed_runtime(tmp_path / "schema")
    state = runtime.incident_bundle(original.incident_id)["mock_state"]
    assert isinstance(state, dict)
    with pytest.raises(ValidationError):
        MockScenarioState.model_validate({**state, "resource_environment": "PRODUCTION"})

    payload = original.model_dump(mode="python")
    payload["action_type"] = "RUN_ARBITRARY_COMMAND"
    with pytest.raises(ValidationError):
        ActionRequest.model_validate(payload)

    payload = original.model_dump(mode="python")
    payload["reason"] = "api_key=contest-plaintext-secret"
    with pytest.raises(ValidationError, match="plaintext secret"):
        ActionRequest.model_validate(payload)
    runtime.close()
