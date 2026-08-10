from pathlib import Path

import pytest
from app.application.demo import DemoRuntime
from app.main import create_app
from fastapi.testclient import TestClient


@pytest.fixture
def client(tmp_path: Path) -> TestClient:
    runtime = DemoRuntime(Path.cwd(), tmp_path / "runtime")
    with TestClient(create_app(runtime)) as test_client:
        yield test_client
    runtime.close()


def _start(client: TestClient, *, verification_failure: bool = False) -> dict[str, object]:
    sources = client.get("/api/v1/replay/sources").json()
    response = client.post(
        "/api/v1/replay/start",
        headers={"X-Demo-Role": "ADMIN"},
        json={
            "official_capture_id": sources["official"][0]["capture_id"],
            "synthetic_scenario_id": sources["synthetic"][0]["scenario_id"],
            "force_verification_failure": verification_failure,
        },
    )
    assert response.status_code == 200
    return response.json()


def test_openapi_rbac_and_no_direct_execution_endpoint(client: TestClient) -> None:
    schema = client.get("/openapi.json").json()
    paths = set(schema["paths"])
    assert "/api/v1/approvals" in paths
    assert not any(path.endswith(("/execute", "/freeze-key", "/rotate-key")) for path in paths)
    assert client.post("/api/v1/replay/reset").status_code == 403
    assert (
        client.post("/api/v1/replay/reset", headers={"X-Demo-Role": "UNKNOWN_ROLE"}).status_code
        == 403
    )
    assert client.post("/api/v1/replay/reset", headers={"X-Demo-Role": "ADMIN"}).status_code == 200

    invalid = client.post(
        "/api/v1/replay/start",
        headers={"X-Demo-Role": "ADMIN"},
        json={"official_capture_id": ""},
    )
    assert invalid.status_code == 422
    assert invalid.json() == {
        "schema_version": "1.0",
        "code": "SCHEMA_INVALID",
        "message": "request schema validation failed",
        "retryable": False,
    }


def test_api_golden_path_uses_real_business_objects_and_sse(client: TestClient) -> None:
    client.post("/api/v1/replay/reset", headers={"X-Demo-Role": "ADMIN"})
    started = _start(client)
    assert started["stage"] == "WAITING_APPROVAL"
    incident_id = started["incident_id"]
    bundle = client.get(f"/api/v1/incidents/{incident_id}/bundle").json()
    assert bundle["incident"]["status"] == "ATTRIBUTED"
    assert len(bundle["facts"]) == 6
    assert bundle["actions"]["executions"] == []
    assert bundle["mock_state"]["credential"]["old_version_status"] == "ACTIVE"
    assert {item["source_badge"] for item in bundle["evidence"]} == {"SYNTHETIC"}
    assert {item["source_badge"] for item in bundle["official_evidence"]} == {"OFFICIAL"}
    official = bundle["official_evidence"][0]
    detail = client.get(f"/api/v1/evidence/{official['evidence_id']}").json()
    assert detail["locator"]["capture_id"].startswith("cap_")
    assert detail["locator"].get("packet_indexes") or detail["locator"].get("flow_id")
    assert "/Users/" not in str(detail)

    with client.stream("GET", "/api/v1/events?once=true") as response:
        body = "".join(response.iter_text())
    assert "approval.required" in body
    assert incident_id in body

    request = bundle["actions"]["requests"][0]
    denied = client.post(
        "/api/v1/approvals",
        headers={"X-Demo-Role": "ANALYST"},
        json={
            "action_request_id": request["action_request_id"],
            "decision": "APPROVED",
            "comment": "not allowed",
            "expected_digest": bundle["actions"]["request_digest"],
            "request_id": "analyst-request-001",
        },
    )
    assert denied.status_code == 403

    conflict = client.post(
        "/api/v1/approvals",
        headers={"X-Demo-Role": "APPROVER"},
        json={
            "action_request_id": request["action_request_id"],
            "decision": "APPROVED",
            "comment": "wrong digest",
            "expected_digest": "0" * 64,
            "request_id": "approver-request-conflict",
        },
    )
    assert conflict.status_code == 409
    assert conflict.json()["code"] == "CONFLICT"

    approved = client.post(
        "/api/v1/approvals",
        headers={"X-Demo-Role": "APPROVER"},
        json={
            "action_request_id": request["action_request_id"],
            "decision": "APPROVED",
            "comment": "approved by API contract test",
            "expected_digest": bundle["actions"]["request_digest"],
            "request_id": "approver-request-success",
        },
    )
    assert approved.status_code == 200
    assert approved.json()["stage"] == "CLOSED"
    closed = client.get(f"/api/v1/incidents/{incident_id}/bundle").json()
    assert closed["incident"]["status"] == "CLOSED"
    assert len(closed["actions"]["executions"]) == 1
    assert len(closed["verification"][0]["assertions"]) == 6
    assert all(item["passed"] for item in closed["verification"][0]["assertions"])
    assert closed["audit"]["chain_valid"] is True


def test_api_reject_and_verification_failure_are_fail_safe(client: TestClient) -> None:
    client.post("/api/v1/replay/reset", headers={"X-Demo-Role": "ADMIN"})
    started = _start(client)
    incident_id = started["incident_id"]
    bundle = client.get(f"/api/v1/incidents/{incident_id}/bundle").json()
    request = bundle["actions"]["requests"][0]
    rejected = client.post(
        "/api/v1/approvals",
        headers={"X-Demo-Role": "APPROVER"},
        json={
            "action_request_id": request["action_request_id"],
            "decision": "REJECTED",
            "comment": "business impact rejected",
            "expected_digest": bundle["actions"]["request_digest"],
            "request_id": "approver-request-reject",
        },
    )
    assert rejected.status_code == 200
    after_reject = client.get(f"/api/v1/incidents/{incident_id}/bundle").json()
    assert after_reject["actions"]["executions"] == []
    assert after_reject["mock_state"] == bundle["mock_state"]

    client.post("/api/v1/replay/reset", headers={"X-Demo-Role": "ADMIN"})
    failed_start = _start(client, verification_failure=True)
    failed_id = failed_start["incident_id"]
    failed_bundle = client.get(f"/api/v1/incidents/{failed_id}/bundle").json()
    failed_request = failed_bundle["actions"]["requests"][0]
    resumed = client.post(
        "/api/v1/approvals",
        headers={"X-Demo-Role": "APPROVER"},
        json={
            "action_request_id": failed_request["action_request_id"],
            "decision": "APPROVED",
            "comment": "exercise verification failure",
            "expected_digest": failed_bundle["actions"]["request_digest"],
            "request_id": "approver-request-failure",
        },
    )
    assert resumed.status_code == 200
    assert resumed.json()["stage"] == "VERIFICATION_FAILED_REPLAN"
    after_failure = client.get(f"/api/v1/incidents/{failed_id}/bundle").json()
    assert after_failure["incident"]["status"] == "ROTATED"
    assert after_failure["verification"][0]["next_step"] == "REPLAN"
    assert any(item["stage"] == "REPLAN" for item in after_failure["reasoning_trace"])
