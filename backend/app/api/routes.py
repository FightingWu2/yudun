import asyncio
import json
from collections.abc import AsyncIterator
from typing import Annotated, cast

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import StreamingResponse

from app.api.auth import DemoRole, current_role, require_role
from app.api.schemas import ApprovalRequest, ReplayStartRequest
from app.application.demo import DemoRuntime

router = APIRouter(prefix="/api/v1")


def runtime(request: Request) -> DemoRuntime:
    return cast(DemoRuntime, request.app.state.demo_runtime)


READ_ROLES = {DemoRole.ANALYST, DemoRole.APPROVER, DemoRole.AUDITOR, DemoRole.ADMIN}
RuntimeDep = Annotated[DemoRuntime, Depends(runtime)]
RoleDep = Annotated[DemoRole, Depends(current_role)]


@router.get("/runtime/status", tags=["runtime"])
def runtime_status(
    service: RuntimeDep,
    role: RoleDep,
) -> dict[str, object]:
    require_role(role, READ_ROLES)
    return service.status()


@router.get("/replay/sources", tags=["replay"])
def replay_sources(
    service: RuntimeDep,
    role: RoleDep,
) -> dict[str, object]:
    require_role(role, READ_ROLES)
    return service.sources()


@router.post("/replay/reset", tags=["replay"])
def replay_reset(
    service: RuntimeDep,
    role: RoleDep,
) -> dict[str, object]:
    require_role(role, {DemoRole.ADMIN})
    return service.reset()


@router.post("/replay/start", tags=["replay"])
def replay_start(
    payload: ReplayStartRequest,
    service: RuntimeDep,
    role: RoleDep,
) -> dict[str, object]:
    require_role(role, {DemoRole.ADMIN})
    return service.start(
        capture_id=payload.official_capture_id,
        scenario_id=payload.synthetic_scenario_id,
        run_mode=payload.run_mode,
        force_verification_failure=payload.force_verification_failure,
        model_failure=payload.model_failure,
    )


@router.get("/replay/status", tags=["replay"])
def replay_status(
    service: RuntimeDep,
    role: RoleDep,
) -> dict[str, object]:
    require_role(role, READ_ROLES)
    return service.status()


@router.get("/incidents", tags=["incidents"])
def incidents(
    service: RuntimeDep,
    role: RoleDep,
) -> list[dict[str, object]]:
    require_role(role, READ_ROLES)
    return service.list_incidents()


@router.get("/incidents/{incident_id}", tags=["incidents"])
def incident(
    incident_id: str,
    service: RuntimeDep,
    role: RoleDep,
) -> dict[str, object]:
    require_role(role, READ_ROLES)
    return service.incident(incident_id)


@router.get("/incidents/{incident_id}/bundle", tags=["incidents"])
def incident_bundle(
    incident_id: str,
    service: RuntimeDep,
    role: RoleDep,
) -> dict[str, object]:
    require_role(role, READ_ROLES)
    return service.incident_bundle(incident_id)


@router.get("/incidents/{incident_id}/signals", tags=["signals"])
def incident_signals(
    incident_id: str,
    service: RuntimeDep,
    role: RoleDep,
) -> object:
    require_role(role, READ_ROLES)
    return service.incident_bundle(incident_id)["signals"]


@router.get("/incidents/{incident_id}/evidence", tags=["evidence"])
def incident_evidence(
    incident_id: str,
    service: RuntimeDep,
    role: RoleDep,
) -> object:
    require_role(role, READ_ROLES)
    bundle = service.incident_bundle(incident_id)
    return {
        "incident_evidence": bundle["evidence"],
        "official_validation_evidence": bundle["official_evidence"],
    }


@router.get("/incidents/{incident_id}/agents", tags=["agents"])
def incident_agents(
    incident_id: str,
    service: RuntimeDep,
    role: RoleDep,
) -> object:
    require_role(role, READ_ROLES)
    bundle = service.incident_bundle(incident_id)
    return {
        "tasks": bundle["tasks"],
        "results": bundle["results"],
        "findings": bundle["findings"],
    }


@router.get("/incidents/{incident_id}/timeline", tags=["agents"])
def incident_timeline(
    incident_id: str,
    service: RuntimeDep,
    role: RoleDep,
) -> object:
    require_role(role, READ_ROLES)
    return service.incident_bundle(incident_id)["timeline"]


@router.get("/incidents/{incident_id}/actions", tags=["actions"])
def incident_actions(
    incident_id: str,
    service: RuntimeDep,
    role: RoleDep,
) -> object:
    require_role(role, READ_ROLES)
    return service.incident_bundle(incident_id)["actions"]


@router.get("/incidents/{incident_id}/verification", tags=["verification"])
def incident_verification(
    incident_id: str,
    service: RuntimeDep,
    role: RoleDep,
) -> object:
    require_role(role, READ_ROLES)
    return service.incident_bundle(incident_id)["verification"]


@router.get("/incidents/{incident_id}/reasoning-trace", tags=["agents"])
def reasoning_trace(
    incident_id: str,
    service: RuntimeDep,
    role: RoleDep,
) -> list[dict[str, object]]:
    require_role(role, READ_ROLES)
    return service.reasoning_trace(incident_id)


@router.get("/incidents/{incident_id}/audit", tags=["audit"])
def audit(
    incident_id: str,
    service: RuntimeDep,
    role: RoleDep,
) -> dict[str, object]:
    require_role(role, {DemoRole.AUDITOR, DemoRole.ADMIN, DemoRole.ANALYST})
    return service.audit(incident_id)


@router.get("/evidence/{evidence_id}", tags=["evidence"])
def evidence(
    evidence_id: str,
    service: RuntimeDep,
    role: RoleDep,
) -> dict[str, object]:
    require_role(role, READ_ROLES)
    return service.evidence(evidence_id)


@router.get("/actions/{action_request_id}", tags=["actions"])
def action(
    action_request_id: str,
    service: RuntimeDep,
    role: RoleDep,
) -> dict[str, object]:
    require_role(role, READ_ROLES)
    return service.action_request(action_request_id)


@router.post("/approvals", tags=["approvals"])
def approval(
    payload: ApprovalRequest,
    service: RuntimeDep,
    role: RoleDep,
) -> dict[str, object]:
    require_role(role, {DemoRole.APPROVER})
    return service.decide(
        action_request_id=payload.action_request_id,
        decision=payload.decision,
        comment=payload.comment,
        expected_digest=payload.expected_digest,
        request_id=payload.request_id,
    )


@router.get("/knowledge/status", tags=["knowledge"])
def knowledge_status(
    service: RuntimeDep,
    role: RoleDep,
) -> dict[str, object]:
    require_role(role, READ_ROLES)
    return service.knowledge_status()


@router.get("/knowledge/documents", tags=["knowledge"])
def knowledge_documents(
    service: RuntimeDep,
    role: RoleDep,
) -> dict[str, object]:
    require_role(role, READ_ROLES)
    return service.knowledge_documents()


@router.get("/knowledge/search", tags=["knowledge"])
def knowledge_search(
    service: RuntimeDep,
    role: RoleDep,
    q: Annotated[str, Query(max_length=200)] = "",
    limit: Annotated[int, Query(ge=1, le=20)] = 8,
) -> dict[str, object]:
    require_role(role, READ_ROLES)
    return service.knowledge_search(q, limit=limit)


@router.post("/knowledge/reload", tags=["knowledge"])
def knowledge_reload(
    service: RuntimeDep,
    role: RoleDep,
) -> dict[str, object]:
    require_role(role, {DemoRole.ADMIN})
    return service.knowledge_reload()


@router.get("/events", tags=["events"])
async def events(
    service: RuntimeDep,
    role: RoleDep,
    once: Annotated[bool, Query()] = False,
) -> StreamingResponse:
    require_role(role, READ_ROLES)

    async def stream() -> AsyncIterator[str]:
        index = 0
        while True:
            batch, index = service.feed.since(index)
            for event in batch:
                yield f"event: {event['event_type']}\ndata: {json.dumps(event)}\n\n"
            if once:
                return
            await asyncio.sleep(0.25)

    return StreamingResponse(stream(), media_type="text/event-stream")
