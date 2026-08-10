import json
import os
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any, cast

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.actions.service import action_request_digest
from app.agents.model import DeterministicTestModel
from app.audit.reporting import ReasoningTraceService
from app.audit.service import AuditService
from app.core.errors import ConflictError, DomainError, ErrorCode
from app.core.ids import runtime_id
from app.core.time import utc_now
from app.db.base import Base
from app.db.models import (
    ActionRecommendationORM,
    ActionRequestORM,
    AgentFindingORM,
    AgentResultORM,
    AgentTaskORM,
    ApprovalRecordORM,
    AssociationORM,
    ConfirmedFactORM,
    EvidenceORM,
    ExecutionResultORM,
    PolicyDecisionORM,
    PolicyPreAuthorizationORM,
    SecurityIncidentORM,
    SecuritySignalORM,
    VerificationResultORM,
)
from app.db.session import create_business_engine, make_session_factory
from app.domain.enums import ApprovalDecision, EvidenceSensitivity, RunMode
from app.evidence.service import EvidenceService
from app.knowledge.service import KnowledgeService
from app.mock.state import MockStateService
from app.orchestration.golden_path import GoldenPathState, GoldenPathWorkflow
from app.pcap.parser import normalize_capture
from app.repositories.actions import ActionRepository
from app.repositories.audit import AuditRepository
from app.repositories.captures import CaptureRepository
from app.repositories.incidents import IncidentRepository
from app.schemas.action import ActionRequest
from app.schemas.data import CaptureRecord
from app.schemas.evidence import EvidenceReference
from app.synthetic.scenario import SCENARIO_ID, replay_golden_path
from app.tools.registry import build_default_registry


class EventFeed:
    """Small in-process notification feed; business objects remain in business.db."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._events: list[dict[str, object]] = []

    def clear(self) -> None:
        with self._lock:
            self._events.clear()

    def publish(self, event_type: str, incident_id: str | None, object_id: str) -> None:
        with self._lock:
            self._events.append(
                {
                    "event_type": event_type,
                    "incident_id": incident_id,
                    "object_id": object_id,
                    "timestamp": utc_now().isoformat().replace("+00:00", "Z"),
                    "version": 1,
                }
            )

    def since(self, index: int) -> tuple[list[dict[str, object]], int]:
        with self._lock:
            return list(self._events[index:]), len(self._events)


class DemoRuntime:
    """Owns one guarded demo run and delegates all decisions to existing domain services."""

    def __init__(
        self,
        root: Path,
        runtime_dir: Path | None = None,
        *,
        autonomous_enabled: bool | None = None,
    ) -> None:
        self.root = root.resolve()
        self.runtime_dir = (runtime_dir or self.root / ".runtime").resolve()
        self.runtime_dir.mkdir(parents=True, exist_ok=True)
        self.business_path = self.runtime_dir / "business.db"
        self.checkpoint_path = self.runtime_dir / "checkpoints.db"
        self.manifest_path = self.root / "artifacts" / "official_dataset_manifest.json"
        self.dataset_root = self.root / "data" / "测评中心基线样本nta"
        self._lock = threading.RLock()
        self.feed = EventFeed()
        self._engine = create_business_engine(f"sqlite:///{self.business_path}")
        Base.metadata.create_all(self._engine)
        self._factory: sessionmaker[Session] = make_session_factory(self._engine)
        self._knowledge = KnowledgeService(self._engine, self.root / "data" / "knowledge")
        self._session: Session | None = None
        self._workflow: GoldenPathWorkflow | None = None
        self._thread_id: str | None = None
        self._incident_id: str | None = None
        self._run_id: str | None = None
        self._stage = "IDLE"
        self._selected_capture_id: str | None = None
        self._official_evidence_ids: list[str] = []
        self._request_results: dict[str, dict[str, object]] = {}
        self._started_at: str | None = None
        self._ended_at: str | None = None
        self._node_timings_ms: dict[str, list[float]] = {}
        self._stop_reason: str | None = None
        self._run_mode = RunMode.PRODUCTION_GUARDED
        self._autonomous_enabled = (
            os.getenv("COMPETITION_AUTONOMOUS_ENABLED") == "1"
            if autonomous_enabled is None
            else autonomous_enabled
        )

    def close(self) -> None:
        with self._lock:
            if self._workflow is not None:
                self._workflow.close()
            if self._session is not None:
                self._session.close()
            self._engine.dispose()

    def reset(self) -> dict[str, object]:
        with self._lock:
            self.close()
            for path in (
                self.business_path,
                self.business_path.with_name(f"{self.business_path.name}-wal"),
                self.business_path.with_name(f"{self.business_path.name}-shm"),
                self.checkpoint_path,
                self.checkpoint_path.with_name(f"{self.checkpoint_path.name}-wal"),
                self.checkpoint_path.with_name(f"{self.checkpoint_path.name}-shm"),
            ):
                if path.exists():
                    path.unlink()
            self._engine = create_business_engine(f"sqlite:///{self.business_path}")
            Base.metadata.create_all(self._engine)
            self._factory = make_session_factory(self._engine)
            self._knowledge = KnowledgeService(self._engine, self.root / "data" / "knowledge")
            self._session = None
            self._workflow = None
            self._thread_id = None
            self._incident_id = None
            self._run_id = None
            self._stage = "IDLE"
            self._selected_capture_id = None
            self._official_evidence_ids = []
            self._request_results.clear()
            self._started_at = None
            self._ended_at = None
            self._node_timings_ms = {}
            self._stop_reason = None
            self._run_mode = RunMode.PRODUCTION_GUARDED
            self.feed.clear()
            self.feed.publish("replay.reset", None, SCENARIO_ID)
            return self.status()

    def sources(self) -> dict[str, object]:
        manifest = self._manifest()
        entries = manifest["entries"]
        preferred = [
            item
            for item in entries
            if item["safe_display_name"]
            in {
                "sql注入.pcap",
                "ThinkPHP_rce.pcap",
                "jsp.pcap",
                "1.postgresql_dnslog_powershell_cs.pcap",
            }
        ]
        return {
            "official": [
                {
                    "capture_id": item["capture_id"],
                    "display_name": item["safe_display_name"],
                    "format": item["format"],
                    "packet_count": item["packet_count"],
                    "source_type": "OFFICIAL",
                }
                for item in (preferred or entries[:20])
            ],
            "synthetic": [
                {
                    "scenario_id": SCENARIO_ID,
                    "display_name": "CI Action 篡改与 API 凭据泄露",
                    "source_type": "SYNTHETIC",
                }
            ],
            "run_modes": [
                {
                    "run_mode": RunMode.PRODUCTION_GUARDED.value,
                    "enabled": True,
                    "safety_label": "HUMAN APPROVAL REQUIRED",
                },
                {
                    "run_mode": RunMode.COMPETITION_AUTONOMOUS.value,
                    "enabled": self._autonomous_enabled,
                    "safety_label": "SANDBOX ONLY · NO PRODUCTION SIDE EFFECT",
                },
            ],
        }

    def start(
        self,
        *,
        capture_id: str,
        scenario_id: str,
        run_mode: RunMode = RunMode.PRODUCTION_GUARDED,
        force_verification_failure: bool = False,
        model_failure: bool = False,
    ) -> dict[str, object]:
        with self._lock:
            if scenario_id != SCENARIO_ID:
                raise DomainError(ErrorCode.SOURCE_UNAVAILABLE, "scenario is not allowlisted")
            if run_mode is RunMode.COMPETITION_AUTONOMOUS and not self._autonomous_enabled:
                raise DomainError(
                    ErrorCode.PERMISSION_DENIED,
                    "Competition Autonomous Sandbox is not explicitly enabled",
                )
            if self._stage != "IDLE":
                raise ConflictError("reset the current replay before starting another run")
            capture = self._capture_by_id(capture_id)
            self._session = self._factory()
            self._import_official(capture, self._session)
            model = self._model(fail="TIMEOUT" if model_failure else None)
            self._thread_id = f"demo-{runtime_id('run')}"
            self._workflow = GoldenPathWorkflow(
                self._session,
                build_default_registry(self._session),
                model,
                self.checkpoint_path,
                autonomous_enabled=self._autonomous_enabled,
                knowledge=self._knowledge,
            )
            initial: GoldenPathState = {
                "run_id": runtime_id("run"),
                "thread_id": self._thread_id,
                "run_mode": run_mode.value,
                "retry_counters": (
                    {"force_verification_failure": 1} if force_verification_failure else {}
                ),
            }
            self._started_at = utc_now().isoformat().replace("+00:00", "Z")
            result = self._workflow.invoke(initial, thread_id=self._thread_id)
            self._node_timings_ms = self._workflow.node_timings_ms
            self._session.commit()
            # The Synthetic scenario owns a reproducible replay identifier inside the graph.
            # The product runtime still needs a fresh ID for each isolated browser run.
            self._run_id = initial["run_id"]
            self._incident_id = result.get("incident_id")
            self._selected_capture_id = capture_id
            self._run_mode = run_mode
            if result.get("__interrupt__"):
                self._stage = "WAITING_APPROVAL"
            else:
                self._stop_reason = str(result.get("stop_reason", "STOPPED"))
                self._stage = (
                    "MANUAL_REQUIRED"
                    if self._stop_reason in {"MODEL_UNAVAILABLE", "SCHEMA_INVALID"}
                    else self._stop_reason
                )
                self._ended_at = utc_now().isoformat().replace("+00:00", "Z")
            self._publish_current(pre_approval=self._stage == "WAITING_APPROVAL")
            return self.status()

    def decide(
        self,
        *,
        action_request_id: str,
        decision: ApprovalDecision,
        comment: str,
        expected_digest: str,
        request_id: str,
    ) -> dict[str, object]:
        with self._lock:
            if request_id in self._request_results:
                return self._request_results[request_id]
            if self._stage != "WAITING_APPROVAL":
                raise ConflictError("workflow is not waiting for approval")
            session = self._required_session()
            request = ActionRepository(session).get_request(action_request_id)
            if request is None:
                raise DomainError(ErrorCode.NOT_FOUND, "ActionRequest was not found")
            if expected_digest != action_request_digest(request):
                raise ConflictError("expected digest does not match current ActionRequest")
            workflow = self._required_workflow()
            result = workflow.resume(
                {
                    "decision": decision.value,
                    "approver_id": "local_demo_approver",
                    "comment": comment,
                },
                thread_id=self._required_thread_id(),
            )
            self._node_timings_ms = workflow.node_timings_ms
            session.commit()
            self._stage = str(result.get("stop_reason", result.get("current_node", "STOPPED")))
            self._stop_reason = result.get("stop_reason")
            self._ended_at = utc_now().isoformat().replace("+00:00", "Z")
            response = self.status()
            self._request_results[request_id] = response
            self._publish_current(pre_approval=False)
            return response

    def status(self) -> dict[str, object]:
        return {
            "run_id": self._run_id,
            "thread_id": self._thread_id,
            "incident_id": self._incident_id,
            "stage": self._stage,
            "run_mode": self._run_mode.value,
            "model_provider": "DETERMINISTIC_TEST",
            "selected_capture_id": self._selected_capture_id,
            "synthetic_scenario_id": SCENARIO_ID,
            "started_at": self._started_at,
            "ended_at": self._ended_at,
            "node_timings_ms": self._node_timings_ms,
            "stop_reason": self._stop_reason,
            "business_database": "business.db",
            "checkpoint_database": "checkpoints.db",
            "competition_autonomous": (
                "IMPLEMENTED_ENABLED" if self._autonomous_enabled else "IMPLEMENTED_DISABLED"
            ),
            "autonomous_enabled": self._autonomous_enabled,
        }

    # ------------------------------------------------- Security Knowledge RAG

    def knowledge_documents(self) -> dict[str, Any]:
        with self._lock:
            documents = self._knowledge.list_documents()
            return {"documents": documents, "total": len(documents)}

    def knowledge_status(self) -> dict[str, Any]:
        with self._lock:
            return self._knowledge.status().model_dump(mode="json")

    def knowledge_search(self, query: str, limit: int = 8) -> dict[str, Any]:
        with self._lock:
            result = self._knowledge.search(query, limit=limit)
            return result.model_dump(mode="json")

    def knowledge_reload(self) -> dict[str, Any]:
        with self._lock:
            return self._knowledge.reload().model_dump(mode="json")

    def list_incidents(self) -> list[dict[str, Any]]:
        with self._read_session() as session:
            rows = session.scalars(
                select(SecurityIncidentORM).order_by(SecurityIncidentORM.opened_at.desc())
            )
            return [dict(row.payload) for row in rows]

    def incident(self, incident_id: str) -> dict[str, Any]:
        with self._read_session() as session:
            incident = IncidentRepository(session).get(incident_id)
            if incident is None:
                raise DomainError(ErrorCode.NOT_FOUND, "Incident was not found")
            result = incident.model_dump(mode="json")
            result["current_blocker"] = self._current_blocker(incident.status.value)
            result["next_expected_stage"] = self._next_stage(incident.status.value)
            return result

    def incident_bundle(self, incident_id: str) -> dict[str, object]:
        with self._read_session() as session:
            incident = IncidentRepository(session).get(incident_id)
            if incident is None:
                raise DomainError(ErrorCode.NOT_FOUND, "Incident was not found")
            actions = self._actions(session, incident_id)
            try:
                mock_state: object = (
                    MockStateService(session).get(SCENARIO_ID).model_dump(mode="json")
                )
            except ValueError:
                mock_state = None
            return {
                "runtime": self.status(),
                "incident": self.incident(incident_id),
                "signals": self._payloads(session, SecuritySignalORM, incident_id),
                "evidence": self._safe_evidence_list(session, incident_id),
                "official_evidence": self._official_evidence(session),
                "tasks": self._payloads(session, AgentTaskORM, incident_id),
                "results": self._payloads(session, AgentResultORM, incident_id),
                "findings": self._payloads(session, AgentFindingORM, incident_id),
                "facts": self._payloads(session, ConfirmedFactORM, incident_id),
                "associations": self._payloads(session, AssociationORM, incident_id),
                "actions": actions,
                "verification": self._payloads(session, VerificationResultORM, incident_id),
                "audit": self._audit_view(session, incident_id),
                "reasoning_trace": [
                    item.model_dump(mode="json")
                    for item in ReasoningTraceService(session).build(incident_id)
                ],
                "mock_state": mock_state,
            }

    def evidence(self, evidence_id: str) -> dict[str, Any]:
        with self._read_session() as session:
            row = session.get(EvidenceORM, evidence_id)
            if row is None:
                raise DomainError(ErrorCode.NOT_FOUND, "Evidence was not found")
            evidence = EvidenceReference.model_validate(row.payload)
            if evidence.sensitivity is EvidenceSensitivity.SECRET:
                raise DomainError(ErrorCode.PERMISSION_DENIED, "SECRET Evidence is not exposed")
            return self._safe_evidence(evidence)

    def action_request(self, action_request_id: str) -> dict[str, object]:
        with self._read_session() as session:
            request = ActionRepository(session).get_request(action_request_id)
            if request is None:
                raise DomainError(ErrorCode.NOT_FOUND, "ActionRequest was not found")
            return {
                "request": request.model_dump(mode="json"),
                "request_digest": action_request_digest(request),
                "policy": self._policy_for_request(session, action_request_id),
                "approval": self._approval_for_request(session, action_request_id),
                "preauthorization": self._preauthorization_for_request(session, action_request_id),
            }

    def reasoning_trace(self, incident_id: str) -> list[dict[str, Any]]:
        with self._read_session() as session:
            return [
                item.model_dump(mode="json")
                for item in ReasoningTraceService(session).build(incident_id)
            ]

    def audit(self, incident_id: str) -> dict[str, object]:
        with self._read_session() as session:
            return self._audit_view(session, incident_id)

    def _import_official(self, capture: CaptureRecord, session: Session) -> None:
        if CaptureRepository(session).get(capture.capture_id) is None:
            CaptureRepository(session).add(capture)
        relative_path = capture.source_location.relative_path
        path = self.dataset_root / relative_path
        normalized = normalize_capture(capture, path)
        self._official_evidence_ids = []
        for evidence in normalized.evidence[:20]:
            EvidenceService(session).create(evidence)
            self._official_evidence_ids.append(evidence.evidence_id)

    def _publish_current(self, *, pre_approval: bool) -> None:
        incident_id = self._incident_id
        if incident_id is None:
            return
        bundle = self.incident_bundle(incident_id)
        signals = cast(list[dict[str, Any]], bundle["signals"])
        tasks = cast(list[dict[str, Any]], bundle["tasks"])
        facts = cast(list[dict[str, Any]], bundle["facts"])
        verifications = cast(list[dict[str, Any]], bundle["verification"])
        actions = cast(dict[str, Any], bundle["actions"])
        for signal in signals:
            self.feed.publish("signal.created", incident_id, signal["signal_id"])
        for task in tasks:
            self.feed.publish("agent.task.created", incident_id, task["task_id"])
        for fact in facts:
            self.feed.publish("fact.confirmed", incident_id, fact["fact_id"])
        if actions["requests"]:
            request = actions["requests"][-1]
            event_type = "approval.required" if pre_approval else "approval.decided"
            if actions["preauthorizations"]:
                event_type = "preauthorization.decided"
            self.feed.publish(
                event_type,
                incident_id,
                request["action_request_id"],
            )
        if not pre_approval:
            for execution in actions["executions"]:
                self.feed.publish("execution.step.updated", incident_id, execution["execution_id"])
            for verification in verifications:
                self.feed.publish(
                    "verification.updated", incident_id, verification["verification_id"]
                )
            final = self.incident(incident_id)
            event_type = "incident.closed" if final["status"] == "CLOSED" else "replan.created"
            self.feed.publish(event_type, incident_id, incident_id)
        self.feed.publish("incident.updated", incident_id, incident_id)

    def _actions(self, session: Session, incident_id: str) -> dict[str, object]:
        recommendations = self._payloads(session, ActionRecommendationORM, incident_id)
        requests = self._payloads(session, ActionRequestORM, incident_id)
        request_ids = [item["action_request_id"] for item in requests]
        policies = [
            dict(row.payload)
            for row in session.scalars(select(PolicyDecisionORM))
            if row.action_request_id in request_ids
        ]
        approvals = [
            dict(row.payload)
            for row in session.scalars(select(ApprovalRecordORM))
            if row.action_request_id in request_ids
        ]
        preauthorizations = [
            dict(row.payload)
            for row in session.scalars(select(PolicyPreAuthorizationORM))
            if row.action_request_id in request_ids
        ]
        executions = [
            dict(row.payload)
            for row in session.scalars(select(ExecutionResultORM))
            if row.action_request_id in request_ids
        ]
        return {
            "recommendations": recommendations,
            "requests": requests,
            "policies": policies,
            "approvals": approvals,
            "preauthorizations": preauthorizations,
            "executions": executions,
            "request_digest": (
                action_request_digest(ActionRequest.model_validate(requests[-1]))
                if requests
                else None
            ),
        }

    def _audit_view(self, session: Session, incident_id: str) -> dict[str, object]:
        records = AuditRepository(session).list_chain(incident_id)
        return {
            "chain_valid": AuditService(session).verify_chain(incident_id),
            "records": [item.model_dump(mode="json") for item in records],
        }

    @staticmethod
    def _payloads(
        session: Session,
        model: type[Any],
        incident_id: str,
    ) -> list[dict[str, Any]]:
        rows = session.scalars(select(model).where(model.incident_id == incident_id))
        return [dict(row.payload) for row in rows]

    def _safe_evidence_list(self, session: Session, incident_id: str) -> list[dict[str, Any]]:
        rows = session.scalars(
            select(EvidenceORM).where(
                (EvidenceORM.incident_id == incident_id) | (EvidenceORM.source_type != "OFFICIAL")
            )
        )
        return [
            self._safe_evidence(EvidenceReference.model_validate(row.payload))
            for row in rows
            if row.sensitivity != EvidenceSensitivity.SECRET.value
        ]

    def _official_evidence(self, session: Session) -> list[dict[str, Any]]:
        result = []
        for evidence_id in self._official_evidence_ids:
            row = session.get(EvidenceORM, evidence_id)
            if row is not None:
                result.append(self._safe_evidence(EvidenceReference.model_validate(row.payload)))
        return result

    @staticmethod
    def _safe_evidence(evidence: EvidenceReference) -> dict[str, Any]:
        payload = evidence.model_dump(mode="json")
        payload.pop("allowed_agent_types", None)
        payload["source_badge"] = evidence.source_type.value
        return payload

    def _manifest(self) -> dict[str, Any]:
        return cast(
            dict[str, Any],
            json.loads(self.manifest_path.read_text(encoding="utf-8")),
        )

    def _capture_by_id(self, capture_id: str) -> CaptureRecord:
        for item in self._manifest()["entries"]:
            if item["capture_id"] == capture_id:
                return CaptureRecord.model_validate(item)
        raise DomainError(ErrorCode.SOURCE_UNAVAILABLE, "official capture is not allowlisted")

    @staticmethod
    def _model(*, fail: str | None = None) -> DeterministicTestModel:
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
                    "proposed_fact_types": [
                        "CI_ACTION_MUTATED",
                        "SECRET_ACCESSED",
                        "CREDENTIAL_EXPOSED",
                        "CREDENTIAL_ABUSED",
                        "SENSITIVE_DATA_ACCESSED",
                        "HIGH_COST_RESOURCE_CREATED",
                    ],
                },
            },
            fail=fail,
        )

    @contextmanager
    def _read_session(self) -> Iterator[Session]:
        # Reset replaces the SQLite files. Keep each read inside the same runtime lock so
        # an SSE refresh cannot observe the short rebuild window.
        with self._lock:
            session = self._factory()
            try:
                yield session
            finally:
                session.close()

    def _required_session(self) -> Session:
        if self._session is None:
            raise ConflictError("no active workflow session")
        return self._session

    def _required_workflow(self) -> GoldenPathWorkflow:
        if self._workflow is None:
            raise ConflictError("no active workflow")
        return self._workflow

    def _required_thread_id(self) -> str:
        if self._thread_id is None:
            raise ConflictError("no active workflow thread")
        return self._thread_id

    @staticmethod
    def _policy_for_request(session: Session, request_id: str) -> dict[str, Any] | None:
        row = session.scalar(
            select(PolicyDecisionORM).where(PolicyDecisionORM.action_request_id == request_id)
        )
        return None if row is None else dict(row.payload)

    @staticmethod
    def _approval_for_request(session: Session, request_id: str) -> dict[str, Any] | None:
        row = session.scalar(
            select(ApprovalRecordORM)
            .where(ApprovalRecordORM.action_request_id == request_id)
            .order_by(ApprovalRecordORM.created_at.desc())
        )
        return None if row is None else dict(row.payload)

    @staticmethod
    def _preauthorization_for_request(session: Session, request_id: str) -> dict[str, Any] | None:
        row = session.scalar(
            select(PolicyPreAuthorizationORM).where(
                PolicyPreAuthorizationORM.action_request_id == request_id
            )
        )
        return None if row is None else dict(row.payload)

    @staticmethod
    def _current_blocker(status: str) -> str | None:
        return {
            "ATTRIBUTED": "Policy and human approval are required.",
            "ROTATED": "All six recovery assertions must pass.",
            "VERIFIED": "Audit integrity is required before closure.",
        }.get(status)

    @staticmethod
    def _next_stage(status: str) -> str | None:
        return {
            "NEW": "DETECTED",
            "DETECTED": "INVESTIGATING",
            "INVESTIGATING": "ATTRIBUTED",
            "ATTRIBUTED": "CONTAINED",
            "CONTAINED": "ROTATED",
            "ROTATED": "VERIFIED",
            "VERIFIED": "CLOSED",
        }.get(status)
