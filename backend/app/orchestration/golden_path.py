import sqlite3
from collections.abc import Callable
from itertools import pairwise
from pathlib import Path
from time import perf_counter
from typing import TypedDict, cast

from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.graph import END, START, StateGraph
from langgraph.types import Command, interrupt
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.actions.service import (
    ActionPlanningService,
    ApprovalService,
    ControlledExecutor,
    OperationAgentService,
    PolicyPreAuthorizationService,
    action_request_digest,
)
from app.agents.contracts import AuditReport
from app.agents.model import ModelAdapter
from app.agents.runtime import AgentRuntime
from app.audit.reporting import AuditAgentService, IncidentClosureService
from app.audit.service import AuditService
from app.core.ids import runtime_id
from app.db.models import EvidenceORM
from app.domain.enums import (
    ApprovalDecision,
    IncidentStatus,
    PreAuthorizationDecision,
    RunMode,
    TaskStatus,
)
from app.evidence.service import EvidenceService
from app.knowledge.service import KnowledgeService
from app.mock.state import MockStateService
from app.policies.engine import PolicyEngine
from app.repositories.actions import ActionRepository
from app.repositories.agents import AgentContractRepository
from app.repositories.evidence import EvidenceRepository
from app.repositories.facts import FactRepository
from app.schemas.agent import AgentTask, AllowedContext, TaskCreator, TaskType
from app.schemas.audit import AuditActorType
from app.schemas.evidence import EvidenceReference
from app.services.events import EventManager
from app.services.facts import FactPromotionCandidate, FactValidator, GoldenPathFactType
from app.services.state import EventStateManager, TransitionContext
from app.synthetic.detection import run_synthetic_rules
from app.synthetic.scenario import SCENARIO_ID, replay_golden_path
from app.tools.registry import AgentType, ToolRegistry
from app.verification.engine import VerificationEngine


class GoldenPathState(TypedDict, total=False):
    run_id: str
    thread_id: str
    incident_id: str
    current_node: str
    latest_task_id: str
    latest_result_id: str
    action_request_id: str
    approval_id: str
    execution_id: str
    verification_id: str
    preauthorization_id: str
    run_mode: str
    retry_counters: dict[str, int]
    stop_reason: str


class GoldenPathWorkflow:
    def __init__(
        self,
        session: Session,
        registry: ToolRegistry,
        model: ModelAdapter,
        checkpoint_path: Path,
        *,
        autonomous_enabled: bool = False,
        knowledge: KnowledgeService | None = None,
    ) -> None:
        self._session = session
        self._registry = registry
        self._model = model
        self._autonomous_enabled = autonomous_enabled
        self._knowledge = knowledge
        self._connection = sqlite3.connect(checkpoint_path, check_same_thread=False)
        self._checkpointer = SqliteSaver(self._connection)
        self._node_timings_ms: dict[str, list[float]] = {}
        self.graph = self._build().compile(checkpointer=self._checkpointer)

    @property
    def node_timings_ms(self) -> dict[str, list[float]]:
        return {name: list(values) for name, values in self._node_timings_ms.items()}

    def close(self) -> None:
        self._connection.close()

    def invoke(self, state: GoldenPathState, *, thread_id: str):  # type: ignore[no-untyped-def]
        return self.graph.invoke(state, config={"configurable": {"thread_id": thread_id}})

    def resume(self, approval: dict[str, str], *, thread_id: str):  # type: ignore[no-untyped-def]
        return self.graph.invoke(
            Command(resume=approval),
            config={"configurable": {"thread_id": thread_id}},
        )

    def _build(self) -> StateGraph[GoldenPathState]:
        builder = StateGraph(GoldenPathState)
        nodes = {
            "ingest_event": self._ingest_event,
            "detect_signal": self._detect_signal,
            "create_incident": self._create_incident,
            "plan_investigation": self._plan_investigation,
            "run_investigation": self._run_investigation,
            "run_trace": self._run_trace,
            "evaluate_facts": self._evaluate_facts,
            "build_action_plan": self._build_action_plan,
            "build_action_request": self._build_action_request,
            "policy_check": self._policy_check,
            "wait_for_approval": self._wait_for_approval,
            "autonomous_preauthorization": self._autonomous_preauthorization,
            "execute_action": self._execute_action,
            "verify_result": self._verify_result,
            "generate_audit": self._generate_audit,
            "close_incident": self._close_incident,
            "manual_or_stop": self._manual_or_stop,
            "replan_or_manual": self._replan_or_manual,
        }
        for name, node in nodes.items():
            # LangGraph's overloads do not accept an otherwise valid TypedDict wrapper.
            builder.add_node(name, self._timed_node(name, node))  # type: ignore[call-overload]
        builder.add_edge(START, "ingest_event")
        sequence = [
            "ingest_event",
            "detect_signal",
            "create_incident",
            "plan_investigation",
        ]
        for left, right in pairwise(sequence):
            builder.add_edge(left, right)
        builder.add_conditional_edges(
            "plan_investigation",
            lambda state: "stop" if state.get("stop_reason") else "investigate",
            {"stop": "manual_or_stop", "investigate": "run_investigation"},
        )
        builder.add_conditional_edges(
            "run_investigation",
            lambda state: "stop" if state.get("stop_reason") else "trace",
            {"stop": "manual_or_stop", "trace": "run_trace"},
        )
        after_investigation = [
            "run_trace",
            "evaluate_facts",
            "build_action_plan",
            "build_action_request",
            "policy_check",
        ]
        for left, right in pairwise(after_investigation):
            builder.add_edge(left, right)
        builder.add_conditional_edges(
            "policy_check",
            self._authorization_route,
            {
                "stop": "manual_or_stop",
                "guarded": "wait_for_approval",
                "autonomous": "autonomous_preauthorization",
            },
        )
        builder.add_conditional_edges(
            "wait_for_approval",
            lambda state: "stop" if state.get("stop_reason") else "execute",
            {"stop": "manual_or_stop", "execute": "execute_action"},
        )
        builder.add_conditional_edges(
            "autonomous_preauthorization",
            lambda state: "stop" if state.get("stop_reason") else "execute",
            {"stop": "manual_or_stop", "execute": "execute_action"},
        )
        builder.add_edge("execute_action", "verify_result")
        builder.add_conditional_edges(
            "verify_result",
            lambda state: "replan" if state.get("stop_reason") else "audit",
            {"replan": "replan_or_manual", "audit": "generate_audit"},
        )
        builder.add_edge("generate_audit", "close_incident")
        builder.add_edge("close_incident", END)
        builder.add_edge("manual_or_stop", END)
        builder.add_edge("replan_or_manual", END)
        return builder

    def _timed_node(
        self,
        name: str,
        node: Callable[[GoldenPathState], GoldenPathState],
    ) -> Callable[[GoldenPathState], GoldenPathState]:
        def measured(state: GoldenPathState) -> GoldenPathState:
            started = perf_counter()
            try:
                return node(state)
            finally:
                elapsed = round((perf_counter() - started) * 1000, 3)
                self._node_timings_ms.setdefault(name, []).append(elapsed)

        return measured

    def _ingest_event(self, state: GoldenPathState) -> GoldenPathState:
        replay = replay_golden_path()
        MockStateService(self._session).reset(SCENARIO_ID)
        evidence_repo = EvidenceRepository(self._session)
        for evidence in replay.evidence:
            if evidence_repo.get(evidence.evidence_id) is None:
                EvidenceService(self._session).create(evidence)
        return {"current_node": "ingest_event", "run_id": replay.run_id}

    def _detect_signal(self, state: GoldenPathState) -> GoldenPathState:
        del state
        signals = run_synthetic_rules(replay_golden_path())
        ci = next(item for item in signals if item.signal_type.value == "CI_ACTION_MUTATION")
        self._session.info["golden_path_ci_signal"] = ci
        return {"current_node": "detect_signal"}

    def _create_incident(self, state: GoldenPathState) -> GoldenPathState:
        del state
        signal = self._session.info["golden_path_ci_signal"]
        incident = EventManager(self._session).create_from_ci_signal(
            signal, tenant_ref="tenant_demo_cloud_01"
        )
        AuditService(self._session).append(
            incident_id=incident.incident_id,
            actor_type=AuditActorType.SYSTEM,
            actor_id="EVENT_MANAGER",
            event_type="SIGNAL_OBSERVED",
            object_type="SecuritySignal",
            object_id=signal.signal_id,
            summary="Evidence-backed CI Action mutation signal opened an incident",
            payload={"evidence_refs": signal.evidence_refs},
        )
        EventStateManager(self._session).transition(
            incident.incident_id,
            IncidentStatus.DETECTED,
            TransitionContext(valid_signal_count=1),
            proposed_by="SILENT_MONITOR_AGENT",
        )
        return {"current_node": "create_incident", "incident_id": incident.incident_id}

    def _plan_investigation(self, state: GoldenPathState) -> GoldenPathState:
        incident_id = state["incident_id"]
        evidence_refs = self._synthetic_evidence_ids()
        main_task = AgentTask(
            task_id=runtime_id("tsk"),
            incident_id=incident_id,
            task_type=TaskType.INVESTIGATE,
            task_goal="Plan the next bounded investigation task.",
            allowed_context=AllowedContext(),
            evidence_refs=evidence_refs,
            allowed_tools=["create_agent_task"],
            expected_output="Structured MainPlan",
            assigned_agent_type=AgentType.MAIN_AGENT.value,
            status=TaskStatus.PENDING,
            created_by=TaskCreator.SYSTEM,
        )
        AgentContractRepository(self._session).add_task(main_task)
        runtime = AgentRuntime(self._session, self._registry, self._knowledge)
        plan = runtime.plan_main(main_task, self._model)
        if plan.next_action.value == "MANUAL":
            return {
                "current_node": "plan_investigation",
                "latest_task_id": main_task.task_id,
                "stop_reason": "MODEL_UNAVAILABLE",
            }
        task = runtime.create_planned_task(main_task, plan)
        EventStateManager(self._session).transition(
            incident_id,
            IncidentStatus.INVESTIGATING,
            TransitionContext(valid_task_count=1),
            proposed_by="MAIN_AGENT",
        )
        return {"current_node": "plan_investigation", "latest_task_id": task.task_id}

    def _run_investigation(self, state: GoldenPathState) -> GoldenPathState:
        task = self._required_task(state["latest_task_id"])
        _, result = AgentRuntime(self._session, self._registry, self._knowledge).run_investigation(
            task, self._model
        )
        if result.task_status is TaskStatus.MANUAL_REQUIRED:
            return {
                "current_node": "run_investigation",
                "latest_result_id": result.result_id,
                "stop_reason": "MODEL_UNAVAILABLE",
            }
        trace_task = AgentTask(
            task_id=runtime_id("tsk"),
            incident_id=task.incident_id,
            task_type=TaskType.TRACE,
            task_goal="Build deterministic source-aware attack timeline.",
            allowed_context=AllowedContext(),
            evidence_refs=task.evidence_refs,
            allowed_tools=["get_evidence", "build_timeline"],
            expected_output="Timeline and missing-link declaration",
            assigned_agent_type=AgentType.TRACE_AGENT.value,
            status=TaskStatus.PENDING,
            created_by=TaskCreator.MAIN_AGENT,
        )
        AgentContractRepository(self._session).add_task(trace_task)
        return {
            "current_node": "run_investigation",
            "latest_task_id": trace_task.task_id,
            "latest_result_id": result.result_id,
        }

    def _run_trace(self, state: GoldenPathState) -> GoldenPathState:
        if state.get("stop_reason"):
            return {"current_node": "run_trace"}
        task = self._required_task(state["latest_task_id"])
        _, _, _, result = AgentRuntime(self._session, self._registry, self._knowledge).run_trace(
            task
        )
        return {"current_node": "run_trace", "latest_result_id": result.result_id}

    def _evaluate_facts(self, state: GoldenPathState) -> GoldenPathState:
        if state.get("stop_reason"):
            return {"current_node": "evaluate_facts"}
        incident_id = state["incident_id"]
        evidence = self._synthetic_evidence_by_type()
        validator = FactValidator(
            EvidenceRepository(self._session),
            FactRepository(self._session),
            AuditService(self._session),
        )
        order = [
            (GoldenPathFactType.CI_ACTION_MUTATED, "CI_SECURITY"),
            (GoldenPathFactType.SECRET_ACCESSED, "SECRET_ACCESS"),
            (GoldenPathFactType.CREDENTIAL_EXPOSED, "CREDENTIAL_EXPOSURE"),
            (GoldenPathFactType.CREDENTIAL_ABUSED, "CLOUD_API_AUDIT"),
            (GoldenPathFactType.SENSITIVE_DATA_ACCESSED, "RESOURCE_ACCESS"),
            (GoldenPathFactType.HIGH_COST_RESOURCE_CREATED, "RESOURCE_OPERATION"),
        ]
        for fact_type, event_type in order:
            validator.promote(
                FactPromotionCandidate(
                    incident_id=incident_id,
                    fact_type=fact_type,
                    subject_refs=["credential_ref_demo_ci"],
                    statement=f"Evidence-backed {fact_type.value}",
                    evidence_refs=[evidence[event_type].evidence_id],
                    proposed_by=state["latest_result_id"],
                )
            )
        EventStateManager(self._session).transition(
            incident_id,
            IncidentStatus.ATTRIBUTED,
            TransitionContext(fact_types=set(GoldenPathFactType)),
            proposed_by="MAIN_AGENT",
        )
        return {"current_node": "evaluate_facts"}

    def _build_action_plan(self, state: GoldenPathState) -> GoldenPathState:
        recommendation = ActionPlanningService(self._session).recommend(state["incident_id"])
        self._session.info["golden_path_recommendation"] = recommendation
        AuditService(self._session).append(
            incident_id=state["incident_id"],
            actor_type=AuditActorType.AGENT,
            actor_id="MAIN_AGENT",
            event_type="ACTION_RECOMMENDATION_CREATED",
            object_type="ActionRecommendation",
            object_id=recommendation.recommendation_id,
            summary="Main Agent proposed credential containment and rotation",
            payload={"output_refs": [recommendation.recommendation_id]},
        )
        return {"current_node": "build_action_plan"}

    def _build_action_request(self, state: GoldenPathState) -> GoldenPathState:
        recommendation = self._session.info["golden_path_recommendation"]
        task = AgentTask(
            task_id=runtime_id("tsk"),
            incident_id=state["incident_id"],
            task_type=TaskType.OPERATE,
            task_goal="Convert the recommendation into a governed action request.",
            allowed_context=AllowedContext(fact_refs=recommendation.fact_refs),
            evidence_refs=self._synthetic_evidence_ids(),
            allowed_tools=["create_action_request"],
            expected_output="Structured ActionRequest only; no execution",
            assigned_agent_type=AgentType.OPERATION_AGENT.value,
            status=TaskStatus.PENDING,
            created_by=TaskCreator.MAIN_AGENT,
        )
        AgentContractRepository(self._session).add_task(task)
        operation = OperationAgentService(self._session, self._registry)
        request = operation.create_request(
            recommendation,
            credential_ref="credential_ref_demo_ci",
            runner_ref="runner_ci_01",
            new_version_ref="credential_version_new_ref",
        )
        result = operation.result_for_request(task, request)
        return {
            "current_node": "build_action_request",
            "action_request_id": request.action_request_id,
            "latest_task_id": task.task_id,
            "latest_result_id": result.result_id,
        }

    def _policy_check(self, state: GoldenPathState) -> GoldenPathState:
        request = self._required_request(state["action_request_id"])
        run_mode = RunMode(state.get("run_mode", RunMode.PRODUCTION_GUARDED.value))
        decision = PolicyEngine(self._session).evaluate(request, run_mode=run_mode)
        if decision.decision.value == "DENY":
            return {"current_node": "policy_check", "stop_reason": "POLICY_DENIED"}
        return {"current_node": "policy_check"}

    @staticmethod
    def _authorization_route(state: GoldenPathState) -> str:
        if state.get("stop_reason"):
            return "stop"
        run_mode = RunMode(state.get("run_mode", RunMode.PRODUCTION_GUARDED.value))
        return "autonomous" if run_mode is RunMode.COMPETITION_AUTONOMOUS else "guarded"

    def _wait_for_approval(self, state: GoldenPathState) -> GoldenPathState:
        if state.get("stop_reason"):
            return {"current_node": "wait_for_approval"}
        request = self._required_request(state["action_request_id"])
        response = cast(
            dict[str, str],
            interrupt(
                {
                    "action_request_id": request.action_request_id,
                    "request_digest": action_request_digest(request),
                    "mode": "PRODUCTION_GUARDED",
                }
            ),
        )
        decision = ApprovalDecision(response["decision"])
        approval = ApprovalService(self._session).decide(
            request,
            decision=decision,
            approver_id=response.get("approver_id", "competition_approver"),
            comment=response.get("comment", "Golden Path decision"),
        )
        if decision is ApprovalDecision.REJECTED:
            return {
                "current_node": "wait_for_approval",
                "approval_id": approval.approval_id,
                "stop_reason": "HUMAN_REJECTED",
            }
        return {"current_node": "wait_for_approval", "approval_id": approval.approval_id}

    def _autonomous_preauthorization(self, state: GoldenPathState) -> GoldenPathState:
        request = self._required_request(state["action_request_id"])
        authorization = PolicyPreAuthorizationService(
            self._session,
            enabled=self._autonomous_enabled,
            production_adapter_enabled=False,
        ).evaluate(
            request,
            run_mode=RunMode(state["run_mode"]),
            scenario_id=SCENARIO_ID,
        )
        update: GoldenPathState = {
            "current_node": "autonomous_preauthorization",
            "preauthorization_id": authorization.preauthorization_id,
        }
        if authorization.decision is PreAuthorizationDecision.DENY:
            update["stop_reason"] = "AUTONOMOUS_PREAUTHORIZATION_DENIED"
        return update

    def _execute_action(self, state: GoldenPathState) -> GoldenPathState:
        execution = ControlledExecutor(self._session, SCENARIO_ID).execute(
            state["action_request_id"],
            run_mode=RunMode(state.get("run_mode", RunMode.PRODUCTION_GUARDED.value)),
        )
        return {"current_node": "execute_action", "execution_id": execution.execution_id}

    def _verify_result(self, state: GoldenPathState) -> GoldenPathState:
        force = state.get("retry_counters", {}).get("force_verification_failure", 0)
        from app.domain.enums import VerificationAssertionType

        verification = VerificationEngine(self._session, SCENARIO_ID).verify(
            state["incident_id"],
            state["execution_id"],
            force_fail=(VerificationAssertionType.LEGITIMATE_CI_RECOVERED if force else None),
        )
        update: GoldenPathState = {
            "current_node": "verify_result",
            "verification_id": verification.verification_id,
        }
        if verification.next_step.value == "REPLAN":
            update["stop_reason"] = "VERIFICATION_FAILED_REPLAN"
        return update

    def _generate_audit(self, state: GoldenPathState) -> GoldenPathState:
        evidence_refs = self._synthetic_evidence_ids()
        task = AgentTask(
            task_id=runtime_id("tsk"),
            incident_id=state["incident_id"],
            task_type=TaskType.AUDIT,
            task_goal="Build deterministic audit report input and verify integrity.",
            allowed_context=AllowedContext(),
            evidence_refs=evidence_refs,
            allowed_tools=["query_audit_records", "generate_report_input"],
            expected_output="Structured audit report",
            assigned_agent_type=AgentType.AUDIT_AGENT.value,
            status=TaskStatus.PENDING,
            created_by=TaskCreator.MAIN_AGENT,
        )
        AgentContractRepository(self._session).add_task(task)
        _, _, result = AuditAgentService(self._session, self._registry).generate(task)
        return {
            "current_node": "generate_audit",
            "latest_task_id": task.task_id,
            "latest_result_id": result.result_id,
        }

    def _close_incident(self, state: GoldenPathState) -> GoldenPathState:
        findings = AgentContractRepository(self._session).list_findings(state["incident_id"])
        audit_finding = next(
            item for item in reversed(findings) if item.finding_type == "AUDIT_REPORT"
        )
        report = AuditReport.model_validate(audit_finding.metadata["report"])
        IncidentClosureService(self._session).close(state["incident_id"], report)
        return {"current_node": "close_incident", "stop_reason": "CLOSED"}

    def _manual_or_stop(self, state: GoldenPathState) -> GoldenPathState:
        return {"current_node": "manual_or_stop", "stop_reason": state["stop_reason"]}

    def _replan_or_manual(self, state: GoldenPathState) -> GoldenPathState:
        AuditService(self._session).append(
            incident_id=state["incident_id"],
            actor_type=AuditActorType.AGENT,
            actor_id="MAIN_AGENT",
            event_type="MAIN_AGENT_REPLAN",
            object_type="VerificationResult",
            object_id=state["verification_id"],
            summary="Verification failure observed; incident remains open for replanning",
            payload={"input_object_refs": [state["verification_id"]]},
        )
        return {"current_node": "replan_or_manual", "stop_reason": state["stop_reason"]}

    def _required_task(self, task_id: str) -> AgentTask:
        task = AgentContractRepository(self._session).get_task(task_id)
        if task is None:
            raise ValueError("AgentTask not found")
        return task

    def _required_request(self, request_id: str):  # type: ignore[no-untyped-def]
        request = ActionRepository(self._session).get_request(request_id)
        if request is None:
            raise ValueError("ActionRequest not found")
        return request

    def _synthetic_evidence_ids(self) -> list[str]:
        return list(
            self._session.scalars(
                select(EvidenceORM.evidence_id)
                .where(EvidenceORM.source_type == "SYNTHETIC")
                .order_by(EvidenceORM.created_at)
            )
        )

    def _synthetic_evidence_by_type(self) -> dict[str, EvidenceReference]:
        result = {}
        for evidence_id in self._synthetic_evidence_ids():
            evidence = EvidenceRepository(self._session).get(evidence_id)
            if evidence is not None and evidence.redacted_snapshot is not None:
                result[str(evidence.redacted_snapshot["event_type"])] = evidence
        return result
