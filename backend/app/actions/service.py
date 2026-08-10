import hashlib

from app.audit.service import AuditService
from app.core.canonical import canonical_json
from app.core.errors import DomainError, ErrorCode
from app.core.ids import runtime_id
from app.core.redaction import contains_plaintext_secret
from app.core.time import utc_now
from app.domain.enums import (
    ApprovalDecision,
    ConfidenceLevel,
    ExecutionStatus,
    IncidentStatus,
    PolicyOutcome,
    PreAuthorizationDecision,
    ResourceEnvironment,
    RunMode,
    SourceType,
    TaskStatus,
)
from app.mock.state import MockStateService
from app.repositories.actions import ActionRepository
from app.repositories.agents import AgentContractRepository
from app.repositories.evidence import EvidenceRepository
from app.repositories.facts import FactRepository
from app.schemas.action import (
    ActionOperation,
    ActionParameters,
    ActionRecommendation,
    ActionRequest,
    ActionRequestStatus,
    ActionType,
    ApprovalRecord,
    ExecutionResult,
    OperationResult,
    OperationType,
    PolicyCheck,
    PolicyPreAuthorization,
    RecommendationType,
)
from app.schemas.agent import AgentResult, AgentTask
from app.schemas.audit import AuditActorType
from app.schemas.mock_state import (
    AttemptResult,
    BuildStatus,
    CreationResult,
    NewVersionStatus,
    OldVersionStatus,
)
from app.services.facts import GoldenPathFactType
from app.services.state import EventStateManager, TransitionContext
from app.tools.registry import AgentType, ToolRegistry
from sqlalchemy.orm import Session


def action_request_digest(request: ActionRequest) -> str:
    return hashlib.sha256(canonical_json(request).encode()).hexdigest()


class ActionPlanningService:
    def __init__(self, session: Session) -> None:
        self._actions = ActionRepository(session)
        self._facts = FactRepository(session)

    def recommend(self, incident_id: str) -> ActionRecommendation:
        facts = self._facts.list_for_incident(incident_id)
        if {item.fact_type for item in facts} != {item.value for item in GoldenPathFactType}:
            raise DomainError(ErrorCode.EVIDENCE_REQUIRED, "all Golden Path facts are required")
        recommendation = ActionRecommendation(
            recommendation_id=runtime_id("rec"),
            incident_id=incident_id,
            recommendation_type=RecommendationType.CONTAIN_AND_ROTATE_CREDENTIAL,
            rationale=(
                "Contain the abused credential, create a new version, and restore CI binding."
            ),
            fact_refs=[item.fact_id for item in facts],
            expected_effect=(
                "Old credential calls fail and legitimate CI resumes on the new version."
            ),
            business_risks=["Temporary CI interruption during credential binding update."],
        )
        return self._actions.add_recommendation(recommendation)


class OperationAgentService:
    def __init__(self, session: Session, registry: ToolRegistry) -> None:
        self._session = session
        self._actions = ActionRepository(session)
        self._registry = registry
        self._audit = AuditService(session)

    def create_request(
        self,
        recommendation: ActionRecommendation,
        *,
        credential_ref: str,
        runner_ref: str,
        new_version_ref: str,
    ) -> ActionRequest:
        self._registry.authorize(
            incident_id=recommendation.incident_id,
            agent_type=AgentType.OPERATION_AGENT,
            tool_id="create_action_request",
            declared_tools={"create_action_request"},
            granted_permissions={"action:propose"},
        )
        request = ActionRequest(
            action_request_id=runtime_id("arq"),
            incident_id=recommendation.incident_id,
            recommendation_id=recommendation.recommendation_id,
            action_type=ActionType.CREDENTIAL_CONTAINMENT_PLAN,
            target_ref=credential_ref,
            operations=[
                ActionOperation(
                    operation_type=OperationType.FREEZE_OLD_KEY,
                    operation_id="op_freeze_old_key",
                    parameters=ActionParameters(credential_ref=credential_ref),
                ),
                ActionOperation(
                    operation_type=OperationType.CREATE_NEW_KEY_VERSION,
                    operation_id="op_create_new_version",
                    parameters=ActionParameters(
                        credential_ref=credential_ref,
                        new_version_ref=new_version_ref,
                    ),
                ),
                ActionOperation(
                    operation_type=OperationType.UPDATE_CI_BINDING,
                    operation_id="op_update_ci_binding",
                    parameters=ActionParameters(
                        credential_ref=credential_ref,
                        runner_ref=runner_ref,
                        new_version_ref=new_version_ref,
                    ),
                ),
            ],
            reason="Execute the confirmed credential containment and rotation recommendation.",
            fact_refs=recommendation.fact_refs,
            idempotency_key=f"containment:{recommendation.incident_id}:{credential_ref}:v1",
            status=ActionRequestStatus.POLICY_PENDING,
        )
        self._actions.add_request(request)
        self._audit.append(
            incident_id=request.incident_id,
            actor_type=AuditActorType.AGENT,
            actor_id="OPERATION_AGENT",
            event_type="ACTION_REQUEST_CREATED",
            object_type="ActionRequest",
            object_id=request.action_request_id,
            summary="Operation Agent proposed a governed action request",
            payload={"recommendation_id": request.recommendation_id},
        )
        return request

    def result_for_request(self, task: AgentTask, request: ActionRequest) -> AgentResult:
        if task.assigned_agent_type != AgentType.OPERATION_AGENT.value:
            raise DomainError(
                ErrorCode.PERMISSION_DENIED, "task is not assigned to Operation Agent"
            )
        result = AgentResult(
            result_id=runtime_id("res"),
            task_id=task.task_id,
            incident_id=task.incident_id,
            task_status=TaskStatus.COMPLETED,
            findings=[],
            evidence_refs=task.evidence_refs,
            confidence_level=ConfidenceLevel.HIGH,
            confidence_basis=(
                "ActionRequest was created from a frozen template and confirmed facts."
            ),
            unresolved_questions=["Human approval is required before controlled execution."],
            next_step="POLICY_CHECK",
            approval_required=True,
            metadata={"action_request_id": request.action_request_id},
        )
        AgentContractRepository(self._session).add_result(result)
        return result


class ApprovalService:
    def __init__(self, session: Session) -> None:
        self._actions = ActionRepository(session)
        self._audit = AuditService(session)

    def decide(
        self,
        request: ActionRequest,
        *,
        decision: ApprovalDecision,
        approver_id: str,
        comment: str,
    ) -> ApprovalRecord:
        policy = self._actions.get_policy_for_request(request.action_request_id)
        if policy is None or policy.decision is not PolicyOutcome.ALLOW_WITH_APPROVAL:
            raise DomainError(ErrorCode.PERMISSION_DENIED, "request is not eligible for approval")
        approval = ApprovalRecord(
            approval_id=runtime_id("apr"),
            action_request_id=request.action_request_id,
            decision=decision,
            approver_id=approver_id,
            comment=comment,
            request_digest=action_request_digest(request),
            decided_at=utc_now(),
        )
        self._actions.add_approval(approval)
        self._audit.append(
            incident_id=request.incident_id,
            actor_type=AuditActorType.HUMAN,
            actor_id=approver_id,
            event_type="ACTION_APPROVAL_DECIDED",
            object_type="ApprovalRecord",
            object_id=approval.approval_id,
            summary=f"Human approval decision: {decision.value}",
            payload={
                "action_request_id": request.action_request_id,
                "request_digest": approval.request_digest,
            },
        )
        return approval


AUTONOMOUS_POLICY_VERSION = "autonomous-sandbox-1.0"
AUTONOMOUS_SCENARIO_ALLOWLIST = frozenset({"scenario_api_key_compromise_v1"})
AUTONOMOUS_OPERATIONS = [
    OperationType.FREEZE_OLD_KEY,
    OperationType.CREATE_NEW_KEY_VERSION,
    OperationType.UPDATE_CI_BINDING,
]


class PolicyPreAuthorizationService:
    """Deterministic Sandbox-only authorization; never creates a human approval."""

    def __init__(
        self,
        session: Session,
        *,
        enabled: bool,
        production_adapter_enabled: bool = False,
    ) -> None:
        self._actions = ActionRepository(session)
        self._facts = FactRepository(session)
        self._evidence = EvidenceRepository(session)
        self._mock = MockStateService(session)
        self._audit = AuditService(session)
        self._enabled = enabled
        self._production_adapter_enabled = production_adapter_enabled

    def evaluate(
        self,
        request: ActionRequest,
        *,
        run_mode: RunMode,
        scenario_id: str,
    ) -> PolicyPreAuthorization:
        facts = self._facts.list_for_incident(request.incident_id)
        fact_ids = {item.fact_id for item in facts}
        subjects = {subject for item in facts for subject in item.subject_refs}
        fact_types = {item.fact_type for item in facts}
        source_types = {
            evidence.source_type
            for fact in facts
            for evidence_id in fact.evidence_refs
            if (evidence := self._evidence.get(evidence_id)) is not None
        }
        try:
            state = self._mock.get(scenario_id)
        except ValueError:
            state = None
        policy = self._actions.get_policy_for_request(request.action_request_id)
        checks = [
            PolicyCheck(
                check_id="RUN_MODE",
                passed=run_mode is RunMode.COMPETITION_AUTONOMOUS,
                reason="RunMode must be COMPETITION_AUTONOMOUS.",
            ),
            PolicyCheck(
                check_id="EXPLICIT_CONFIG",
                passed=self._enabled,
                reason="Competition autonomous execution must be explicitly enabled.",
            ),
            PolicyCheck(
                check_id="SANDBOX_ENVIRONMENT",
                passed=state is not None
                and state.resource_environment is ResourceEnvironment.SANDBOX,
                reason="Only the local SANDBOX state service is eligible.",
            ),
            PolicyCheck(
                check_id="SCENARIO_ALLOWLIST",
                passed=scenario_id in AUTONOMOUS_SCENARIO_ALLOWLIST,
                reason="Scenario must be in the frozen competition allowlist.",
            ),
            PolicyCheck(
                check_id="ACTION_ALLOWLIST",
                passed=request.action_type is ActionType.CREDENTIAL_CONTAINMENT_PLAN,
                reason="Only the credential containment plan is autonomous-eligible.",
            ),
            PolicyCheck(
                check_id="OPERATION_ALLOWLIST",
                passed=[item.operation_type for item in request.operations]
                == AUTONOMOUS_OPERATIONS,
                reason="Only the frozen three-step operation sequence is allowed.",
            ),
            PolicyCheck(
                check_id="TARGET_SCOPE",
                passed=request.target_ref in subjects,
                reason="Target must belong to current incident facts.",
            ),
            PolicyCheck(
                check_id="FACTS_COMPLETE",
                passed=fact_types == {item.value for item in GoldenPathFactType}
                and set(request.fact_refs) <= fact_ids,
                reason="All six evidence-validated facts are required.",
            ),
            PolicyCheck(
                check_id="SOURCE_SCOPE",
                passed=bool(source_types)
                and source_types <= {SourceType.SYNTHETIC, SourceType.MOCK},
                reason="Autonomous facts may use only SYNTHETIC or MOCK evidence.",
            ),
            PolicyCheck(
                check_id="NO_PLAINTEXT_SECRET",
                passed=not contains_plaintext_secret(request.model_dump(mode="json")),
                reason="Request must contain references, never plaintext credentials.",
            ),
            PolicyCheck(
                check_id="NO_PRODUCTION_ADAPTER",
                passed=not self._production_adapter_enabled,
                reason="No production write adapter may be active.",
            ),
            PolicyCheck(
                check_id="NO_ARBITRARY_COMMAND",
                passed=all(
                    item.operation_type in AUTONOMOUS_OPERATIONS for item in request.operations
                ),
                reason="Shell, subprocess and arbitrary commands are not represented.",
            ),
            PolicyCheck(
                check_id="POLICY_ELIGIBLE",
                passed=policy is not None
                and policy.decision is PolicyOutcome.ALLOW_WITH_PREAUTHORIZATION,
                reason="Primary deterministic policy must require preauthorization.",
            ),
        ]
        decision = (
            PreAuthorizationDecision.AUTO_PREAUTHORIZED
            if all(item.passed for item in checks)
            else PreAuthorizationDecision.DENY
        )
        item = PolicyPreAuthorization(
            preauthorization_id=runtime_id("paz"),
            incident_id=request.incident_id,
            action_request_id=request.action_request_id,
            run_mode=RunMode.COMPETITION_AUTONOMOUS,
            scenario_id=scenario_id,
            environment=ResourceEnvironment.SANDBOX,
            policy_version=AUTONOMOUS_POLICY_VERSION,
            allowed_operations=AUTONOMOUS_OPERATIONS,
            request_digest=action_request_digest(request),
            guard_checks=checks,
            decision=decision,
        )
        self._actions.add_preauthorization(item)
        self._audit.append(
            incident_id=request.incident_id,
            actor_type=AuditActorType.SYSTEM,
            actor_id="SYSTEM_POLICY",
            event_type="POLICY_PREAUTHORIZATION_DECIDED",
            object_type="PolicyPreAuthorization",
            object_id=item.preauthorization_id,
            summary=f"Autonomous Sandbox preauthorization {decision.value}",
            payload={
                "action_request_id": request.action_request_id,
                "request_digest": item.request_digest,
                "checks": [check.model_dump(mode="json") for check in checks],
            },
        )
        return item


class ControlledExecutor:
    def __init__(self, session: Session, scenario_id: str) -> None:
        self._session = session
        self._scenario_id = scenario_id
        self._actions = ActionRepository(session)
        self._mock = MockStateService(session)
        self._audit = AuditService(session)

    def execute(
        self,
        request_id: str,
        *,
        run_mode: RunMode = RunMode.PRODUCTION_GUARDED,
    ) -> ExecutionResult:
        request = self._actions.get_request(request_id)
        if request is None:
            raise DomainError(ErrorCode.NOT_FOUND, "ActionRequest does not exist")
        existing = self._actions.get_execution_by_idempotency(request.idempotency_key)
        if existing is not None:
            return existing
        policy = self._actions.get_policy_for_request(request_id)
        if run_mode is RunMode.PRODUCTION_GUARDED:
            approval = self._actions.latest_approval(request_id)
            if policy is None or policy.decision is not PolicyOutcome.ALLOW_WITH_APPROVAL:
                raise DomainError(ErrorCode.PERMISSION_DENIED, "valid guarded policy is required")
            if approval is None or approval.decision is not ApprovalDecision.APPROVED:
                raise DomainError(
                    ErrorCode.PERMISSION_DENIED, "approved human decision is required"
                )
            if approval.request_digest != action_request_digest(request):
                raise DomainError(ErrorCode.CONFLICT, "approved request digest no longer matches")
        elif run_mode is RunMode.COMPETITION_AUTONOMOUS:
            preauthorization = self._actions.get_preauthorization_for_request(request_id)
            if (
                policy is None
                or policy.decision is not PolicyOutcome.ALLOW_WITH_PREAUTHORIZATION
                or preauthorization is None
                or preauthorization.decision is not PreAuthorizationDecision.AUTO_PREAUTHORIZED
            ):
                raise DomainError(
                    ErrorCode.PERMISSION_DENIED,
                    "valid autonomous Sandbox preauthorization is required",
                )
            if preauthorization.request_digest != action_request_digest(request):
                raise DomainError(
                    ErrorCode.CONFLICT, "preauthorized request digest no longer matches"
                )
        else:
            raise DomainError(ErrorCode.PERMISSION_DENIED, "unsupported execution run mode")
        state = self._mock.get(self._scenario_id)
        if (
            run_mode is RunMode.COMPETITION_AUTONOMOUS
            and state.resource_environment is not ResourceEnvironment.SANDBOX
        ):
            raise DomainError(ErrorCode.PERMISSION_DENIED, "autonomous execution is Sandbox only")
        if request.target_ref != state.credential.credential_ref:
            raise DomainError(
                ErrorCode.PERMISSION_DENIED, "request target does not match Mock state"
            )
        started = utc_now()
        results = []
        for operation in request.operations:
            before, _ = self._mock.snapshot(
                state,
                incident_id=request.incident_id,
                operation_id=operation.operation_id,
                phase="BEFORE",
            )
            previous_version = state.version
            state = self._apply(operation, state)
            state = self._mock.save(state, expected_version=previous_version)
            after, evidence = self._mock.snapshot(
                state,
                incident_id=request.incident_id,
                operation_id=operation.operation_id,
                phase="AFTER",
            )
            results.append(
                OperationResult(
                    operation_id=operation.operation_id,
                    status=ExecutionStatus.SUCCEEDED,
                    state_snapshot_before=before.snapshot_id,
                    state_snapshot_after=after.snapshot_id,
                    receipt_ref=evidence.evidence_id,
                )
            )
            if operation.operation_type is OperationType.FREEZE_OLD_KEY:
                EventStateManager(self._session).transition(
                    request.incident_id,
                    IncidentStatus.CONTAINED,
                    TransitionContext(containment_verified=True),
                    proposed_by="OPERATION_AGENT",
                )
            if operation.operation_type is OperationType.UPDATE_CI_BINDING:
                EventStateManager(self._session).transition(
                    request.incident_id,
                    IncidentStatus.ROTATED,
                    TransitionContext(rotation_verified=True),
                    proposed_by="OPERATION_AGENT",
                )
        execution = ExecutionResult(
            execution_id=runtime_id("exe"),
            action_request_id=request.action_request_id,
            operation_results=results,
            overall_status=ExecutionStatus.SUCCEEDED,
            idempotency_key=request.idempotency_key,
            started_at=started,
            completed_at=utc_now(),
        )
        self._actions.add_execution(execution)
        self._audit.append(
            incident_id=request.incident_id,
            actor_type=AuditActorType.SYSTEM,
            actor_id="SYSTEM_EXECUTOR",
            event_type="CONTROLLED_EXECUTION_COMPLETED",
            object_type="ExecutionResult",
            object_id=execution.execution_id,
            summary="Three-step Mock credential plan completed",
            payload={"operation_count": len(results), "status": execution.overall_status.value},
        )
        return execution

    @staticmethod
    def _apply(operation: ActionOperation, state):  # type: ignore[no-untyped-def]
        now = utc_now()
        if operation.operation_type is OperationType.FREEZE_OLD_KEY:
            if state.credential.old_version_status not in {
                OldVersionStatus.ACTIVE,
                OldVersionStatus.FROZEN,
            }:
                raise DomainError(ErrorCode.CONFLICT, "old credential cannot be frozen")
            return state.model_copy(
                update={
                    "credential": state.credential.model_copy(
                        update={"old_version_status": OldVersionStatus.FROZEN, "updated_at": now}
                    ),
                    "attack": state.attack.model_copy(
                        update={
                            "old_key_attempt_enabled": False,
                            "last_attempt_result": AttemptResult.DENIED,
                            "last_attempt_at": now,
                        }
                    ),
                    "resource": state.resource.model_copy(
                        update={
                            "high_cost_creation_enabled": False,
                            "last_creation_result": CreationResult.DENIED,
                            "updated_at": now,
                        }
                    ),
                }
            )
        if operation.operation_type is OperationType.CREATE_NEW_KEY_VERSION:
            if state.credential.old_version_status is not OldVersionStatus.FROZEN:
                raise DomainError(ErrorCode.CONFLICT, "old credential must be frozen first")
            return state.model_copy(
                update={
                    "credential": state.credential.model_copy(
                        update={
                            "new_version_status": NewVersionStatus.ACTIVE,
                            "updated_at": now,
                        }
                    )
                }
            )
        if state.credential.new_version_status is not NewVersionStatus.ACTIVE:
            raise DomainError(ErrorCode.CONFLICT, "new credential version must be active")
        return state.model_copy(
            update={
                "credential": state.credential.model_copy(
                    update={
                        "active_version_ref": operation.parameters.new_version_ref,
                        "updated_at": now,
                    }
                ),
                "ci": state.ci.model_copy(
                    update={
                        "bound_credential_version_ref": operation.parameters.new_version_ref,
                        "last_build_status": BuildStatus.SUCCESS,
                        "updated_at": now,
                    }
                ),
            }
        )
