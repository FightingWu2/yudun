import hashlib

from sqlalchemy.orm import Session

from app.audit.service import AuditService
from app.core.canonical import canonical_json
from app.core.ids import runtime_id
from app.core.redaction import contains_plaintext_secret
from app.domain.enums import PolicyOutcome, RunMode
from app.repositories.actions import ActionRepository
from app.repositories.facts import FactRepository
from app.schemas.action import (
    ActionRequest,
    ActionType,
    ApprovalRequirement,
    OperationType,
    PolicyCheck,
    PolicyDecision,
)
from app.schemas.audit import AuditActorType
from app.services.facts import GoldenPathFactType

POLICY_VERSION = "credential-containment-1.0"


class PolicyEngine:
    def __init__(self, session: Session) -> None:
        self._session = session
        self._actions = ActionRepository(session)
        self._facts = FactRepository(session)
        self._audit = AuditService(session)

    def evaluate(
        self,
        request: ActionRequest,
        *,
        run_mode: RunMode = RunMode.PRODUCTION_GUARDED,
    ) -> PolicyDecision:
        facts = self._facts.list_for_incident(request.incident_id)
        fact_ids = {item.fact_id for item in facts}
        subjects = {subject for item in facts for subject in item.subject_refs}
        fact_types = {item.fact_type for item in facts}
        checks = [
            PolicyCheck(
                check_id="ACTION_ALLOWLIST",
                passed=request.action_type is ActionType.CREDENTIAL_CONTAINMENT_PLAN,
                reason="Only the frozen credential containment plan is allowed.",
            ),
            PolicyCheck(
                check_id="TARGET_SCOPE",
                passed=request.target_ref in subjects,
                reason="Target must be referenced by confirmed incident facts.",
            ),
            PolicyCheck(
                check_id="FACTS_COMPLETE",
                passed=fact_types == {item.value for item in GoldenPathFactType}
                and set(request.fact_refs) <= fact_ids,
                reason="All six Golden Path facts and request references are required.",
            ),
            PolicyCheck(
                check_id="OPERATION_ORDER",
                passed=[item.operation_type for item in request.operations]
                == [
                    OperationType.FREEZE_OLD_KEY,
                    OperationType.CREATE_NEW_KEY_VERSION,
                    OperationType.UPDATE_CI_BINDING,
                ],
                reason="Operations must use the frozen safe order.",
            ),
            PolicyCheck(
                check_id="REQUESTER",
                passed=request.requested_by == "OPERATION_AGENT",
                reason="Only Operation Agent may propose the request.",
            ),
            PolicyCheck(
                check_id="NO_PLAINTEXT_SECRET",
                passed=not contains_plaintext_secret(request.model_dump(mode="json")),
                reason="Action request must contain references, never plaintext credentials.",
            ),
            PolicyCheck(
                check_id="IDEMPOTENCY_KEY",
                passed=len(request.idempotency_key) >= 16,
                reason="A stable non-trivial idempotency key is required.",
            ),
            PolicyCheck(
                check_id=(
                    "HUMAN_APPROVAL"
                    if run_mode is RunMode.PRODUCTION_GUARDED
                    else "AUTONOMOUS_PREAUTHORIZATION"
                ),
                passed=True,
                reason=(
                    "PRODUCTION_GUARDED always requires human approval."
                    if run_mode is RunMode.PRODUCTION_GUARDED
                    else "COMPETITION_AUTONOMOUS requires additional Sandbox preauthorization."
                ),
            ),
        ]
        allowed = all(item.passed for item in checks)
        decision = PolicyDecision(
            policy_decision_id=runtime_id("pol"),
            action_request_id=request.action_request_id,
            decision=(
                (
                    PolicyOutcome.ALLOW_WITH_APPROVAL
                    if run_mode is RunMode.PRODUCTION_GUARDED
                    else PolicyOutcome.ALLOW_WITH_PREAUTHORIZATION
                )
                if allowed
                else PolicyOutcome.DENY
            ),
            policy_version=POLICY_VERSION,
            checks=checks,
            approval_requirement=(
                (
                    ApprovalRequirement.HUMAN_REQUIRED
                    if run_mode is RunMode.PRODUCTION_GUARDED
                    else ApprovalRequirement.POLICY_PREAUTHORIZATION_REQUIRED
                )
                if allowed
                else ApprovalRequirement.NOT_ALLOWED
            ),
        )
        self._actions.add_policy(decision)
        self._audit.append(
            incident_id=request.incident_id,
            actor_type=AuditActorType.SYSTEM,
            actor_id="POLICY_ENGINE",
            event_type="POLICY_DECIDED",
            object_type="PolicyDecision",
            object_id=decision.policy_decision_id,
            summary=f"Policy outcome {decision.decision.value}",
            payload={
                "request_id": request.action_request_id,
                "request_digest": hashlib.sha256(canonical_json(request).encode()).hexdigest(),
                "checks": [item.model_dump(mode="json") for item in checks],
            },
        )
        return decision
