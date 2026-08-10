from sqlalchemy.orm import Session

from app.audit.service import AuditService
from app.core.errors import DomainError, ErrorCode
from app.core.ids import runtime_id
from app.core.time import utc_now
from app.domain.enums import IncidentStatus, VerificationAssertionType
from app.mock.state import MockStateService
from app.repositories.actions import ActionRepository
from app.repositories.incidents import IncidentRepository
from app.schemas.action import (
    VerificationAssertion,
    VerificationNextStep,
    VerificationObservation,
    VerificationResult,
    VerificationStatus,
)
from app.schemas.audit import AuditActorType
from app.schemas.mock_state import (
    AttemptResult,
    BuildStatus,
    CreationResult,
    NewVersionStatus,
    OldVersionStatus,
)
from app.services.state import EventStateManager, TransitionContext


class VerificationEngine:
    def __init__(self, session: Session, scenario_id: str) -> None:
        self._session = session
        self._scenario_id = scenario_id
        self._actions = ActionRepository(session)
        self._audit = AuditService(session)

    def verify(
        self,
        incident_id: str,
        execution_id: str,
        *,
        force_fail: VerificationAssertionType | None = None,
    ) -> VerificationResult:
        execution = self._actions.get_execution(execution_id)
        if execution is None:
            raise DomainError(ErrorCode.NOT_FOUND, "ExecutionResult does not exist")
        state = MockStateService(self._session).get(self._scenario_id)
        _, evidence = MockStateService(self._session).snapshot(
            state,
            incident_id=incident_id,
            operation_id=f"verification_{execution_id}",
            phase="READBACK",
        )
        expected_actual = {
            VerificationAssertionType.OLD_KEY_DISABLED: (
                state.credential.old_version_status is OldVersionStatus.FROZEN,
                state.credential.old_version_status.value,
                OldVersionStatus.FROZEN.value,
            ),
            VerificationAssertionType.OLD_KEY_CALL_REJECTED: (
                state.attack.last_attempt_result is AttemptResult.DENIED,
                state.attack.last_attempt_result.value,
                AttemptResult.DENIED.value,
            ),
            VerificationAssertionType.MALICIOUS_ACTIVITY_STOPPED: (
                not state.attack.old_key_attempt_enabled,
                state.attack.old_key_attempt_enabled,
                False,
            ),
            VerificationAssertionType.NEW_KEY_ACTIVE: (
                state.credential.new_version_status is NewVersionStatus.ACTIVE,
                state.credential.new_version_status.value,
                NewVersionStatus.ACTIVE.value,
            ),
            VerificationAssertionType.LEGITIMATE_CI_RECOVERED: (
                state.ci.last_build_status is BuildStatus.SUCCESS,
                state.ci.last_build_status.value,
                BuildStatus.SUCCESS.value,
            ),
            VerificationAssertionType.HIGH_COST_RESOURCE_STOPPED: (
                not state.resource.high_cost_creation_enabled
                and state.resource.last_creation_result is CreationResult.DENIED,
                {
                    "enabled": state.resource.high_cost_creation_enabled,
                    "last_result": state.resource.last_creation_result.value,
                },
                {"enabled": False, "last_result": CreationResult.DENIED.value},
            ),
        }
        assertions = []
        for assertion_type, (passed, actual, expected) in expected_actual.items():
            if assertion_type is force_fail:
                passed = False
                actual = "FORCED_FAILURE_FIXTURE"
            assertions.append(
                VerificationAssertion(
                    assertion_type=assertion_type,
                    passed=passed,
                    observed_value=VerificationObservation(actual=actual, expected=expected),
                    evidence_refs=[evidence.evidence_id],
                    checked_at=utc_now(),
                )
            )
        failed = [item.assertion_type for item in assertions if not item.passed]
        status = VerificationStatus.PASSED if not failed else VerificationStatus.FAILED
        result = VerificationResult(
            verification_id=runtime_id("ver"),
            incident_id=incident_id,
            execution_id=execution_id,
            assertions=assertions,
            overall_status=status,
            failed_assertions=failed,
            next_step=(VerificationNextStep.CLOSE if not failed else VerificationNextStep.REPLAN),
        )
        self._actions.add_verification(result)
        self._audit.append(
            incident_id=incident_id,
            actor_type=AuditActorType.SYSTEM,
            actor_id="VERIFICATION_ENGINE",
            event_type=("VERIFICATION_COMPLETED" if not failed else "VERIFICATION_REPLAN_REQUIRED"),
            object_type="VerificationResult",
            object_id=result.verification_id,
            summary=f"Verification result {result.overall_status.value}",
            payload={
                "assertions": [
                    {
                        "assertion_type": item.assertion_type.value,
                        "passed": item.passed,
                        "evidence_refs": item.evidence_refs,
                    }
                    for item in assertions
                ],
                "next_step": result.next_step.value,
            },
        )
        incident = IncidentRepository(self._session).get(incident_id)
        if not failed and incident is not None and incident.status is IncidentStatus.ROTATED:
            EventStateManager(self._session).transition(
                incident_id,
                IncidentStatus.VERIFIED,
                TransitionContext(recovery_assertions_passed=True),
                proposed_by="MAIN_AGENT",
            )
        return result
