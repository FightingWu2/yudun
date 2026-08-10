from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import (
    ActionRecommendationORM,
    ActionRequestORM,
    ApprovalRecordORM,
    ExecutionResultORM,
    PolicyDecisionORM,
    PolicyPreAuthorizationORM,
    VerificationResultORM,
)
from app.schemas.action import (
    ActionRecommendation,
    ActionRequest,
    ApprovalRecord,
    ExecutionResult,
    PolicyDecision,
    PolicyPreAuthorization,
    VerificationResult,
)


class ActionRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def add_recommendation(self, item: ActionRecommendation) -> ActionRecommendation:
        self._session.add(
            ActionRecommendationORM(
                recommendation_id=item.recommendation_id,
                incident_id=item.incident_id,
                recommendation_type=item.recommendation_type.value,
                schema_version=item.schema_version,
                payload=item.model_dump(mode="json"),
                created_at=item.created_at,
            )
        )
        self._session.flush()
        return item

    def get_recommendation(self, item_id: str) -> ActionRecommendation | None:
        row = self._session.get(ActionRecommendationORM, item_id)
        return None if row is None else ActionRecommendation.model_validate(row.payload)

    def add_request(self, item: ActionRequest) -> ActionRequest:
        self._session.add(
            ActionRequestORM(
                action_request_id=item.action_request_id,
                incident_id=item.incident_id,
                recommendation_id=item.recommendation_id,
                action_type=item.action_type.value,
                status=item.status.value,
                idempotency_key=item.idempotency_key,
                schema_version=item.schema_version,
                payload=item.model_dump(mode="json"),
                created_at=item.created_at,
            )
        )
        self._session.flush()
        return item

    def get_request(self, item_id: str) -> ActionRequest | None:
        row = self._session.get(ActionRequestORM, item_id)
        return None if row is None else ActionRequest.model_validate(row.payload)

    def add_policy(self, item: PolicyDecision) -> PolicyDecision:
        self._session.add(
            PolicyDecisionORM(
                policy_decision_id=item.policy_decision_id,
                action_request_id=item.action_request_id,
                decision=item.decision.value,
                schema_version=item.schema_version,
                payload=item.model_dump(mode="json"),
                created_at=item.created_at,
            )
        )
        self._session.flush()
        return item

    def get_policy_for_request(self, request_id: str) -> PolicyDecision | None:
        row = self._session.scalar(
            select(PolicyDecisionORM).where(PolicyDecisionORM.action_request_id == request_id)
        )
        return None if row is None else PolicyDecision.model_validate(row.payload)

    def add_approval(self, item: ApprovalRecord) -> ApprovalRecord:
        self._session.add(
            ApprovalRecordORM(
                approval_id=item.approval_id,
                action_request_id=item.action_request_id,
                decision=item.decision.value,
                request_digest=item.request_digest,
                schema_version=item.schema_version,
                payload=item.model_dump(mode="json"),
                created_at=item.decided_at,
            )
        )
        self._session.flush()
        return item

    def latest_approval(self, request_id: str) -> ApprovalRecord | None:
        row = self._session.scalar(
            select(ApprovalRecordORM)
            .where(ApprovalRecordORM.action_request_id == request_id)
            .order_by(ApprovalRecordORM.created_at.desc())
        )
        return None if row is None else ApprovalRecord.model_validate(row.payload)

    def add_preauthorization(self, item: PolicyPreAuthorization) -> PolicyPreAuthorization:
        self._session.add(
            PolicyPreAuthorizationORM(
                preauthorization_id=item.preauthorization_id,
                incident_id=item.incident_id,
                action_request_id=item.action_request_id,
                decision=item.decision.value,
                run_mode=item.run_mode.value,
                request_digest=item.request_digest,
                schema_version=item.schema_version,
                payload=item.model_dump(mode="json"),
                created_at=item.created_at,
            )
        )
        self._session.flush()
        return item

    def get_preauthorization_for_request(self, request_id: str) -> PolicyPreAuthorization | None:
        row = self._session.scalar(
            select(PolicyPreAuthorizationORM).where(
                PolicyPreAuthorizationORM.action_request_id == request_id
            )
        )
        return None if row is None else PolicyPreAuthorization.model_validate(row.payload)

    def add_execution(self, item: ExecutionResult) -> ExecutionResult:
        self._session.add(
            ExecutionResultORM(
                execution_id=item.execution_id,
                action_request_id=item.action_request_id,
                overall_status=item.overall_status.value,
                idempotency_key=item.idempotency_key,
                schema_version=item.schema_version,
                payload=item.model_dump(mode="json"),
                created_at=item.started_at,
            )
        )
        self._session.flush()
        return item

    def get_execution_by_idempotency(self, key: str) -> ExecutionResult | None:
        row = self._session.scalar(
            select(ExecutionResultORM).where(ExecutionResultORM.idempotency_key == key)
        )
        return None if row is None else ExecutionResult.model_validate(row.payload)

    def get_execution(self, execution_id: str) -> ExecutionResult | None:
        row = self._session.get(ExecutionResultORM, execution_id)
        return None if row is None else ExecutionResult.model_validate(row.payload)

    def add_verification(self, item: VerificationResult) -> VerificationResult:
        self._session.add(
            VerificationResultORM(
                verification_id=item.verification_id,
                incident_id=item.incident_id,
                execution_id=item.execution_id,
                overall_status=item.overall_status.value,
                schema_version=item.schema_version,
                payload=item.model_dump(mode="json"),
                created_at=item.created_at,
            )
        )
        self._session.flush()
        return item

    def list_verifications(self, incident_id: str) -> list[VerificationResult]:
        rows = self._session.scalars(
            select(VerificationResultORM)
            .where(VerificationResultORM.incident_id == incident_id)
            .order_by(VerificationResultORM.created_at)
        )
        return [VerificationResult.model_validate(row.payload) for row in rows]
