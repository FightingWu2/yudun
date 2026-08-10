import hashlib

from sqlalchemy.orm import Session

from app.core.canonical import canonical_json
from app.core.errors import ConflictError
from app.core.ids import runtime_id
from app.core.time import utc_now
from app.db.models import MockScenarioStateORM, StateSnapshotORM
from app.domain.enums import EvidenceSensitivity, SourceType
from app.evidence.service import EvidenceService
from app.schemas.evidence import EvidenceReference, EvidenceType, MockEvidenceLocator
from app.schemas.mock_state import (
    AttackState,
    AttemptResult,
    BuildStatus,
    CIState,
    CreationResult,
    CredentialState,
    MockScenarioState,
    NewVersionStatus,
    OldVersionStatus,
    ResourceState,
    StateSnapshot,
)


class MockStateService:
    def __init__(self, session: Session) -> None:
        self._session = session

    def reset(self, scenario_id: str) -> MockScenarioState:
        now = utc_now()
        state = MockScenarioState(
            scenario_id=scenario_id,
            credential=CredentialState(
                credential_ref="credential_ref_demo_ci",
                old_version_status=OldVersionStatus.ACTIVE,
                new_version_status=NewVersionStatus.NOT_CREATED,
                active_version_ref="credential_version_old_ref",
                updated_at=now,
            ),
            attack=AttackState(
                malicious_source_ref="source_external_203_0_113_50",
                old_key_attempt_enabled=True,
                last_attempt_result=AttemptResult.ALLOWED,
                last_attempt_at=now,
            ),
            ci=CIState(
                runner_ref="runner_ci_01",
                bound_credential_version_ref="credential_version_old_ref",
                last_build_status=BuildStatus.SUCCESS,
                updated_at=now,
            ),
            resource=ResourceState(
                high_cost_creation_enabled=True,
                abnormal_resource_count=1,
                last_creation_result=CreationResult.CREATED,
                updated_at=now,
            ),
            version=1,
        )
        row = self._session.get(MockScenarioStateORM, scenario_id)
        if row is None:
            self._session.add(
                MockScenarioStateORM(
                    scenario_id=scenario_id,
                    version=state.version,
                    schema_version=state.schema_version,
                    payload=state.model_dump(mode="json"),
                    created_at=now,
                )
            )
        else:
            row.version = state.version
            row.payload = state.model_dump(mode="json")
            row.created_at = now
        self._session.flush()
        return state

    def get(self, scenario_id: str) -> MockScenarioState:
        row = self._session.get(MockScenarioStateORM, scenario_id)
        if row is None:
            raise ValueError("mock scenario is not initialized")
        return MockScenarioState.model_validate(row.payload)

    def save(self, state: MockScenarioState, *, expected_version: int) -> MockScenarioState:
        row = self._session.get(MockScenarioStateORM, state.scenario_id)
        if row is None or row.version != expected_version:
            raise ConflictError("mock state version conflict")
        updated = state.model_copy(update={"version": expected_version + 1})
        updated = MockScenarioState.model_validate(updated.model_dump(mode="python"))
        row.version = updated.version
        row.payload = updated.model_dump(mode="json")
        self._session.flush()
        return updated

    def snapshot(
        self,
        state: MockScenarioState,
        *,
        incident_id: str,
        operation_id: str,
        phase: str,
    ) -> tuple[StateSnapshot, EvidenceReference]:
        snapshot = StateSnapshot(
            snapshot_id=runtime_id("snp"),
            scenario_id=state.scenario_id,
            operation_id=operation_id,
            phase=phase,
            state=state,
            captured_at=utc_now(),
        )
        self._session.add(
            StateSnapshotORM(
                snapshot_id=snapshot.snapshot_id,
                scenario_id=snapshot.scenario_id,
                operation_id=snapshot.operation_id,
                phase=snapshot.phase,
                schema_version=snapshot.schema_version,
                payload=snapshot.model_dump(mode="json"),
                created_at=snapshot.captured_at,
            )
        )
        content_hash = hashlib.sha256(canonical_json(snapshot.state).encode()).hexdigest()
        evidence = EvidenceReference(
            evidence_id=runtime_id("evd"),
            incident_id=incident_id,
            source_type=SourceType.MOCK,
            source_dataset=state.scenario_id,
            source_record_id=snapshot.snapshot_id,
            evidence_type=EvidenceType.MOCK_STATE,
            locator=MockEvidenceLocator(
                state_snapshot_id=snapshot.snapshot_id,
                operation_id=operation_id,
            ),
            content_sha256=content_hash,
            summary=f"Mock state {phase.lower()} operation {operation_id}",
            redacted_snapshot=snapshot.state.model_dump(mode="json"),
            sensitivity=EvidenceSensitivity.INTERNAL,
            allowed_agent_types=[
                "INVESTIGATION_AGENT",
                "OPERATION_AGENT",
                "AUDIT_AGENT",
            ],
            created_by="MOCK_STATE_SERVICE",
        )
        EvidenceService(self._session).create(evidence)
        self._session.flush()
        return snapshot, evidence
