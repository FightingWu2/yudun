from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import AgentFindingORM, AgentResultORM, AgentTaskORM
from app.schemas.agent import AgentFinding, AgentResult, AgentTask


class AgentContractRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def add_task(self, task: AgentTask) -> AgentTask:
        self._session.add(
            AgentTaskORM(
                task_id=task.task_id,
                incident_id=task.incident_id,
                task_type=task.task_type.value,
                status=task.status.value,
                assigned_agent_type=task.assigned_agent_type,
                schema_version=task.schema_version,
                payload=task.model_dump(mode="json"),
                created_at=task.created_at,
            )
        )
        self._session.flush()
        return task

    def add_finding(self, finding: AgentFinding) -> AgentFinding:
        self._require_task(finding.task_id, finding.incident_id)
        self._session.add(
            AgentFindingORM(
                finding_id=finding.finding_id,
                incident_id=finding.incident_id,
                task_id=finding.task_id,
                finding_type=finding.finding_type,
                schema_version=finding.schema_version,
                payload=finding.model_dump(mode="json"),
                created_at=finding.created_at,
            )
        )
        self._session.flush()
        return finding

    def add_result(self, result: AgentResult) -> AgentResult:
        self._require_task(result.task_id, result.incident_id)
        known_findings = set(
            self._session.scalars(
                select(AgentFindingORM.finding_id).where(
                    AgentFindingORM.incident_id == result.incident_id
                )
            )
        )
        if not set(result.findings) <= known_findings:
            raise ValueError("AgentResult references findings that are not persisted")
        self._session.add(
            AgentResultORM(
                result_id=result.result_id,
                incident_id=result.incident_id,
                task_id=result.task_id,
                task_status=result.task_status.value,
                schema_version=result.schema_version,
                payload=result.model_dump(mode="json"),
                created_at=result.created_at,
            )
        )
        self._session.flush()
        return result

    def get_task(self, task_id: str) -> AgentTask | None:
        row = self._session.get(AgentTaskORM, task_id)
        return None if row is None else AgentTask.model_validate(row.payload)

    def update_task(self, task: AgentTask) -> AgentTask:
        row = self._session.get(AgentTaskORM, task.task_id)
        if row is None:
            raise ValueError("task does not exist")
        row.status = task.status.value
        row.payload = task.model_dump(mode="json")
        self._session.flush()
        return task

    def list_tasks(self, incident_id: str) -> list[AgentTask]:
        rows = self._session.scalars(
            select(AgentTaskORM)
            .where(AgentTaskORM.incident_id == incident_id)
            .order_by(AgentTaskORM.created_at)
        )
        return [AgentTask.model_validate(row.payload) for row in rows]

    def list_results(self, incident_id: str) -> list[AgentResult]:
        rows = self._session.scalars(
            select(AgentResultORM)
            .where(AgentResultORM.incident_id == incident_id)
            .order_by(AgentResultORM.created_at)
        )
        return [AgentResult.model_validate(row.payload) for row in rows]

    def list_findings(self, incident_id: str) -> list[AgentFinding]:
        rows = self._session.scalars(
            select(AgentFindingORM)
            .where(AgentFindingORM.incident_id == incident_id)
            .order_by(AgentFindingORM.created_at)
        )
        return [AgentFinding.model_validate(row.payload) for row in rows]

    def _require_task(self, task_id: str, incident_id: str) -> None:
        task = self._session.get(AgentTaskORM, task_id)
        if task is None or task.incident_id != incident_id:
            raise ValueError("task does not exist in the incident")
