from enum import StrEnum

from pydantic import Field
from sqlalchemy.orm import Session

from app.audit.service import AuditService
from app.core.errors import PermissionDeniedError
from app.domain.enums import EvidenceSensitivity
from app.schemas.audit import AuditActorType
from app.schemas.base import NonEmptyStr, StrictSchema


class AgentType(StrEnum):
    MAIN_AGENT = "MAIN_AGENT"
    SILENT_MONITOR_AGENT = "SILENT_MONITOR_AGENT"
    INVESTIGATION_AGENT = "INVESTIGATION_AGENT"
    TRACE_AGENT = "TRACE_AGENT"
    OPERATION_AGENT = "OPERATION_AGENT"
    AUDIT_AGENT = "AUDIT_AGENT"
    SYSTEM_EXECUTOR = "SYSTEM_EXECUTOR"


class ToolRisk(StrEnum):
    READ_ONLY = "READ_ONLY"
    WRITE_LOW = "WRITE_LOW"
    PROPOSAL_ONLY = "PROPOSAL_ONLY"
    CONTROLLED_EXECUTION = "CONTROLLED_EXECUTION"


class AuditPolicy(StrEnum):
    ALWAYS = "ALWAYS"
    DENIAL_AND_SUCCESS = "DENIAL_AND_SUCCESS"


class ToolDefinition(StrictSchema):
    tool_id: NonEmptyStr
    version: NonEmptyStr
    owner: NonEmptyStr
    allowed_agent_types: set[AgentType] = Field(min_length=1)
    input_schema: NonEmptyStr
    output_schema: NonEmptyStr
    required_permissions: set[NonEmptyStr] = Field(default_factory=set)
    risk_level: ToolRisk
    side_effect: bool
    timeout_seconds: int = Field(ge=1, le=300)
    audit_policy: AuditPolicy
    data_sensitivity: EvidenceSensitivity


class ToolRegistry:
    def __init__(self, session: Session, definitions: list[ToolDefinition]) -> None:
        self._definitions = {item.tool_id: item for item in definitions}
        if len(self._definitions) != len(definitions):
            raise ValueError("duplicate tool_id")
        self._audit = AuditService(session)

    def get(self, tool_id: str) -> ToolDefinition | None:
        return self._definitions.get(tool_id)

    def list_for_agent(self, agent_type: AgentType) -> list[ToolDefinition]:
        return [
            item for item in self._definitions.values() if agent_type in item.allowed_agent_types
        ]

    def authorize(
        self,
        *,
        incident_id: str | None,
        agent_type: AgentType,
        tool_id: str,
        declared_tools: set[str],
        granted_permissions: set[str],
    ) -> ToolDefinition:
        definition = self._definitions.get(tool_id)
        reason: str | None = None
        if definition is None:
            reason = "tool is not registered"
        elif tool_id not in declared_tools:
            reason = "tool was not declared in AgentTask"
        elif agent_type not in definition.allowed_agent_types:
            reason = "agent type is not allowed"
        elif not definition.required_permissions <= granted_permissions:
            reason = "required permissions are missing"
        if reason is not None:
            self._audit.append(
                incident_id=incident_id,
                actor_type=AuditActorType.AGENT,
                actor_id=agent_type.value,
                event_type="TOOL_ACCESS_DENIED",
                object_type="Tool",
                object_id=tool_id,
                summary=f"Denied tool access for {agent_type.value}",
                payload={"reason": reason},
            )
            raise PermissionDeniedError(reason)
        assert definition is not None
        if definition.audit_policy in {
            AuditPolicy.ALWAYS,
            AuditPolicy.DENIAL_AND_SUCCESS,
        }:
            self._audit.append(
                incident_id=incident_id,
                actor_type=AuditActorType.AGENT,
                actor_id=agent_type.value,
                event_type="TOOL_ACCESS_GRANTED",
                object_type="Tool",
                object_id=tool_id,
                summary=f"Granted governed tool access for {agent_type.value}",
                payload={
                    "tool_version": definition.version,
                    "risk_level": definition.risk_level.value,
                    "side_effect": definition.side_effect,
                },
            )
        return definition


def build_default_registry(session: Session) -> ToolRegistry:
    def tool(
        tool_id: str,
        allowed: set[AgentType],
        permission: str,
        *,
        risk: ToolRisk = ToolRisk.READ_ONLY,
        side_effect: bool = False,
        sensitivity: EvidenceSensitivity = EvidenceSensitivity.INTERNAL,
    ) -> ToolDefinition:
        return ToolDefinition(
            tool_id=tool_id,
            version="1.0",
            owner="YUDUN_CORE",
            allowed_agent_types=allowed,
            input_schema=f"{tool_id}.input.v1",
            output_schema=f"{tool_id}.output.v1",
            required_permissions={permission},
            risk_level=risk,
            side_effect=side_effect,
            timeout_seconds=30,
            audit_policy=AuditPolicy.DENIAL_AND_SUCCESS,
            data_sensitivity=sensitivity,
        )

    read_agents = {
        AgentType.MAIN_AGENT,
        AgentType.SILENT_MONITOR_AGENT,
        AgentType.INVESTIGATION_AGENT,
        AgentType.TRACE_AGENT,
        AgentType.AUDIT_AGENT,
    }
    definitions = [
        tool("query_event_summary", read_agents, "event:read"),
        tool(
            "query_normalized_events",
            {AgentType.SILENT_MONITOR_AGENT},
            "event:read",
        ),
        tool(
            "create_agent_task",
            {AgentType.MAIN_AGENT},
            "task:create",
            risk=ToolRisk.WRITE_LOW,
            side_effect=True,
        ),
        tool(
            "run_detection_rules",
            {AgentType.SILENT_MONITOR_AGENT},
            "detection:run",
        ),
        tool(
            "get_evidence",
            read_agents,
            "evidence:read",
            sensitivity=EvidenceSensitivity.SENSITIVE,
        ),
        tool("query_cloud_audit", {AgentType.INVESTIGATION_AGENT}, "cloud_audit:read"),
        tool(
            "query_resource_events",
            {AgentType.INVESTIGATION_AGENT},
            "resource:read",
        ),
        tool(
            "query_network_flow",
            {AgentType.INVESTIGATION_AGENT},
            "network:read",
        ),
        tool(
            "query_mock_state_readonly",
            {AgentType.INVESTIGATION_AGENT},
            "mock_state:read",
        ),
        tool("build_timeline", {AgentType.TRACE_AGENT}, "timeline:build"),
        tool(
            "create_action_request",
            {AgentType.OPERATION_AGENT},
            "action:propose",
            risk=ToolRisk.PROPOSAL_ONLY,
            side_effect=True,
        ),
        tool("query_audit_records", {AgentType.AUDIT_AGENT}, "audit:read"),
        tool("generate_report_input", {AgentType.AUDIT_AGENT}, "audit:read"),
        tool(
            "search_knowledge",
            {AgentType.MAIN_AGENT, AgentType.INVESTIGATION_AGENT, AgentType.AUDIT_AGENT},
            "knowledge:read",
        ),
        tool(
            "query_policy_decision",
            {AgentType.OPERATION_AGENT},
            "policy:read",
        ),
        tool(
            "query_execution_result",
            {AgentType.OPERATION_AGENT},
            "execution:read",
        ),
        tool(
            "query_verification_status",
            {AgentType.OPERATION_AGENT},
            "verification:read",
        ),
        tool(
            "execute_mock_action_plan",
            {AgentType.SYSTEM_EXECUTOR},
            "controlled_execution:execute",
            risk=ToolRisk.CONTROLLED_EXECUTION,
            side_effect=True,
            sensitivity=EvidenceSensitivity.RESTRICTED,
        ),
    ]
    return ToolRegistry(session, definitions)
