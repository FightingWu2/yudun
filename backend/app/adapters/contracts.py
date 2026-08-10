from dataclasses import dataclass
from typing import Literal, Protocol

from app.schemas.action import ActionRequest, PolicyPreAuthorization
from app.schemas.analysis import SecuritySignal
from app.schemas.data import RawEvent
from app.schemas.evidence import EvidenceReference


@dataclass(frozen=True, slots=True)
class ExternalSecurityBatch:
    """Typed conversion boundary for an enterprise alert/evidence provider."""

    provider: str
    cursor: str | None
    raw_events: tuple[RawEvent, ...]
    evidence: tuple[EvidenceReference, ...]
    signals: tuple[SecuritySignal, ...]


class EnterpriseAlertEvidenceAdapter(Protocol):
    provider: str

    def fetch_batch(self, *, cursor: str | None, limit: int) -> ExternalSecurityBatch: ...


@dataclass(frozen=True, slots=True)
class ExternalSandboxWorkorderReceipt:
    provider: str
    action_request_id: str
    external_workorder_ref: str
    status: Literal["ACCEPTED", "REJECTED", "UNKNOWN"]
    resource_environment: Literal["SANDBOX"] = "SANDBOX"


class EnterpriseSandboxActionAdapter(Protocol):
    """Future external Sandbox boundary; production writes are intentionally absent."""

    provider: str

    def submit_sandbox_workorder(
        self,
        *,
        request: ActionRequest,
        preauthorization: PolicyPreAuthorization,
    ) -> ExternalSandboxWorkorderReceipt: ...
