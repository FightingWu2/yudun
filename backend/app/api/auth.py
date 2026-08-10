from enum import StrEnum

from fastapi import Header

from app.core.errors import PermissionDeniedError


class DemoRole(StrEnum):
    ANALYST = "ANALYST"
    APPROVER = "APPROVER"
    AUDITOR = "AUDITOR"
    ADMIN = "ADMIN"


def current_role(x_demo_role: str = Header(default="ANALYST")) -> DemoRole:
    try:
        return DemoRole(x_demo_role.upper())
    except ValueError as exc:
        raise PermissionDeniedError("unknown local demo role") from exc


def require_role(role: DemoRole, allowed: set[DemoRole]) -> None:
    if role not in allowed:
        raise PermissionDeniedError(f"{role.value} is not allowed for this operation")
