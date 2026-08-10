from enum import StrEnum


class ErrorCode(StrEnum):
    PERMISSION_DENIED = "PERMISSION_DENIED"
    SCHEMA_INVALID = "SCHEMA_INVALID"
    SOURCE_UNAVAILABLE = "SOURCE_UNAVAILABLE"
    NOT_FOUND = "NOT_FOUND"
    CONFLICT = "CONFLICT"
    TIMEOUT = "TIMEOUT"
    EVIDENCE_REQUIRED = "EVIDENCE_REQUIRED"
    INVALID_STATE_TRANSITION = "INVALID_STATE_TRANSITION"


class DomainError(Exception):
    def __init__(self, code: ErrorCode, message: str, *, retryable: bool = False) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.retryable = retryable


class ConflictError(DomainError):
    def __init__(self, message: str) -> None:
        super().__init__(ErrorCode.CONFLICT, message, retryable=True)


class PermissionDeniedError(DomainError):
    def __init__(self, message: str) -> None:
        super().__init__(ErrorCode.PERMISSION_DENIED, message)


class InvalidStateTransitionError(DomainError):
    def __init__(self, message: str) -> None:
        super().__init__(ErrorCode.INVALID_STATE_TRANSITION, message)
