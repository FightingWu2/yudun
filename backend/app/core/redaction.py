import logging
import re
from collections.abc import Mapping
from typing import Any

REDACTED = "[REDACTED]"

_SENSITIVE_EXACT_KEYS = {
    "authorization",
    "cookie",
    "set-cookie",
    "set_cookie",
    "token",
    "api_key",
    "apikey",
    "secret",
    "credential",
    "password",
}
_SAFE_REFERENCE_SUFFIXES = ("_ref", "_id", "_hash", "_sha256", "_present")
_AUTH_VALUE = re.compile(r"(?i)\b(authorization\s*:\s*(?:bearer|basic)\s+)\S+")
_COOKIE_VALUE = re.compile(r"(?i)\b((?:set-)?cookie\s*:\s*)[^\r\n]+")
_ASSIGNMENT_VALUE = re.compile(
    r"(?i)\b(api[-_]?key|password|secret|token|credential)\s*([=:])\s*([^\s,;&]+)"
)


def is_sensitive_key(key: str) -> bool:
    normalized = key.strip().lower().replace(" ", "_")
    if normalized.endswith(_SAFE_REFERENCE_SUFFIXES):
        return False
    if normalized in _SENSITIVE_EXACT_KEYS:
        return True
    return any(
        normalized.endswith(f"_{suffix}")
        for suffix in ("token", "api_key", "secret", "credential", "password")
    )


def redact_text(value: str) -> str:
    redacted = _AUTH_VALUE.sub(lambda match: f"{match.group(1)}{REDACTED}", value)
    redacted = _COOKIE_VALUE.sub(lambda match: f"{match.group(1)}{REDACTED}", redacted)
    return _ASSIGNMENT_VALUE.sub(
        lambda match: f"{match.group(1)}{match.group(2)}{REDACTED}", redacted
    )


def redact(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            str(key): REDACTED if is_sensitive_key(str(key)) else redact(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, tuple):
        return [redact(item) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    return value


def contains_plaintext_secret(value: Any) -> bool:
    redacted = redact(value)
    return bool(redacted != value)


class RedactionFilter(logging.Filter):
    """Sanitize message and arguments before any configured handler emits them."""

    def filter(self, record: logging.LogRecord) -> bool:
        rendered = record.getMessage()
        record.msg = redact_text(rendered)
        record.args = ()
        return True
