import re
from collections.abc import Mapping
from datetime import datetime
from typing import Annotated, Any, TypeAlias

from pydantic import (
    AfterValidator,
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    JsonValue,
    StringConstraints,
    model_validator,
)

from app.core.canonical import canonical_json
from app.core.time import normalize_datetime, utc_now

UtcDateTime = Annotated[datetime, BeforeValidator(normalize_datetime)]
Sha256 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
NonEmptyStr = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]
Port = Annotated[int, Field(ge=0, le=65535)]
PositiveCount = Annotated[int, Field(ge=0)]

_SENSITIVE_KEY_PATTERN = re.compile(
    r"(^|[-_])(authorization|cookie|set[-_]?cookie|api[-_]?key|password|secret|token|credential)($|[-_])",
    re.IGNORECASE,
)
_PLAINTEXT_SECRET_PATTERN = re.compile(
    r"(?:authorization\s*:\s*(?:bearer|basic)\s+(?!\[redacted\])\S+|"
    r"(?:api[-_]?key|password|secret|token)\s*[=:]\s*(?!\[redacted\])[^\s,;&]+)",
    re.IGNORECASE,
)
_SAFE_SENSITIVE_CONTAINERS = {"credential"}


def _assert_no_plaintext_secrets(value: Any, *, path: str = "$") -> None:
    if isinstance(value, Mapping):
        for raw_key, item in value.items():
            key = str(raw_key)
            is_redacted = isinstance(item, str) and item.strip().upper() == "[REDACTED]"
            is_safe_reference = key.lower().endswith(("_ref", "_id", "_hash", "_present"))
            is_safe_container = key.lower() in _SAFE_SENSITIVE_CONTAINERS and isinstance(
                item, (Mapping, BaseModel)
            )
            if _SENSITIVE_KEY_PATTERN.search(key) and not (
                is_redacted or is_safe_reference or is_safe_container
            ):
                raise ValueError(f"sensitive field is not allowed at {path}.{key}")
            _assert_no_plaintext_secrets(item, path=f"{path}.{key}")
    elif isinstance(value, (list, tuple, set, frozenset)):
        for index, item in enumerate(value):
            _assert_no_plaintext_secrets(item, path=f"{path}[{index}]")
    elif isinstance(value, str) and _PLAINTEXT_SECRET_PATTERN.search(value):
        raise ValueError(f"plaintext secret is not allowed at {path}")


def _validate_metadata(value: dict[str, JsonValue]) -> dict[str, JsonValue]:
    _assert_no_plaintext_secrets(value)
    if len(canonical_json(value).encode("utf-8")) > 16 * 1024:
        raise ValueError("metadata exceeds 16 KiB")
    return value


SafeMetadata: TypeAlias = Annotated[dict[str, JsonValue], AfterValidator(_validate_metadata)]


class StrictSchema(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True, str_strip_whitespace=True)

    schema_version: str = "1.0"

    @model_validator(mode="before")
    @classmethod
    def reject_plaintext_secrets(cls, value: Any) -> Any:
        _assert_no_plaintext_secrets(value)
        return value


class TimestampedSchema(StrictSchema):
    created_at: UtcDateTime = Field(default_factory=utc_now)
    metadata: SafeMetadata = Field(default_factory=dict)


def require_prefix(value: str, prefix: str) -> str:
    if not value.startswith(f"{prefix}_"):
        raise ValueError(f"ID must use {prefix}_ prefix")
    return value
