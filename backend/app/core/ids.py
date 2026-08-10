import hashlib
import re
from typing import Final

import ulid

from app.core.canonical import canonical_json

ID_PREFIXES: Final[frozenset[str]] = frozenset(
    {
        "inc",
        "sig",
        "evd",
        "tsk",
        "res",
        "fnd",
        "fac",
        "rec",
        "arq",
        "pol",
        "apr",
        "exe",
        "ver",
        "aud",
        "cap",
        "flw",
        "raw",
        "run",
        "snp",
        "asc",
        "rsk",
        "paz",
    }
)
_RUNTIME_ID_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[a-z]{3}_[0-9A-HJKMNP-TV-Z]{26}$")
_SOURCE_ID_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[a-z]{3}_[0-9a-f]{24}$")


def _validate_prefix(prefix: str) -> str:
    normalized = prefix.removesuffix("_")
    if normalized not in ID_PREFIXES:
        raise ValueError(f"unsupported ID prefix: {prefix}")
    return normalized


def runtime_id(prefix: str) -> str:
    normalized = _validate_prefix(prefix)
    return f"{normalized}_{ulid.new()}"


def source_derived_id(prefix: str, canonical_source_locator: object, parser_version: str) -> str:
    normalized = _validate_prefix(prefix)
    if not parser_version.strip():
        raise ValueError("parser_version must not be empty")
    material = canonical_json(
        {"source_locator": canonical_source_locator, "parser_version": parser_version}
    )
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:24]
    return f"{normalized}_{digest}"


def validate_id(value: str, *, expected_prefix: str | None = None) -> str:
    if not (_RUNTIME_ID_PATTERN.fullmatch(value) or _SOURCE_ID_PATTERN.fullmatch(value)):
        raise ValueError("invalid object ID")
    prefix = value.split("_", 1)[0]
    _validate_prefix(prefix)
    if expected_prefix is not None and prefix != _validate_prefix(expected_prefix):
        raise ValueError(f"expected {expected_prefix.removesuffix('_')}_ ID")
    return value
