from datetime import UTC, datetime


def utc_now() -> datetime:
    """Return an aware UTC datetime."""
    return datetime.now(UTC)


def normalize_datetime(value: datetime | str) -> datetime:
    """Normalize an aware datetime/RFC3339 string to UTC; reject naive values."""
    if isinstance(value, str):
        candidate = value.strip()
        if candidate.endswith("Z"):
            candidate = f"{candidate[:-1]}+00:00"
        try:
            parsed = datetime.fromisoformat(candidate)
        except ValueError as exc:
            raise ValueError("datetime must be valid RFC3339") from exc
    else:
        parsed = value
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("naive datetime is not allowed")
    return parsed.astimezone(UTC)


def format_rfc3339(value: datetime) -> str:
    normalized = normalize_datetime(value)
    return normalized.isoformat(timespec="microseconds").replace("+00:00", "Z")
