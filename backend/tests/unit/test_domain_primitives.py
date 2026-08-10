from datetime import UTC, datetime, timedelta

import pytest
from app.core.canonical import canonical_json
from app.core.ids import ID_PREFIXES, runtime_id, source_derived_id, validate_id
from app.core.time import format_rfc3339, normalize_datetime, utc_now
from app.domain.enums import SourceType


def test_runtime_ids_are_unique_and_valid_for_every_prefix() -> None:
    ids = {runtime_id(prefix) for prefix in ID_PREFIXES for _ in range(3)}
    assert len(ids) == len(ID_PREFIXES) * 3
    for value in ids:
        assert validate_id(value) == value


def test_source_derived_id_is_reproducible() -> None:
    locator = {"capture_id": "cap_fixture", "packet_indexes": [1, 2]}
    first = source_derived_id("evd", locator, "parser-1")
    second = source_derived_id(
        "evd_", {"packet_indexes": [1, 2], "capture_id": "cap_fixture"}, "parser-1"
    )
    assert first == second
    assert validate_id(first, expected_prefix="evd") == first


def test_source_derived_id_changes_with_parser_version() -> None:
    locator = {"capture_id": "cap_fixture", "packet_indexes": [1]}
    assert source_derived_id("raw", locator, "v1") != source_derived_id("raw", locator, "v2")


@pytest.mark.parametrize("prefix", ["", "bad", "incident", "INC"])
def test_invalid_prefix_is_rejected(prefix: str) -> None:
    with pytest.raises(ValueError, match="unsupported ID prefix"):
        runtime_id(prefix)


def test_validate_id_rejects_wrong_expected_prefix() -> None:
    with pytest.raises(ValueError, match="expected inc_ ID"):
        validate_id(runtime_id("sig"), expected_prefix="inc")


def test_utc_now_is_aware_utc() -> None:
    value = utc_now()
    assert value.tzinfo is UTC
    assert value.utcoffset() == timedelta(0)


def test_normalize_datetime_converts_offset_and_rfc3339_z() -> None:
    assert normalize_datetime("2026-08-10T08:00:00+08:00") == datetime(2026, 8, 10, tzinfo=UTC)
    assert normalize_datetime("2026-08-10T00:00:00Z") == datetime(2026, 8, 10, tzinfo=UTC)


def test_naive_datetime_is_rejected() -> None:
    with pytest.raises(ValueError, match="naive"):
        normalize_datetime(datetime(2026, 8, 10))


def test_rfc3339_always_uses_z() -> None:
    assert format_rfc3339(datetime(2026, 8, 10, tzinfo=UTC)) == "2026-08-10T00:00:00.000000Z"


def test_canonical_json_is_stable_for_order_datetime_enum_and_set() -> None:
    first = {
        "source": SourceType.OFFICIAL,
        "at": datetime(2026, 8, 10, tzinfo=UTC),
        "items": {"b", "a"},
        "nested": {"z": 1, "a": 2},
    }
    second = {
        "nested": {"a": 2, "z": 1},
        "items": {"a", "b"},
        "at": datetime(2026, 8, 10, tzinfo=UTC),
        "source": "OFFICIAL",
    }
    assert canonical_json(first) == canonical_json(second)
    assert canonical_json(first) == canonical_json(first)


def test_canonical_json_rejects_naive_datetime() -> None:
    with pytest.raises(ValueError, match="naive"):
        canonical_json({"at": datetime(2026, 8, 10)})
