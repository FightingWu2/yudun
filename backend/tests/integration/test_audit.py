import io
import logging
from pathlib import Path

import pytest
from app.audit.service import AuditService
from app.core.redaction import REDACTED, RedactionFilter, contains_plaintext_secret, redact
from app.db.base import Base
from app.db.models import AuditMutationError, AuditRecordORM
from app.db.session import create_business_engine, make_session_factory
from app.schemas.audit import AuditActorType
from sqlalchemy import select, text


def make_factory(tmp_path: Path):  # type: ignore[no-untyped-def]
    engine = create_business_engine(f"sqlite:///{tmp_path / 'audit.db'}")
    Base.metadata.create_all(engine)
    return engine, make_session_factory(engine)


def append_three(factory) -> list[str]:  # type: ignore[no-untyped-def]
    record_ids: list[str] = []
    with factory.begin() as session:
        service = AuditService(session)
        for index in range(1, 4):
            record = service.append(
                incident_id=None,
                actor_type=AuditActorType.SYSTEM,
                actor_id="test",
                event_type=f"EVENT_{index}",
                object_type="Fixture",
                object_id=f"object_{index}",
                summary=f"Append event {index}",
                payload={"index": index},
            )
            record_ids.append(record.audit_id)
    return record_ids


def test_redaction_handles_headers_nested_fields_and_text() -> None:
    value = {
        "Authorization": "Bearer abc.def",
        "Cookie": "session=plain",
        "nested": {
            "api_key": "plain-key",
            "password": "plain-password",
            "credential_ref": "safe-reference",
        },
        "message": "token=plain-token",
    }
    result = redact(value)
    assert result["Authorization"] == REDACTED
    assert result["Cookie"] == REDACTED
    assert result["nested"]["api_key"] == REDACTED
    assert result["nested"]["password"] == REDACTED
    assert result["nested"]["credential_ref"] == "safe-reference"
    assert result["message"] == f"token={REDACTED}"
    assert contains_plaintext_secret(value)
    assert not contains_plaintext_secret(result)


def test_logging_filter_removes_plaintext_secret() -> None:
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.addFilter(RedactionFilter())
    logger = logging.getLogger("test.safe.logging")
    logger.handlers = [handler]
    logger.propagate = False
    logger.setLevel(logging.INFO)

    logger.info("Authorization: Bearer %s api_key=%s", "plain-token", "plain-key")
    output = stream.getvalue()
    assert "plain-token" not in output
    assert "plain-key" not in output
    assert REDACTED in output


def test_audit_normal_chain_passes_and_payload_is_redacted(tmp_path: Path) -> None:
    _, factory = make_factory(tmp_path)
    with factory.begin() as session:
        service = AuditService(session)
        service.append(
            incident_id=None,
            actor_type=AuditActorType.SYSTEM,
            actor_id="test",
            event_type="SECRET_TEST",
            object_type="Fixture",
            object_id="object_1",
            summary="Authorization: Bearer plain-token",
            payload={"api_key": "plain-key", "safe": "value"},
        )

    with factory() as session:
        service = AuditService(session)
        assert service.verify_chain(None)
        row = session.scalar(select(AuditRecordORM))
        assert row is not None
        persisted = f"{row.summary} {row.payload_redacted}"
        assert "plain-token" not in persisted
        assert "plain-key" not in persisted
        assert REDACTED in persisted


def test_audit_tampered_history_fails(tmp_path: Path) -> None:
    engine, factory = make_factory(tmp_path)
    record_ids = append_three(factory)
    with engine.begin() as connection:
        connection.execute(
            text("UPDATE audit_records SET summary='tampered' WHERE audit_id=:audit_id"),
            {"audit_id": record_ids[1]},
        )
    with factory() as session:
        assert not AuditService(session).verify_chain(None)


def test_audit_deleted_middle_record_fails(tmp_path: Path) -> None:
    engine, factory = make_factory(tmp_path)
    record_ids = append_three(factory)
    with engine.begin() as connection:
        connection.execute(
            text("DELETE FROM audit_records WHERE audit_id=:audit_id"),
            {"audit_id": record_ids[1]},
        )
    with factory() as session:
        assert not AuditService(session).verify_chain(None)


def test_audit_reordered_records_fail(tmp_path: Path) -> None:
    engine, factory = make_factory(tmp_path)
    record_ids = append_three(factory)
    with engine.begin() as connection:
        connection.execute(
            text("UPDATE audit_records SET sequence_no=99 WHERE audit_id=:audit_id"),
            {"audit_id": record_ids[0]},
        )
        connection.execute(
            text("UPDATE audit_records SET sequence_no=1 WHERE audit_id=:audit_id"),
            {"audit_id": record_ids[1]},
        )
        connection.execute(
            text("UPDATE audit_records SET sequence_no=2 WHERE audit_id=:audit_id"),
            {"audit_id": record_ids[0]},
        )
    with factory() as session:
        assert not AuditService(session).verify_chain(None)


def test_orm_update_and_delete_are_rejected(tmp_path: Path) -> None:
    _, factory = make_factory(tmp_path)
    record_id = append_three(factory)[0]

    with factory() as session:
        row = session.get(AuditRecordORM, record_id)
        assert row is not None
        row.summary = "attempted mutation"
        with pytest.raises(AuditMutationError, match="append-only"):
            session.flush()
        session.rollback()

    with factory() as session:
        row = session.get(AuditRecordORM, record_id)
        assert row is not None
        session.delete(row)
        with pytest.raises(AuditMutationError, match="append-only"):
            session.flush()
