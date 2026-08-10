from datetime import UTC, datetime
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from app.core.ids import runtime_id, source_derived_id
from app.db.base import Base
from app.db.models import CaptureORM
from app.db.session import create_business_engine, make_session_factory
from app.domain.enums import AutomationState, IncidentStatus, Severity
from app.repositories.incidents import IncidentRepository
from app.schemas.incident import IncidentType, SecurityIncident
from sqlalchemy import inspect, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

NOW = datetime(2026, 8, 10, tzinfo=UTC)


def alembic_config(database_path: Path) -> Config:
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", f"sqlite:///{database_path}")
    return config


def make_incident() -> SecurityIncident:
    return SecurityIncident(
        incident_id=runtime_id("inc"),
        title="Repository fixture",
        incident_type=IncidentType.API_CREDENTIAL_COMPROMISE,
        tenant_ref="tenant_fixture",
        status=IncidentStatus.NEW,
        automation_state=AutomationState.ACTIVE,
        severity=Severity.HIGH,
        summary="Repository round trip",
        opened_at=NOW,
        updated_at=NOW,
        created_at=NOW,
    )


def test_initial_migration_upgrade_and_downgrade(tmp_path: Path) -> None:
    database_path = tmp_path / "migration.db"
    config = alembic_config(database_path)

    command.upgrade(config, "head")
    engine = create_business_engine(f"sqlite:///{database_path}")
    tables = set(inspect(engine).get_table_names())
    assert "security_incidents" in tables
    assert "evidence_references" in tables
    assert "audit_records" in tables
    assert "mock_scenario_states" in tables
    assert "state_snapshots" in tables
    assert "policy_preauthorizations" in tables
    assert "langgraph_checkpoints" not in tables

    command.downgrade(config, "base")
    remaining = set(inspect(engine).get_table_names())
    assert remaining <= {"alembic_version"}


def test_sqlite_wal_and_foreign_keys_are_enabled(tmp_path: Path) -> None:
    database_path = tmp_path / "pragma.db"
    engine = create_business_engine(f"sqlite:///{database_path}")
    with engine.connect() as connection:
        assert connection.scalar(text("PRAGMA foreign_keys")) == 1
        assert connection.scalar(text("PRAGMA journal_mode")) == "wal"


def test_repository_round_trip(tmp_path: Path) -> None:
    engine = create_business_engine(f"sqlite:///{tmp_path / 'repo.db'}")
    Base.metadata.create_all(engine)
    factory = make_session_factory(engine)
    incident = make_incident()

    with factory.begin() as session:
        repository = IncidentRepository(session)
        repository.add(incident)

    with factory() as session:
        repository = IncidentRepository(session)
        assert repository.get(incident.incident_id) == incident
        assert repository.list_by_tenant("tenant_fixture") == [incident]
        assert repository.get("inc_missing") is None


def test_unique_constraint_rejects_duplicate_capture_hash(tmp_path: Path) -> None:
    engine = create_business_engine(f"sqlite:///{tmp_path / 'unique.db'}")
    Base.metadata.create_all(engine)
    common = {
        "source_id": "fixture.pcap",
        "file_sha256": "a" * 64,
        "parse_status": "PENDING",
        "schema_version": "1.0",
        "payload": {},
        "created_at": NOW,
    }
    with Session(engine) as session:
        session.add(CaptureORM(capture_id=source_derived_id("cap", {"n": 1}, "v1"), **common))
        session.commit()
        session.add(CaptureORM(capture_id=source_derived_id("cap", {"n": 2}, "v1"), **common))
        with pytest.raises(IntegrityError):
            session.commit()


def test_foreign_key_constraint_is_enforced(tmp_path: Path) -> None:
    engine = create_business_engine(f"sqlite:///{tmp_path / 'fk.db'}")
    Base.metadata.create_all(engine)
    with engine.begin() as connection, pytest.raises(IntegrityError):
        connection.execute(
            text(
                """
                    INSERT INTO raw_events
                    (event_id, capture_id, source_type, event_kind, source_timestamp,
                     schema_version, payload, created_at)
                    VALUES
                    (:event_id, :capture_id, 'OFFICIAL', 'PACKET', :timestamp,
                     '1.0', '{}', :timestamp)
                    """
            ),
            {
                "event_id": source_derived_id("raw", {"n": 1}, "v1"),
                "capture_id": source_derived_id("cap", {"missing": True}, "v1"),
                "timestamp": NOW,
            },
        )
