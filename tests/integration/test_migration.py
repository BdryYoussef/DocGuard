import sqlite3
from pathlib import Path

import pytest
from alembic.config import Config
from sqlalchemy import create_engine, inspect

from alembic import command


def test_initial_migration_applies_to_temporary_database(tmp_path: Path) -> None:
    database_path = tmp_path / "migration.db"
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", f"sqlite:///{database_path}")

    command.upgrade(config, "head")

    engine = create_engine(f"sqlite:///{database_path}")
    try:
        database_inspector = inspect(engine)
        assert set(database_inspector.get_table_names()) == {
            "alembic_version",
            "artifacts",
            "auth_sessions",
            "audit_events",
            "findings",
            "operators",
            "scans",
        }
        scan_columns = {column["name"] for column in database_inspector.get_columns("scans")}
        assert {
            "state",
            "display_filename",
            "claimed_content_type",
            "detected_type",
            "analysis_error_code",
            "analysis_started_at",
            "analysis_completed_at",
            "policy_version",
            "policy_fingerprint",
            "release_eligible",
            "policy_evaluation_json",
            "analysis_metadata_json",
            "origin",
            "parent_scan_id",
        }.issubset(scan_columns)
        artifact_columns = {
            column["name"] for column in database_inspector.get_columns("artifacts")
        }
        assert {
            "derived_scan_id",
            "size_bytes",
            "sanitizer_version",
            "sanitizer_fingerprint",
            "policy_version",
            "policy_fingerprint",
        }.issubset(artifact_columns)
        assert {
            constraint["name"]
            for constraint in database_inspector.get_unique_constraints("artifacts")
        } >= {"uq_artifacts_source_sanitizer"}
        assert any(
            key["constrained_columns"] == ["parent_scan_id"] and key["referred_table"] == "scans"
            for key in database_inspector.get_foreign_keys("scans")
        )
        assert any(
            key["constrained_columns"] == ["derived_scan_id"] and key["referred_table"] == "scans"
            for key in database_inspector.get_foreign_keys("artifacts")
        )
        operator_columns = {
            column["name"] for column in database_inspector.get_columns("operators")
        }
        assert {"username", "password_hash", "role", "is_active", "last_login_at"}.issubset(
            operator_columns
        )
        assert {
            constraint["name"]
            for constraint in database_inspector.get_unique_constraints("operators")
        } >= {"uq_operators_username"}
        assert {
            constraint["name"]
            for constraint in database_inspector.get_unique_constraints("auth_sessions")
        } >= {"uq_auth_sessions_token_hash"}
        assert any(
            key["constrained_columns"] == ["user_id"]
            and key["referred_table"] == "operators"
            and key["options"].get("ondelete") == "CASCADE"
            for key in database_inspector.get_foreign_keys("auth_sessions")
        )
    finally:
        engine.dispose()


def test_operator_auth_migration_constraints_and_audit_actor_compatibility(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "constraints.db"
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", f"sqlite:///{database_path}")
    command.upgrade(config, "head")

    connection = sqlite3.connect(database_path)
    connection.execute("PRAGMA foreign_keys = ON")
    timestamp = "2026-08-14 12:00:00+00:00"
    operator_id = "1" * 32
    session_values = (
        "3" * 32,
        operator_id,
        "4" * 64,
        "5" * 64,
        timestamp,
        "2026-08-14 20:00:00+00:00",
        timestamp,
        None,
    )
    try:
        connection.execute(
            "INSERT INTO operators "
            "(id, username, password_hash, role, is_active, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (operator_id, "operator", "$argon2id$controlled", "OPERATOR", 1, timestamp, timestamp),
        )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO operators "
                "(id, username, password_hash, role, is_active, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    "2" * 32,
                    "operator",
                    "$argon2id$other",
                    "OPERATOR",
                    1,
                    timestamp,
                    timestamp,
                ),
            )
        connection.execute(
            "INSERT INTO auth_sessions "
            "(id, user_id, token_hash, csrf_token_hash, created_at, expires_at, last_seen_at, "
            "revoked_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            session_values,
        )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO auth_sessions "
                "(id, user_id, token_hash, csrf_token_hash, created_at, expires_at, last_seen_at, "
                "revoked_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                ("6" * 32, operator_id, "4" * 64, "7" * 64, timestamp, timestamp, timestamp, None),
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO auth_sessions "
                "(id, user_id, token_hash, csrf_token_hash, created_at, expires_at, last_seen_at, "
                "revoked_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                ("8" * 32, "9" * 32, "a" * 64, "b" * 64, timestamp, timestamp, timestamp, None),
            )
        connection.execute(
            "INSERT INTO audit_events "
            "(id, event_type, actor_type, actor_id, outcome, details_json, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("c" * 32, "AUTH_LOGIN_SUCCESS", "OPERATOR", operator_id, "SUCCESS", "{}", timestamp),
        )
        connection.execute("DELETE FROM operators WHERE id = ?", (operator_id,))
        assert connection.execute("SELECT count(*) FROM auth_sessions").fetchone() == (0,)
        assert connection.execute("SELECT actor_type, actor_id FROM audit_events").fetchone() == (
            "OPERATOR",
            operator_id,
        )
    finally:
        connection.close()
