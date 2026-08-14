from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from sqlalchemy import text

from app.core.database import create_database_engine, redact_database_url
from app.core.qualification import qualify_database


def test_sqlite_wal_full_foreign_keys_busy_timeout_and_restart(tmp_path: Path) -> None:
    database = tmp_path / "docguard.db"
    engine = create_database_engine(f"sqlite:///{database}", busy_timeout_ms=7_500)
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE parent (id INTEGER PRIMARY KEY)"))
        connection.execute(
            text(
                "CREATE TABLE child (parent_id INTEGER NOT NULL "
                "REFERENCES parent(id) ON DELETE RESTRICT)"
            )
        )
        assert connection.exec_driver_sql("PRAGMA foreign_keys").scalar() == 1
        assert connection.exec_driver_sql("PRAGMA busy_timeout").scalar() == 7_500
        assert str(connection.exec_driver_sql("PRAGMA journal_mode").scalar()).casefold() == "wal"
        assert connection.exec_driver_sql("PRAGMA synchronous").scalar() == 2
    assert database.stat().st_mode & 0o777 == 0o600
    engine.dispose()

    restarted = create_database_engine(f"sqlite:///{database}", busy_timeout_ms=7_500)
    with restarted.connect() as connection:
        assert connection.exec_driver_sql("PRAGMA quick_check(1)").scalar() == "ok"
        assert connection.scalar(text("SELECT count(*) FROM child")) == 0
    restarted.dispose()


def test_sqlite_wal_allows_reader_during_normal_uncommitted_write(tmp_path: Path) -> None:
    engine = create_database_engine(f"sqlite:///{tmp_path / 'concurrent.db'}")
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE values_table (id INTEGER PRIMARY KEY)"))
    writer = engine.connect()
    transaction = writer.begin()
    try:
        writer.execute(text("INSERT INTO values_table (id) VALUES (1)"))
        with engine.connect() as reader:
            assert reader.scalar(text("SELECT count(*) FROM values_table")) == 0
        transaction.commit()
        with engine.connect() as reader:
            assert reader.scalar(text("SELECT count(*) FROM values_table")) == 1
    finally:
        if transaction.is_active:
            transaction.rollback()
        writer.close()
        engine.dispose()


def test_database_file_mode_is_explicit_under_permissive_umask(tmp_path: Path) -> None:
    database = tmp_path / "private.db"
    original = os.umask(0)
    try:
        engine = create_database_engine(f"sqlite:///{database}")
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        engine.dispose()
    finally:
        os.umask(original)
    assert database.stat().st_mode & 0o777 == 0o600


def test_corrupt_database_fails_qualification_without_exposing_rows(tmp_path: Path) -> None:
    database = tmp_path / "corrupt.db"
    database.write_bytes(b"not a sqlite database")
    database.chmod(0o600)
    engine = create_database_engine(f"sqlite:///{database}")
    report = qualify_database(engine)
    engine.dispose()
    assert not report.passed
    assert report.checks["database_connectivity"] is False


def test_database_integrity_cli_healthy_and_corrupt_exit_semantics(tmp_path: Path) -> None:
    environment = {
        **os.environ,
        "PYTHONPATH": ".python-deps:.worker-deps:.",
        "DOCGUARD_DATABASE_URL": f"sqlite:///{tmp_path / 'healthy.db'}",
    }
    engine = create_database_engine(environment["DOCGUARD_DATABASE_URL"])
    with engine.connect() as connection:
        connection.execute(text("SELECT 1"))
    engine.dispose()
    healthy = subprocess.run(
        [sys.executable, "-m", "scripts.check_database"],
        cwd=Path.cwd(),
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert healthy.returncode == 0
    assert healthy.stdout.startswith("PASS SQLite quick integrity check")

    corrupt = tmp_path / "corrupt-cli.db"
    corrupt.write_bytes(b"controlled corrupt database fixture")
    corrupt.chmod(0o600)
    environment["DOCGUARD_DATABASE_URL"] = f"sqlite:///{corrupt}"
    failed = subprocess.run(
        [sys.executable, "-m", "scripts.check_database", "--full"],
        cwd=Path.cwd(),
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert failed.returncode == 1
    assert failed.stdout.startswith("FAIL database integrity check")
    assert str(corrupt) not in failed.stdout


def test_reference_deployment_freezes_single_loopback_worker_and_proxy_overwrite() -> None:
    unit = Path("deploy/systemd/docguard.service").read_text(encoding="utf-8")
    nginx = Path("deploy/nginx/docguard.conf.example").read_text(encoding="utf-8")
    environment = Path("deploy/docguard.env.example").read_text(encoding="utf-8")

    assert "--host 127.0.0.1" in unit
    assert "--workers 1" in unit
    assert "--no-proxy-headers" in unit
    assert "--no-access-log" in unit
    assert "UMask=0077" in unit
    assert "NoNewPrivileges=true" in unit
    assert "CapabilityBoundingSet=\n" in unit
    assert "PrivateUsers=" not in unit
    assert "RestrictNamespaces=" not in unit
    assert "proxy_pass http://127.0.0.1:8000" in nginx
    assert "listen 443 ssl default_server" in nginx
    assert "ssl_reject_handshake on" in nginx
    assert "proxy_set_header X-Real-IP $remote_addr" in nginx
    assert 'proxy_set_header X-Forwarded-For ""' in nginx
    assert "proxy_cache off" in nginx
    assert "autoindex on" not in nginx
    assert "DOCGUARD_TRUSTED_PROXY_IPS=127.0.0.1,::1" in environment
    for forbidden in ("PASSWORD=", "SESSION_TOKEN=", "CSRF_TOKEN="):
        assert forbidden not in environment


def test_check_storage_and_reconcile_print_actionable_hint_for_uninitialized_schema(
    tmp_path: Path,
) -> None:
    """check_storage and reconcile_state must emit a HINT when the DB has no schema tables.

    An empty SQLite file passes PRAGMA quick_check(1) but has no application tables.
    The CLIs previously printed only FAIL ... (OperationalError) which gave no actionable
    information. This regression test confirms the HINT line is now emitted.
    """
    environment = {
        **os.environ,
        "PYTHONPATH": ".python-deps:.worker-deps:.",
        "DOCGUARD_DATABASE_URL": f"sqlite:///{tmp_path / 'empty.db'}",
        "DOCGUARD_STORAGE_ROOT": str(tmp_path / "storage"),
        "DOCGUARD_APPLICATION_ORIGIN": "https://docguard.test.local",
    }
    # Create the empty SQLite file and storage root (no alembic migration)
    engine = create_database_engine(environment["DOCGUARD_DATABASE_URL"])
    with engine.connect() as connection:
        connection.execute(text("SELECT 1"))
    engine.dispose()
    storage = tmp_path / "storage"
    storage.mkdir(mode=0o700, exist_ok=True)

    check = subprocess.run(
        [sys.executable, "-m", "scripts.check_storage"],
        cwd=Path.cwd(),
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert check.returncode == 1
    assert "FAIL storage verification (OperationalError)" in check.stdout
    assert "HINT database schema is not initialized" in check.stdout
    assert "alembic upgrade head" in check.stdout
    # Must not expose raw SQL or the DB path
    assert str(tmp_path) not in check.stdout
    assert "SELECT" not in check.stdout

    reconcile = subprocess.run(
        [sys.executable, "-m", "scripts.reconcile_state"],
        cwd=Path.cwd(),
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert reconcile.returncode == 1
    assert "FAIL reconciliation (OperationalError)" in reconcile.stdout
    assert "HINT database schema is not initialized" in reconcile.stdout
    assert "alembic upgrade head" in reconcile.stdout
    assert str(tmp_path) not in reconcile.stdout
    assert "SELECT" not in reconcile.stdout


def test_database_url_redaction_never_returns_credentials_or_internal_path() -> None:
    rendered = redact_database_url("postgresql://operator:secret@example.test/private")
    assert rendered == "postgresql://[redacted]"
    assert "secret" not in rendered and "operator" not in rendered and "example" not in rendered
    sqlite = redact_database_url("sqlite:////var/lib/docguard/private.db")
    assert sqlite == "sqlite://[redacted]"
    assert "/var/" not in sqlite
