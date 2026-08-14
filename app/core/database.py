"""Database engine construction with explicit SQLite durability controls."""

import os
from contextlib import suppress
from pathlib import Path
from typing import Any

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.engine import make_url


def create_database_engine(database_url: str, *, busy_timeout_ms: int = 5_000) -> Engine:
    parsed_url = make_url(database_url)
    connect_args: dict[str, object] = {}
    if parsed_url.get_backend_name() == "sqlite":
        connect_args["check_same_thread"] = False
    engine = create_engine(database_url, connect_args=connect_args, pool_pre_ping=True)
    if parsed_url.get_backend_name() == "sqlite":

        @event.listens_for(engine, "connect")
        def configure_sqlite_connection(dbapi_connection: Any, connection_record: Any) -> None:
            del connection_record
            cursor = dbapi_connection.cursor()
            try:
                cursor.execute("PRAGMA foreign_keys=ON")
                cursor.execute(f"PRAGMA busy_timeout={busy_timeout_ms}")
                cursor.execute("PRAGMA synchronous=FULL")
                if parsed_url.database not in {None, "", ":memory:"}:
                    cursor.execute("PRAGMA journal_mode=WAL")
            finally:
                cursor.close()
            if parsed_url.database not in {None, "", ":memory:"}:
                database_path = Path(str(parsed_url.database)).absolute()
                with suppress(FileNotFoundError):
                    os.chmod(database_path, 0o600, follow_symlinks=False)

    return engine


def redact_database_url(database_url: str) -> str:
    """Return only a safe backend label; paths, users, hosts, and passwords stay private."""

    try:
        backend = make_url(database_url).get_backend_name()
    except Exception:
        return "invalid-database-url"
    return f"{backend}://[redacted]"


__all__ = ["create_database_engine", "redact_database_url"]
