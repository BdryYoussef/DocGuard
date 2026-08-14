"""Bounded SQLite integrity maintenance command."""

from __future__ import annotations

import argparse

from sqlalchemy.engine import make_url

from app.core.config import Settings
from app.core.database import create_database_engine


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify the configured DocGuard SQLite database")
    parser.add_argument(
        "--full", action="store_true", help="run the slower full PRAGMA integrity_check"
    )
    arguments = parser.parse_args()
    settings = Settings()
    url = make_url(settings.database_url)
    if url.get_backend_name() != "sqlite":
        print("FAIL database backend is not SQLite")
        return 2
    engine = create_database_engine(
        settings.database_url, busy_timeout_ms=settings.sqlite_busy_timeout_ms
    )
    pragma = "integrity_check" if arguments.full else "quick_check(1)"
    try:
        with engine.connect() as connection:
            result = connection.exec_driver_sql(f"PRAGMA {pragma}").scalar()
    except Exception as exc:
        print(f"FAIL database integrity check ({type(exc).__name__})")
        return 1
    finally:
        engine.dispose()
    if result != "ok":
        print("FAIL database integrity check")
        return 1
    print(f"PASS SQLite {'full' if arguments.full else 'quick'} integrity check")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
