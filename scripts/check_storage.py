"""Read-only bounded verification of DocGuard private storage."""

from __future__ import annotations

import argparse

from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings
from app.core.database import create_database_engine
from app.operations.storage_integrity import StorageIntegrityService
from app.storage.paths import StoragePaths


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify DocGuard private object integrity")
    parser.add_argument("--batch-size", type=int, default=500)
    parser.add_argument("--include-quarantine", action="store_true")
    arguments = parser.parse_args()
    if not 1 <= arguments.batch_size <= 10_000:
        parser.error("--batch-size must be between 1 and 10000")
    settings = Settings()
    engine = create_database_engine(
        settings.database_url, busy_timeout_ms=settings.sqlite_busy_timeout_ms
    )
    sessions = sessionmaker(engine, class_=Session, expire_on_commit=False)
    try:
        report = StorageIntegrityService(sessions, StoragePaths(settings.storage_root)).check(
            batch_size=arguments.batch_size,
            include_quarantine=arguments.include_quarantine,
        )
    except Exception as exc:
        print(f"FAIL storage verification ({type(exc).__name__})")
        return 1
    finally:
        engine.dispose()
    counts: dict[str, int] = {}
    for issue in report.issues:
        counts[issue.code] = counts.get(issue.code, 0) + 1
    for code, count in sorted(counts.items()):
        print(f"FAIL {code} count={count}")
    if report.passed:
        print(f"PASS private storage objects inspected={report.inspected}")
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
