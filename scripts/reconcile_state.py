"""Dry-run-by-default bounded crash-state reconciliation."""

from __future__ import annotations

import argparse

from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings
from app.core.database import create_database_engine
from app.operations.reconciliation import ReconciliationLocked, ReconciliationService
from app.storage.paths import StoragePaths


def main() -> int:
    parser = argparse.ArgumentParser(description="Inspect DocGuard crash consistency")
    parser.add_argument("--batch-size", type=int, default=500)
    parser.add_argument("--stale-seconds", type=int)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument(
        "--cleanup-temporary",
        action="store_true",
        help="with --apply, delete only qualified stale application temp files",
    )
    arguments = parser.parse_args()
    if not 1 <= arguments.batch_size <= 10_000:
        parser.error("--batch-size must be between 1 and 10000")
    if arguments.cleanup_temporary and not arguments.apply:
        parser.error("--cleanup-temporary requires --apply")
    settings = Settings()
    stale_seconds = arguments.stale_seconds or settings.reconciliation_stale_seconds
    if not 60 <= stale_seconds <= 86_400:
        parser.error("--stale-seconds must be between 60 and 86400")
    engine = create_database_engine(
        settings.database_url, busy_timeout_ms=settings.sqlite_busy_timeout_ms
    )
    sessions = sessionmaker(engine, class_=Session, expire_on_commit=False)
    try:
        report = ReconciliationService(sessions, StoragePaths(settings.storage_root)).inspect(
            stale_seconds=stale_seconds,
            batch_size=arguments.batch_size,
            apply=arguments.apply,
            cleanup_temporary=arguments.cleanup_temporary,
        )
    except ReconciliationLocked:
        print("FAIL reconciliation lock is unavailable or held")
        return 2
    except Exception as exc:
        print(f"FAIL reconciliation ({type(exc).__name__})")
        return 1
    finally:
        engine.dispose()
    counts: dict[str, int] = {}
    for issue in report.issues:
        counts[issue.code] = counts.get(issue.code, 0) + 1
    mode = "APPLY" if arguments.apply else "DRY-RUN"
    print(f"PASS reconciliation completed mode={mode}")
    print(
        f"inspected_scans={report.inspected_scans} "
        f"inspected_artifacts={report.inspected_artifacts} "
        f"inspected_files={report.inspected_files}"
    )
    for code, count in sorted(counts.items()):
        print(f"FINDING {code} count={count}")
    if arguments.apply:
        print(
            f"stale_scans_quarantined={report.stale_scans_quarantined} "
            f"temporary_files_cleaned={report.temporary_files_cleaned}"
        )
    return 3 if report.truncated else 0


if __name__ == "__main__":
    raise SystemExit(main())
