"""Run DocGuard's read-only production qualification gate."""

from __future__ import annotations

from app.core.config import Settings
from app.core.preflight import run_production_preflight


def main() -> int:
    try:
        settings = Settings()
        report = run_production_preflight(settings)
    except Exception as exc:
        print(f"FAIL configuration ({type(exc).__name__})")
        return 1
    for name, passed in sorted(report.checks.items()):
        print(f"{'PASS' if passed else 'FAIL'} {name}")
    return 0 if report.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
