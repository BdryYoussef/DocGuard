"""Read-only production qualification assembled from reusable checks."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from sqlalchemy import func, select

from app.auth.models import Role
from app.auth.passwords import PasswordService
from app.cdr.registry import sanitizer_fingerprint, sanitizer_registry_is_valid
from app.core.config import AppEnvironment, Settings
from app.core.database import create_database_engine
from app.core.qualification import (
    QualificationReport,
    qualify_database,
    qualify_filesystem,
    qualify_runtime,
)
from app.models.database import OperatorUser
from app.orchestrator.factory import create_isolation_backend
from app.policies.registry import (
    POLICY_FINGERPRINT,
    compute_policy_fingerprint,
    policy_registry_is_valid,
)
from app.storage.paths import StoragePaths


def run_production_preflight(
    settings: Settings, *, project_root: Path | None = None
) -> QualificationReport:
    root = (project_root or Path.cwd()).resolve()
    checks: dict[str, bool] = {
        "production_environment": settings.env is AppEnvironment.PRODUCTION,
        "production_https_origin": settings.application_origin.startswith("https://"),
        "secure_session_cookie": settings.effective_session_cookie_secure,
        "csrf_enabled": settings.csrf_required,
        "origin_required": settings.effective_require_origin_header,
        "trusted_proxy_configuration": _proxy_configuration_is_valid(settings),
        "password_hasher": PasswordService().ready,
        "policy_registry": policy_registry_is_valid(),
        "sanitizer_registry": sanitizer_registry_is_valid(settings),
        "policy_fingerprint": compute_policy_fingerprint() == POLICY_FINGERPRINT,
        "sanitizer_fingerprint": len(sanitizer_fingerprint(settings)) == 64,
    }
    checks.update(_host_isolation_prerequisites(settings))
    paths = StoragePaths(settings.storage_root)
    checks.update(
        qualify_filesystem(
            settings,
            paths,
            static_root=root / "app" / "web" / "static",
            project_root=root,
        ).checks
    )
    checks.update(qualify_runtime(settings, project_root=root).checks)
    engine = create_database_engine(
        settings.database_url, busy_timeout_ms=settings.sqlite_busy_timeout_ms
    )
    try:
        checks.update(qualify_database(engine).checks)
        try:
            with engine.connect() as connection:
                active = connection.scalar(
                    select(func.count())
                    .select_from(OperatorUser)
                    .where(
                        OperatorUser.is_active.is_(True),
                        OperatorUser.role == Role.OPERATOR.value,
                    )
                )
            checks["active_operator"] = bool(active)
        except Exception:
            checks["active_operator"] = False
    finally:
        engine.dispose()
    try:
        backend = create_isolation_backend(settings, project_root=root)
        self_test_method = getattr(backend, "self_test", None)
        if callable(self_test_method):
            self_test = self_test_method()
            checks["sandbox_self_test"] = self_test.passed
            checks["worker_parser_runtime"] = self_test.worker_dependencies_load
            checks["renderer_mupdf_runtime"] = self_test.renderer_runtime_loads
            checks["archive_compression_runtime"] = self_test.archive_runtime_loads
            checks["yara_manifest_fingerprint"] = self_test.yara_rule_pack_qualifies
            checks["yara_rules_read_only"] = self_test.yara_rules_read_only
            checks["cgroup_rlimit_controls"] = self_test.resource_limits_applied
        else:
            checks["sandbox_self_test"] = backend.ready
    except Exception:
        checks["sandbox_self_test"] = False
    return QualificationReport(checks)


def _proxy_configuration_is_valid(settings: Settings) -> bool:
    try:
        _ = settings.parsed_trusted_proxy_ips
    except ValueError:
        return False
    return True


def _host_isolation_prerequisites(settings: Settings) -> dict[str, bool]:
    checks = {
        "bubblewrap_executable": os.access(settings.bubblewrap_path, os.X_OK),
        "prlimit_executable": os.access(settings.prlimit_path, os.X_OK),
        "systemd_run_executable": os.access(settings.systemd_run_path, os.X_OK),
        "cgroup_v2": Path("/sys/fs/cgroup/cgroup.controllers").is_file(),
        "user_systemd_bus": Path(f"/run/user/{os.getuid()}/bus").exists(),
    }
    try:
        completed = subprocess.run(  # noqa: S603 - validated configured launcher, no shell
            [str(settings.bubblewrap_path), "--version"],
            check=False,
            capture_output=True,
            text=True,
            timeout=2,
            env={"PATH": "/usr/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
        )
        checks["bubblewrap_version_0_11_1"] = (
            completed.returncode == 0 and completed.stdout.strip() == "bubblewrap 0.11.1"
        )
    except (OSError, subprocess.TimeoutExpired):
        checks["bubblewrap_version_0_11_1"] = False
    return checks


__all__ = ["run_production_preflight"]
