"""Safe, reusable production qualification checks."""

from __future__ import annotations

import importlib.metadata
import os
import stat
import sys
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy import Engine, text
from sqlalchemy.engine import make_url

from app.core.config import Settings
from app.storage.paths import StoragePaths

ALEMBIC_HEAD = "0005"
TRUSTED_RUNTIME_VERSIONS = {
    "argon2-cffi": "25.1.0",
    "argon2-cffi-bindings": "25.1.0",
    "fastapi": "0.141.1",
    "Jinja2": "3.1.6",
    "pydantic": "2.13.4",
    "pydantic-settings": "2.15.0",
    "SQLAlchemy": "2.0.52",
    "starlette": "1.6.0",
    "uvicorn": "0.52.3",
}
WORKER_RUNTIME_VERSIONS = {
    "cryptography": "50.0.0",
    "defusedxml": "0.7.1",
    "lxml": "6.1.1",
    "msoffcrypto-tool": "6.0.0",
    "olefile": "0.47",
    "oletools": "0.60.2",
    "pikepdf": "10.11.0",
    "Pillow": "12.3.0",
    "PyMuPDF": "1.28.2",
    "pyparsing": "3.2.5",
    "yara-python": "4.5.4",
}


@dataclass(frozen=True, slots=True)
class QualificationReport:
    checks: dict[str, bool]

    @property
    def passed(self) -> bool:
        return all(self.checks.values())


def qualify_filesystem(
    settings: Settings,
    paths: StoragePaths,
    *,
    static_root: Path,
    project_root: Path,
) -> QualificationReport:
    checks: dict[str, bool] = {}
    private_directories = (
        paths.root,
        paths.incoming,
        paths.quarantine,
        paths.sanitized,
        paths.work,
    )
    checks["storage_absolute"] = paths.root.is_absolute()
    checks["storage_directories_private"] = all(
        _owned_real_directory(path, exact_mode=0o700) for path in private_directories
    )
    checks["storage_no_symlink_components"] = not any(
        _has_symlink_component(path) for path in private_directories
    )
    checks["static_private_separation"] = _static_is_separate(static_root, paths.root)
    checks["static_assets_trusted"] = _tree_is_trusted(static_root)

    url = make_url(settings.database_url)
    if url.get_backend_name() == "sqlite" and url.database not in {None, "", ":memory:"}:
        database_path = Path(str(url.database))
        checks["sqlite_path_absolute"] = database_path.is_absolute()
        database_path = database_path.absolute()
        checks["database_parent_private"] = _owned_real_directory(
            database_path.parent, exact_mode=0o700
        )
        checks["database_file_private"] = not database_path.exists() or _owned_regular_file(
            database_path, maximum_mode=0o600
        )
        checks["database_no_symlink_components"] = not _has_symlink_component(database_path)

    worker_root = _configured_path(project_root, settings.worker_dependency_root)
    rule_path = (
        _configured_path(project_root, settings.worker_source_root) / "rules" / "docguard_v1.yar"
    )
    checks["worker_dependency_artifact"] = _tree_is_trusted(worker_root)
    checks["yara_rules_private"] = _owned_regular_file(rule_path, maximum_mode=0o644)
    return QualificationReport(checks)


def qualify_database(engine: Engine) -> QualificationReport:
    checks: dict[str, bool] = {}
    try:
        with engine.connect() as connection:
            checks["database_connectivity"] = connection.execute(text("SELECT 1")).scalar() == 1
            revision = connection.execute(text("SELECT version_num FROM alembic_version")).scalar()
            checks["migration_head"] = revision == ALEMBIC_HEAD
            if engine.dialect.name == "sqlite":
                checks["sqlite_foreign_keys"] = (
                    connection.exec_driver_sql("PRAGMA foreign_keys").scalar() == 1
                )
                checks["sqlite_busy_timeout"] = (
                    int(connection.exec_driver_sql("PRAGMA busy_timeout").scalar() or 0) >= 100
                )
                database_name = str(engine.url.database or "")
                journal = str(connection.exec_driver_sql("PRAGMA journal_mode").scalar()).casefold()
                checks["sqlite_journal_mode"] = (
                    journal == "memory" if database_name == ":memory:" else journal == "wal"
                )
                checks["sqlite_synchronous_full"] = (
                    int(connection.exec_driver_sql("PRAGMA synchronous").scalar() or 0) == 2
                )
                checks["sqlite_quick_check"] = (
                    connection.exec_driver_sql("PRAGMA quick_check(1)").scalar() == "ok"
                )
    except Exception:
        checks.setdefault("database_connectivity", False)
    for required in (
        "migration_head",
        "sqlite_foreign_keys",
        "sqlite_busy_timeout",
        "sqlite_journal_mode",
        "sqlite_synchronous_full",
        "sqlite_quick_check",
    ):
        if engine.dialect.name == "sqlite":
            checks.setdefault(required, False)
    return QualificationReport(checks)


def qualify_runtime(settings: Settings, *, project_root: Path) -> QualificationReport:
    checks = {
        "python_runtime": (3, 12) <= sys.version_info[:2] < (3, 15),
        "trusted_dependency_versions": _installed_versions_match(TRUSTED_RUNTIME_VERSIONS),
        "worker_dependency_versions": _artifact_versions_match(
            _configured_path(project_root, settings.worker_dependency_root), WORKER_RUNTIME_VERSIONS
        ),
        "trusted_lock_exact_pins": _lock_is_exact(project_root / "requirements.lock"),
        "worker_lock_exact_pins": _lock_is_exact(project_root / "requirements-worker.lock"),
    }
    return QualificationReport(checks)


def _installed_versions_match(expected: dict[str, str]) -> bool:
    try:
        return all(
            importlib.metadata.version(name) == version for name, version in expected.items()
        )
    except importlib.metadata.PackageNotFoundError:
        return False


def _artifact_versions_match(root: Path, expected: dict[str, str]) -> bool:
    installed = {
        (distribution.metadata["Name"] or "").casefold(): distribution.version
        for distribution in importlib.metadata.distributions(path=[str(root)])
    }
    return all(installed.get(name.casefold()) == version for name, version in expected.items())


def _lock_is_exact(path: Path) -> bool:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return False
    requirements = [
        line.strip() for line in lines if line.strip() and not line.lstrip().startswith("#")
    ]
    return bool(requirements) and all(
        "==" in line
        and not any(operator in line for operator in (">=", "<=", "~=", "!=", "===", "*"))
        for line in requirements
    )


def _configured_path(project_root: Path, path: Path) -> Path:
    return (path if path.is_absolute() else project_root / path).absolute()


def _has_symlink_component(path: Path) -> bool:
    absolute = path.absolute()
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        try:
            if stat.S_ISLNK(current.lstat().st_mode):
                return True
        except FileNotFoundError:
            continue
        except OSError:
            return True
    return False


def _owned_real_directory(
    path: Path, *, exact_mode: int | None = None, maximum_mode: int | None = None
) -> bool:
    try:
        metadata = path.stat(follow_symlinks=False)
    except OSError:
        return False
    mode = stat.S_IMODE(metadata.st_mode)
    return (
        stat.S_ISDIR(metadata.st_mode)
        and not path.is_symlink()
        and metadata.st_uid == os.geteuid()
        and (exact_mode is None or mode == exact_mode)
        and (maximum_mode is None or mode & ~maximum_mode == 0)
    )


def _owned_regular_file(path: Path, *, maximum_mode: int) -> bool:
    try:
        metadata = path.stat(follow_symlinks=False)
    except OSError:
        return False
    return (
        stat.S_ISREG(metadata.st_mode)
        and not path.is_symlink()
        and metadata.st_uid == os.geteuid()
        and stat.S_IMODE(metadata.st_mode) & ~maximum_mode == 0
    )


def _static_is_separate(static_root: Path, storage_root: Path) -> bool:
    if _has_symlink_component(static_root):
        return False
    try:
        static = static_root.resolve(strict=True)
        storage = storage_root.resolve(strict=True)
    except OSError:
        return False
    return not static.is_relative_to(storage) and not storage.is_relative_to(static)


def _tree_is_trusted(root: Path, *, maximum_entries: int = 20_000) -> bool:
    if not _owned_real_directory(root, maximum_mode=0o755) or _has_symlink_component(root):
        return False
    pending = [root]
    observed = 0
    while pending:
        directory = pending.pop()
        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    observed += 1
                    if observed > maximum_entries:
                        return False
                    metadata = entry.stat(follow_symlinks=False)
                    mode = stat.S_IMODE(metadata.st_mode)
                    if metadata.st_uid != os.geteuid() or mode & ~0o755:
                        return False
                    if stat.S_ISDIR(metadata.st_mode):
                        pending.append(Path(entry.path))
                    elif not stat.S_ISREG(metadata.st_mode):
                        return False
        except OSError:
            return False
    return True


__all__ = [
    "ALEMBIC_HEAD",
    "TRUSTED_RUNTIME_VERSIONS",
    "WORKER_RUNTIME_VERSIONS",
    "QualificationReport",
    "qualify_database",
    "qualify_filesystem",
    "qualify_runtime",
]
