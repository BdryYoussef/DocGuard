from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

from app.orchestrator.contract import WorkerRequest

_HOSTILE_PARSER_MODULES = {
    "fitz",
    "defusedxml",
    "magic",
    "olefile",
    "oletools",
    "pdfminer",
    "pikepdf",
    "pypdf",
    "yara",
    "zipfile",
}
_TRUSTED_FRAMEWORK_MODULES = {"fastapi", "pydantic", "sqlalchemy"}


def imported_roots(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(alias.name.partition(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            roots.add(node.module.partition(".")[0])
    return roots


def test_trusted_app_does_not_import_hostile_parser_or_worker_packages() -> None:
    for source in Path("app").rglob("*.py"):
        imports = imported_roots(source)
        assert not imports.intersection(_HOSTILE_PARSER_MODULES), source
        assert "worker" not in imports, source


def test_worker_is_standalone_from_trusted_application_and_frameworks() -> None:
    for source in Path("worker").rglob("*.py"):
        imports = imported_roots(source)
        assert "app" not in imports, source
        assert not imports.intersection(_TRUSTED_FRAMEWORK_MODULES), source


def test_pdf_parser_is_worker_only_in_dependency_manifests() -> None:
    trusted_lock = Path("requirements.lock").read_text(encoding="utf-8").casefold()
    worker_lock = Path("requirements-worker.lock").read_text(encoding="utf-8").casefold()
    project = Path("pyproject.toml").read_text(encoding="utf-8").casefold()

    assert "pikepdf" not in trusted_lock
    assert "pikepdf==10.11.0" in worker_lock
    assert "worker = [" in project


def test_office_parsers_are_worker_only_in_dependency_manifests() -> None:
    trusted_lock = Path("requirements.lock").read_text(encoding="utf-8").casefold()
    worker_lock = Path("requirements-worker.lock").read_text(encoding="utf-8").casefold()

    for package, version in (
        ("oletools", "0.60.2"),
        ("olefile", "0.47"),
        ("defusedxml", "0.7.1"),
    ):
        assert package not in trusted_lock
        assert f"{package}=={version}" in worker_lock


def test_archive_parser_is_worker_only_and_uses_no_extraction_api() -> None:
    source_path = Path("worker/analyzers/archive.py")
    tree = ast.parse(source_path.read_text(encoding="utf-8"), filename=str(source_path))
    called_attributes = {
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    path_constructions = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "Path"
    ]

    assert "extract" not in called_attributes
    assert "extractall" not in called_attributes
    assert path_constructions == []
    assert "zipfile" not in imported_roots(Path("app/orchestrator/service.py"))
    assert "zipfile" not in imported_roots(Path("app/orchestrator/scan_service.py"))


def test_yara_dependency_rules_and_execution_are_worker_only() -> None:
    trusted_lock = Path("requirements.lock").read_text(encoding="utf-8").casefold()
    worker_lock = Path("requirements-worker.lock").read_text(encoding="utf-8").casefold()
    project = Path("pyproject.toml").read_text(encoding="utf-8").casefold()
    worker_source = Path("worker/yara_engine.py").read_text(encoding="utf-8")

    assert "yara-python" not in trusted_lock
    assert "yara-python==4.5.4" in worker_lock
    assert '"yara-python==4.5.4"' in project
    assert "import yara" in worker_source
    assert "yara.compile" in worker_source
    assert "yara.set_config" in worker_source
    assert not any("yara" in imported_roots(path) for path in Path("app").rglob("*.py"))


def test_users_cannot_supply_rules_and_api_has_no_rule_upload_route() -> None:
    assert set(WorkerRequest.model_fields) == {
        "schema_version",
        "job_id",
        "sample_path",
        "original_filename",
        "claimed_content_type",
        "operation",
        "cdr",
    }
    scan_routes = Path("app/api/scans.py").read_text(encoding="utf-8")
    assert "/rules" not in scan_routes.casefold()
    assert "rule_source" not in scan_routes.casefold()
    assert "yara.compile" not in scan_routes.casefold()
    assert list(Path("worker/rules").glob("*.yar")) == [Path("worker/rules/docguard_v1.yar")]


def test_renderer_dependency_and_imports_remain_worker_only() -> None:
    trusted_lock = Path("requirements.lock").read_text(encoding="utf-8").casefold()
    worker_lock = Path("requirements-worker.lock").read_text(encoding="utf-8").casefold()
    app_sources = "\n".join(path.read_text(encoding="utf-8") for path in Path("app").rglob("*.py"))

    assert "pymupdf" not in trusted_lock
    assert "pymupdf==1.28.2" in worker_lock
    assert "import pymupdf" not in app_sources
    assert "import pymupdf" in Path("worker/cdr.py").read_text(encoding="utf-8")


def test_trusted_application_imports_without_pdf_parser_available() -> None:
    environment = {
        "PATH": "/usr/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PYTHONPATH": str(Path(".python-deps").resolve()),
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    completed = subprocess.run(
        [
            sys.executable,
            "-S",
            "-c",
            (
                "import importlib.util, sys; import app.main; "
                "assert importlib.util.find_spec('pikepdf') is None; "
                "assert importlib.util.find_spec('oletools') is None; "
                "assert importlib.util.find_spec('olefile') is None; "
                "assert importlib.util.find_spec('defusedxml') is None; "
                "assert importlib.util.find_spec('yara') is None; "
                "assert not {'pikepdf', 'oletools', 'olefile', 'defusedxml', 'yara'} "
                "& sys.modules.keys()"
            ),
        ],
        cwd=Path.cwd(),
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert completed.returncode == 0, completed.stderr
