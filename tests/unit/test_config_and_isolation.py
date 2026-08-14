from dataclasses import fields, replace
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.core.config import AppEnvironment, IsolationBackendName, Settings
from app.orchestrator.isolation import (
    IsolationUnavailable,
    SandboxSelfTest,
    UnsafeDevelopmentBackend,
)


def test_unsafe_backend_requires_explicit_flag() -> None:
    with pytest.raises(ValidationError, match="explicit opt-in"):
        Settings(
            env=AppEnvironment.TEST,
            isolation_backend=IsolationBackendName.UNSAFE_DEVELOPMENT,
        )


def test_unsafe_backend_rejected_in_production() -> None:
    with pytest.raises(ValidationError, match="forbidden in production"):
        Settings(
            env=AppEnvironment.PRODUCTION,
            isolation_backend=IsolationBackendName.UNSAFE_DEVELOPMENT,
            allow_unsafe_development_backend=True,
        )


def test_backend_constructor_rechecks_production_policy(tmp_path: Path) -> None:
    production = Settings()
    with pytest.raises(IsolationUnavailable, match="forbidden in production"):
        UnsafeDevelopmentBackend(production, project_root=tmp_path)


def test_explicit_development_backend_emits_critical_warning(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    settings = Settings(
        env=AppEnvironment.TEST,
        isolation_backend=IsolationBackendName.UNSAFE_DEVELOPMENT,
        allow_unsafe_development_backend=True,
    )

    with caplog.at_level("CRITICAL"):
        backend = UnsafeDevelopmentBackend(settings, project_root=tmp_path)

    assert backend.ready is True
    assert "UNSAFE_DEVELOPMENT_BACKEND_ENABLED" in caplog.text


def test_yara_qualification_is_required_for_sandbox_readiness() -> None:
    values = {item.name: True for item in fields(SandboxSelfTest) if item.name != "diagnostics"}
    qualified = SandboxSelfTest(**values)  # type: ignore[arg-type]

    assert qualified.passed
    assert not replace(qualified, yara_rule_pack_qualifies=False).passed
    assert not replace(qualified, yara_rules_read_only=False).passed
    assert not replace(qualified, renderer_runtime_loads=False).passed
    assert not replace(qualified, worker_dependencies_load=False).passed
