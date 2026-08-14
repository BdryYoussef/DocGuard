from pathlib import Path

import httpx
import pytest
from alembic.config import Config

import app.api.health as health_module
import app.policies.registry as registry_module
from alembic import command
from app.core.config import AppEnvironment, IsolationBackendName, Settings
from app.main import create_app
from app.models.database import Base
from app.orchestrator.contract import WorkerRequest
from app.orchestrator.isolation import WorkerExecution
from app.policies.registry import FINDING_POLICIES
from tests.auth_helpers import TEST_OPERATOR_PASSWORD


class FailedSelfTestBackend:
    @property
    def ready(self) -> bool:
        return False

    def execute(self, request: WorkerRequest, timeout_seconds: float) -> WorkerExecution:
        del request, timeout_seconds
        raise AssertionError("unready backend must not execute")


class PassingSelfTestBackend(FailedSelfTestBackend):
    @property
    def ready(self) -> bool:
        return True


@pytest.mark.asyncio
async def test_health_live_and_ready(tmp_path: Path) -> None:
    settings = Settings(
        env=AppEnvironment.TEST,
        database_url=f"sqlite:///{tmp_path / 'health.db'}",
        storage_root=tmp_path / "storage",
        isolation_backend=IsolationBackendName.UNSAFE_DEVELOPMENT,
        allow_unsafe_development_backend=True,
    )

    app = create_app(settings)
    transport = httpx.ASGITransport(app=app)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=transport, base_url="https://127.0.0.1:8000") as client,
    ):
        Base.metadata.create_all(app.state.database_engine)
        live = await client.get("/health/live")
        ready = await client.get("/health/ready")

    assert live.status_code == 200
    assert live.json() == {"status": "alive"}
    assert ready.status_code == 200
    assert ready.json()["status"] == "ready"
    assert all(ready.json()["checks"].values())


@pytest.mark.asyncio
async def test_readiness_fails_closed_when_sandbox_self_test_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import app.main as main_module

    monkeypatch.setattr(
        main_module, "create_isolation_backend", lambda settings: FailedSelfTestBackend()
    )
    settings = Settings(
        env=AppEnvironment.PRODUCTION,
        database_url=f"sqlite:///{tmp_path / 'health.db'}",
        storage_root=tmp_path / "storage",
        isolation_backend=IsolationBackendName.BUBBLEWRAP,
    )

    app = create_app(settings)
    transport = httpx.ASGITransport(app=app)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=transport, base_url="https://127.0.0.1:8000") as client,
    ):
        response = await client.get("/health/ready")

    assert response.status_code == 503
    assert response.json() == {"status": "not_ready"}


@pytest.mark.asyncio
async def test_production_readiness_requires_active_operator_without_disclosing_details(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import app.main as main_module

    monkeypatch.setattr(
        main_module, "create_isolation_backend", lambda settings: PassingSelfTestBackend()
    )
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'auth-ready.db'}",
        storage_root=tmp_path / "storage",
    )
    migration = Config("alembic.ini")
    migration.set_main_option("sqlalchemy.url", settings.database_url)
    command.upgrade(migration, "head")
    app = create_app(settings)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="https://127.0.0.1:8000"
        ) as client,
    ):
        before_bootstrap = await client.get("/health/ready")
        assert before_bootstrap.status_code == 503
        assert before_bootstrap.json() == {"status": "not_ready"}
        app.state.authentication_service.create_operator(
            "production-operator", TEST_OPERATOR_PASSWORD
        )
        after_bootstrap = await client.get("/health/ready")
        assert after_bootstrap.status_code == 200
        assert after_bootstrap.json() == {"status": "ready"}


@pytest.mark.asyncio
async def test_readiness_fails_closed_when_policy_registry_is_incomplete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    incomplete = dict(FINDING_POLICIES)
    incomplete.pop("PDF_JAVASCRIPT")
    monkeypatch.setattr(registry_module, "FINDING_POLICIES", incomplete)
    settings = Settings(
        env=AppEnvironment.TEST,
        database_url=f"sqlite:///{tmp_path / 'health.db'}",
        storage_root=tmp_path / "storage",
        isolation_backend=IsolationBackendName.UNSAFE_DEVELOPMENT,
        allow_unsafe_development_backend=True,
    )
    app = create_app(settings)
    transport = httpx.ASGITransport(app=app)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=transport, base_url="http://test") as client,
    ):
        Base.metadata.create_all(app.state.database_engine)
        response = await client.get("/health/ready")

    assert response.status_code == 503
    assert response.json()["checks"]["policy_registry"] is False


@pytest.mark.asyncio
async def test_readiness_fails_closed_when_sanitizer_registry_is_invalid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(health_module, "sanitizer_registry_is_valid", lambda settings: False)
    settings = Settings(
        env=AppEnvironment.TEST,
        database_url=f"sqlite:///{tmp_path / 'health.db'}",
        storage_root=tmp_path / "storage",
        isolation_backend=IsolationBackendName.UNSAFE_DEVELOPMENT,
        allow_unsafe_development_backend=True,
    )
    app = create_app(settings)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client,
    ):
        Base.metadata.create_all(app.state.database_engine)
        response = await client.get("/health/ready")

    assert response.status_code == 503
    assert response.json()["checks"]["sanitizer_registry"] is False
