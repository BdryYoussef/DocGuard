from __future__ import annotations

from pathlib import Path

import httpx
import pytest
from alembic.config import Config

import app.main as main_module
from alembic import command
from app.core.config import Settings
from app.main import create_app
from tests.auth_helpers import TEST_OPERATOR_PASSWORD


class ReadyBackend:
    ready = True


def _migrate(settings: Settings, revision: str = "head") -> None:
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", settings.database_url)
    command.upgrade(config, revision)


@pytest.mark.asyncio
@pytest.mark.parametrize("unsafe_layout", ["storage_mode", "static_overlap"])
async def test_production_readiness_rejects_unsafe_filesystem_layout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    unsafe_layout: str,
) -> None:
    monkeypatch.setattr(main_module, "create_isolation_backend", lambda settings: ReadyBackend())
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'ready.db'}",
        storage_root=tmp_path / "storage",
        application_origin="https://docguard.example",
    )
    _migrate(settings)
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        app.state.authentication_service.create_operator("operator", TEST_OPERATOR_PASSWORD)
        if unsafe_layout == "storage_mode":
            app.state.storage_paths.root.chmod(0o755)
        else:
            app.state.web_root = app.state.storage_paths.root
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="https://docguard.example"
        ) as client:
            response = await client.get("/health/ready")
    assert response.status_code == 503
    assert response.json() == {"status": "not_ready"}


@pytest.mark.asyncio
async def test_production_readiness_rejects_old_migration_without_details(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(main_module, "create_isolation_backend", lambda settings: ReadyBackend())
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'old.db'}",
        storage_root=tmp_path / "storage",
        application_origin="https://docguard.example",
    )
    _migrate(settings, "0004")
    app = create_app(settings)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="https://docguard.example"
        ) as client,
    ):
        response = await client.get("/health/ready")
    assert response.status_code == 503
    assert response.json() == {"status": "not_ready"}
    assert "0004" not in response.text
