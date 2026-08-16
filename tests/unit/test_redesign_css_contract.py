"""Source-level regression guards for the frontend redesign's structural
promises: no banned "eyebrow" kicker pattern, a real reduced-motion story (not
just a blanket 0.001ms hack), and no new inline styles/handlers anywhere.

Follows the established precedent (see test_web_icon_and_skip_link_regressions.py):
plain source/markup assertions, no browser dependency.
"""

from __future__ import annotations

import re
from pathlib import Path

import httpx
import pytest

from app.core.config import AppEnvironment, IsolationBackendName, Settings
from app.main import create_app
from app.models.database import Base
from tests.auth_helpers import authenticate_operator

_CSS_PATH = Path("app/web/static/app.css")
_TEMPLATES_DIR = Path("app/web/templates")


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        env=AppEnvironment.TEST,
        database_url=f"sqlite:///{tmp_path / 'css-contract.db'}",
        storage_root=tmp_path / "storage",
        isolation_backend=IsolationBackendName.UNSAFE_DEVELOPMENT,
        allow_unsafe_development_backend=True,
        application_origin="http://test",
    )


def test_no_eyebrow_kicker_class_anywhere() -> None:
    css = _CSS_PATH.read_text(encoding="utf-8")
    assert ".eyebrow" not in css
    for template in _TEMPLATES_DIR.rglob("*.html"):
        assert 'class="eyebrow' not in template.read_text(encoding="utf-8"), template


def test_reduced_motion_is_a_deliberate_static_fallback_not_a_speed_hack() -> None:
    css = _CSS_PATH.read_text(encoding="utf-8")
    # Entrance/stagger keyframes and animations must be declared only under the
    # no-preference query, never unconditionally then "disabled" by shrinking
    # their duration to near-zero everywhere.
    assert "@media (prefers-reduced-motion: no-preference)" in css
    assert "0.001ms" not in css
    no_pref_block = css.split("@media (prefers-reduced-motion: no-preference)", 1)[1]
    assert "enter-up" in no_pref_block
    assert ".motion-enter" in no_pref_block


def test_no_inline_style_or_event_handler_attributes_in_any_template() -> None:
    for template in _TEMPLATES_DIR.rglob("*.html"):
        text = template.read_text(encoding="utf-8")
        assert 'style="' not in text, f"inline style found in {template}"
        assert not re.search(r"\bon\w+=", text), f"inline event handler found in {template}"


def test_motion_tokens_are_centralized_not_scattered_magic_numbers() -> None:
    css = _CSS_PATH.read_text(encoding="utf-8")
    for token in (
        "--ease-out",
        "--ease-in-out",
        "--duration-fast",
        "--duration-standard",
        "--duration-enter",
    ):
        assert css.count(f"{token}:") == 1, f"{token} should be defined exactly once, in :root"


@pytest.mark.asyncio
async def test_dashboard_decision_rail_uses_real_decision_counts_not_fake_metrics(
    tmp_path: Path,
) -> None:
    app = create_app(_settings(tmp_path))
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client,
    ):
        Base.metadata.create_all(app.state.database_engine)
        await authenticate_operator(app, client)
        dashboard = await client.get("/app")

    assert dashboard.status_code == 200
    text = dashboard.text
    assert 'class="rail"' in text
    for decision in ("ALLOW", "REVIEW", "QUARANTINE", "BLOCK"):
        assert f'data-decision="{decision}"' in text
    # Derived/sanitized artifacts are visually and semantically distinct from the
    # four policy decisions, never presented as a fifth decision.
    assert "not a fifth policy decision" in text
    # A freshly-created database has zero scans; the rail must show a real zero,
    # never an invented placeholder count.
    assert ">0<" in text
    assert "17%" not in text and "53%" not in text and "89%" not in text
