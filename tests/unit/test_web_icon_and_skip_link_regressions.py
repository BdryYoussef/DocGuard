"""Narrow regression guards for the Stage A+B visual bug fix.

These do not (and cannot) prove pixel-accurate sizing in a real browser — that was
verified manually per the fix's completion report. They only guard against the exact
class of regression that caused the bug: icon sizing drifting back to a relative unit,
or a template losing its icon/skip-link class hooks. No browser dependency is
introduced; these are plain source/markup assertions.
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
        database_url=f"sqlite:///{tmp_path / 'icons.db'}",
        storage_root=tmp_path / "storage",
        isolation_backend=IsolationBackendName.UNSAFE_DEVELOPMENT,
        allow_unsafe_development_backend=True,
        application_origin="http://test",
    )


def test_icon_class_never_uses_a_relative_font_size_unit() -> None:
    """The root cause of the oversized-icon regression: `.icon { width: 1.1em }`
    resolves inconsistently across browsers. Icon sizing must always be a fixed
    pixel value so it can never inflate with an inherited font-size."""
    css = _CSS_PATH.read_text(encoding="utf-8")
    icon_rules = re.findall(r"\.icon\s*\{[^}]*\}|\.[\w-]+\s+\.icon\s*\{[^}]*\}", css)
    assert icon_rules, "expected at least one .icon CSS rule"
    for rule in icon_rules:
        assert "em;" not in rule and "em }" not in rule, f"relative unit found in: {rule}"
        assert "rem" not in rule, f"relative unit found in: {rule}"


def test_icon_sizes_stay_within_the_approved_enterprise_scale() -> None:
    """Every explicit icon-size rule must fall inside the prescribed ranges, so a
    future edit cannot silently reintroduce an oversized icon."""
    css = _CSS_PATH.read_text(encoding="utf-8")
    bounds = {
        r"\.topbar nav a \.icon": (18, 22),
        r"\.button \.icon": (16, 18),
        r"\.operator-identity \.icon": (20, 24),
    }
    for selector, (low, high) in bounds.items():
        match = re.search(selector + r"\s*\{\s*width:\s*(\d+)px", css)
        assert match, f"expected an explicit pixel width rule for {selector}"
        size = int(match.group(1))
        assert low <= size <= high, f"{selector} is {size}px, expected {low}-{high}px"


def test_wordmark_dimensions_are_explicit_pixels_within_the_approved_scale() -> None:
    """The brand lockup is now the wordmark image itself (no icon). Its intrinsic
    width/height attributes must be explicit pixels (never a relative unit — that
    was the exact class of the original icon-sizing regression) and stay within a
    deliberately narrow, intentional range, never so large it distorts the navbar."""
    bounds = {
        "base.html": (110, 145),
        "login.html": (135, 165),
        "landing.html": (110, 145),
    }
    for template_name, (low, high) in bounds.items():
        text = (_TEMPLATES_DIR / template_name).read_text(encoding="utf-8")
        match = re.search(
            r'<img class="wordmark[^"]*"[^>]*\bwidth="(\d+)"[^>]*\bheight="(\d+)"', text
        )
        assert match, f"expected an explicit-dimension .wordmark <img> in {template_name}"
        width, height = int(match.group(1)), int(match.group(2))
        assert low <= width <= high, (
            f"{template_name} wordmark is {width}px wide, expected {low}-{high}px"
        )
        # Aspect ratio must stay close to the source asset's (~4.5:1) — no distortion.
        assert 4.0 <= width / height <= 5.0, (
            f"{template_name} wordmark aspect ratio looks distorted"
        )


def test_topbar_uses_min_height_not_a_fixed_height() -> None:
    """A fixed `height` on the topbar cannot grow when the mobile nav wraps to
    multiple rows, clipping content below the header's own background box. This
    guards against reintroducing that specific regression."""
    css = _CSS_PATH.read_text(encoding="utf-8")
    topbar_rule = re.search(r"\.topbar\s*\{([^}]*)\}", css)
    assert topbar_rule is not None
    body = topbar_rule.group(1)
    assert "min-height" in body
    assert re.search(r"(?<!min-)height:\s*\d", body) is None


def test_skip_link_is_clipped_not_moved_off_canvas_and_never_display_none() -> None:
    css = _CSS_PATH.read_text(encoding="utf-8")
    skip_rule = re.search(r"\.skip-link\s*\{([^}]*)\}", css)
    assert skip_rule is not None
    body = skip_rule.group(1)
    assert "display: none" not in body
    assert "display:none" not in body
    assert "visibility: hidden" not in body
    assert "clip" in body
    focus_rule = re.search(r"\.skip-link:focus\s*\{([^}]*)\}", css)
    assert focus_rule is not None
    assert "clip: auto" in focus_rule.group(1) or "clip:auto" in focus_rule.group(1)


def test_no_inline_style_or_event_handler_attributes_in_any_template() -> None:
    """The fix must stay CSP-compatible: no inline style/script workaround."""
    for template in _TEMPLATES_DIR.rglob("*.html"):
        text = template.read_text(encoding="utf-8")
        assert 'style="' not in text, f"inline style found in {template}"
        assert not re.search(r"\bon\w+=", text), f"inline event handler found in {template}"


@pytest.mark.asyncio
async def test_rendered_pages_carry_icon_class_and_skip_link(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path))
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client,
    ):
        Base.metadata.create_all(app.state.database_engine)
        landing = await client.get("/")
        login = await client.get("/login")
        csrf = await authenticate_operator(app, client)
        del csrf
        dashboard = await client.get("/app")

    for page in (landing, login, dashboard):
        assert 'class="skip-link"' in page.text
        assert 'class="icon"' in page.text
        assert "content-security-policy" in page.headers
        assert "unsafe-inline" not in page.headers["content-security-policy"]
