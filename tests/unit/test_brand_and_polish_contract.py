"""Regression guards for the visual-polish + brand-integration passes:

- the DocGuard wordmark image is the sole visible brand lockup on every public
  brand context (no adjacent icon, no separate typed "DocGuard" text duplicating
  its own accessible name) and is served from a version-controlled static path,
  never the absolute source path it was provided at;
- the wordmark has a white derivative for use on the dark chrome surfaces it
  actually appears on (checked for real, sampled contrast at generation time —
  see the asset-generation notes in the final report, not re-derived here);
- the existing compact checkpoint-icon favicon is preserved (a wide wordmark is
  illegible at 16x16), same-origin, no CSP change needed;
- the UI font stack has no remote/CDN font reference — Manrope is served as a
  same-origin static asset (see test_manrope_font_integration.py);
- the native multi-file input stays `multiple` and accessible (clipped, not
  display:none/hidden) even though a designed label is now the visible control;
- findings present the human-facing title before the technical finding code,
  which lives only inside the collapsed technical-details disclosure, and the
  severity indicator stays a small compact chip, never a tall vertical bar.
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
_FAVICON_SRC = "/static/favicon.png"
_WORDMARK_WHITE = "/static/brand/docguard-wordmark-white.png"


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        env=AppEnvironment.TEST,
        database_url=f"sqlite:///{tmp_path / 'brand-contract.db'}",
        storage_root=tmp_path / "storage",
        isolation_backend=IsolationBackendName.UNSAFE_DEVELOPMENT,
        allow_unsafe_development_backend=True,
        application_origin="http://test",
    )


def test_no_absolute_source_path_leaks_into_any_template_or_stylesheet() -> None:
    for path in (*sorted(_TEMPLATES_DIR.rglob("*.html")), _CSS_PATH):
        text = path.read_text(encoding="utf-8")
        assert "/home/" not in text, f"absolute filesystem path leaked into {path}"


def test_wordmark_assets_exist_committed_and_permissioned_like_other_static_files() -> None:
    assets = [
        Path("app/web/static/brand/docguard-wordmark.png"),
        Path("app/web/static/brand/docguard-wordmark-white.png"),
        Path("app/web/static/favicon.png"),
    ]
    for asset in assets:
        assert asset.is_file(), f"missing static asset: {asset}"
    # Same trust posture the production-readiness check enforces on the whole
    # static tree: owner-writable, group/other read-only, no stray write bits.
    for asset in (*assets, assets[0].parent):
        mode = asset.stat().st_mode & 0o777
        assert mode & ~0o755 == 0, f"{asset} has unexpected permission bits: {oct(mode)}"


@pytest.mark.parametrize("template_name", ["base.html", "login.html", "landing.html"])
def test_wordmark_is_the_sole_brand_lockup_no_icon_no_duplicate_text(template_name: str) -> None:
    text = (_TEMPLATES_DIR / template_name).read_text(encoding="utf-8")
    assert f'<link rel="icon" type="image/png" href="{_FAVICON_SRC}">' in text
    assert _WORDMARK_WHITE in text
    assert 'class="wordmark' in text
    # Real accessible name lives on the image's own alt text...
    assert 'alt="DocGuard"' in text
    # ...so a second, separately-rendered "DocGuard" string right beside it would
    # be a redundant duplicate announcement — the old icon+label lockup is gone.
    assert "<span>DocGuard</span>" not in text
    assert 'class="brand-text"' not in text
    # No old checkpoint icon riding along beside the wordmark in the brand lockup.
    brand_lockup = re.search(r'<a class="brand"[^>]*>.*?</a>', text, re.DOTALL)
    assert brand_lockup is not None
    assert "icon_isolation" not in brand_lockup.group(0)
    assert '<img class="icon' not in brand_lockup.group(0)


def test_favicon_is_the_compact_icon_not_the_wide_wordmark() -> None:
    """A horizontal wordmark compressed to 16x16 is illegible; the existing
    checkpoint icon was verified legible at that size and is kept intentionally."""
    text = Path("app/web/templates/base.html").read_text(encoding="utf-8")
    match = re.search(r'<link rel="icon"[^>]*href="([^"]+)"', text)
    assert match is not None
    assert match.group(1) == _FAVICON_SRC
    assert "wordmark" not in match.group(1)


def test_no_remote_font_cdn_or_google_fonts_reference() -> None:
    for path in (*sorted(_TEMPLATES_DIR.rglob("*.html")), _CSS_PATH):
        text = path.read_text(encoding="utf-8")
        assert "fonts.googleapis.com" not in text
        assert "fonts.gstatic.com" not in text
        assert "@import url(" not in text
        assert "use.typekit.net" not in text


def test_technical_monospace_stack_remains_available() -> None:
    css = _CSS_PATH.read_text(encoding="utf-8")
    assert "--font-mono" in css
    # Metadata values (hashes, finding codes, policy versions) still route through
    # the monospace stack; ordinary body copy must not.
    assert ".metadata dd" in css
    metadata_dd_rules = re.findall(r"\.metadata dd\s*\{([^}]*)\}", css)
    assert metadata_dd_rules, "expected at least one .metadata dd rule"
    assert any("var(--font-mono)" in body for body in metadata_dd_rules)


def test_file_input_is_clipped_not_hidden_from_assistive_technology() -> None:
    css = _CSS_PATH.read_text(encoding="utf-8")
    rule = re.search(r'\.drop-zone input\[type="file"\]\s*\{([^}]*)\}', css)
    assert rule is not None
    body = rule.group(1)
    assert "display: none" not in body and "display:none" not in body
    assert "visibility: hidden" not in body and "visibility:hidden" not in body
    assert "clip" in body


@pytest.mark.asyncio
async def test_dashboard_upload_input_remains_multiple_and_labelled(tmp_path: Path) -> None:
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
    input_tag = re.search(r'<input\s+id="document"[^>]*>', text)
    assert input_tag is not None
    tag = input_tag.group(0)
    assert 'type="file"' in tag
    assert "multiple" in tag
    # A real <label for="document"> still exists, associated by id — the visible
    # designed control, not a div/span pretending to be one.
    assert 'for="document"' in text
    assert "<label" in text


@pytest.mark.asyncio
async def test_findings_show_human_title_before_technical_code(tmp_path: Path) -> None:
    from tests.fixtures.pdf_factory import write_malformed_pdf

    app = create_app(_settings(tmp_path))
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client,
    ):
        Base.metadata.create_all(app.state.database_engine)
        csrf = await authenticate_operator(app, client)
        response = await client.post(
            "/api/v1/scans",
            params={"filename": "malformed.pdf"},
            content=write_malformed_pdf(tmp_path / "malformed.pdf").read_bytes(),
            headers={"content-type": "application/pdf", "x-csrf-token": csrf},
        )
        assert response.status_code == 201
        page = await client.get(f"/app/scans/{response.json()['scan_id']}")

    assert page.status_code == 200
    text = page.text
    title_index = text.find("Malformed PDF structure detected")
    code_index = text.find("<code>PDF_MALFORMED</code>")
    assert title_index != -1
    assert code_index != -1
    assert title_index < code_index
    # The code lives inside a collapsed disclosure, not beside the severity chip.
    assert "<summary>Technical details</summary>" in text


def test_severity_chip_stays_a_compact_pill_never_a_tall_vertical_bar() -> None:
    """Regression guard for a real bug: `.finding-row` is a flex row with no
    `align-items` set, so its default `stretch` pulled the severity chip's own
    box up to the full height of the (much taller) finding body next to it,
    rendering as a tall colored vertical capsule instead of a small pill."""
    css = _CSS_PATH.read_text(encoding="utf-8")
    row_rule = re.search(r"\.finding-row\s*\{([^}]*)\}", css)
    assert row_rule is not None
    assert "align-items: flex-start" in row_rule.group(1)
    chip_rule = re.search(r"\.severity-chip\s*\{([^}]*)\}", css)
    assert chip_rule is not None
    chip_body = chip_rule.group(1)
    assert "align-self: flex-start" in chip_body
    height_match = re.search(r"height:\s*(\d+)px", chip_body)
    assert height_match is not None, "severity chip must have an explicit bounded height"
    assert int(height_match.group(1)) <= 24, "severity chip is taller than a compact pill"
