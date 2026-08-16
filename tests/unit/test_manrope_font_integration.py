"""Regression guards for the local Manrope font integration:

- the variable font file and its OFL license are committed, same-origin static
  assets, permissioned like the rest of the static tree;
- the stylesheet declares Manrope via a local @font-face (no remote src) and
  makes it the primary UI font, while the existing technical monospace stack
  is left untouched;
- no template or stylesheet gained a remote font reference of any kind;
- the DocGuard wordmark image remains the brand — this task did not replace
  it with typed Manrope text.
"""

from __future__ import annotations

import re
from pathlib import Path

_CSS_PATH = Path("app/web/static/app.css")
_TEMPLATES_DIR = Path("app/web/templates")
_FONT_PATH = Path("app/web/static/fonts/Manrope-VariableFont_wght.ttf")
_LICENSE_PATH = Path("app/web/static/fonts/OFL.txt")


def test_manrope_font_and_license_are_committed_static_assets_with_trusted_permissions() -> None:
    for asset in (_FONT_PATH, _LICENSE_PATH, _FONT_PATH.parent):
        assert asset.exists(), f"missing static asset: {asset}"
        mode = asset.stat().st_mode & 0o777
        assert mode & ~0o755 == 0, f"{asset} has unexpected permission bits: {oct(mode)}"
    license_text = _LICENSE_PATH.read_text(encoding="utf-8")
    assert "SIL Open Font License" in license_text


def test_font_face_declares_manrope_from_a_local_same_origin_path() -> None:
    css = _CSS_PATH.read_text(encoding="utf-8")
    rule = re.search(r"@font-face\s*\{([^}]*)\}", css)
    assert rule is not None, "expected a @font-face rule"
    body = rule.group(1)
    assert '"Manrope"' in body
    assert 'url("/static/fonts/Manrope-VariableFont_wght.ttf")' in body
    assert "font-display: swap" in body
    # The variable font's actual axis range (verified against the binary at
    # integration time), not a guess — never wider than what the file supports.
    weight_match = re.search(r"font-weight:\s*(\d+)\s+(\d+)", body)
    assert weight_match is not None
    assert int(weight_match.group(1)) == 200
    assert int(weight_match.group(2)) == 800


def test_no_remote_font_reference_anywhere() -> None:
    for path in (*sorted(_TEMPLATES_DIR.rglob("*.html")), _CSS_PATH):
        text = path.read_text(encoding="utf-8")
        assert "fonts.googleapis.com" not in text
        assert "fonts.gstatic.com" not in text
        assert "@import url(" not in text
        assert "use.typekit.net" not in text
        assert not re.search(r'@font-face\s*\{[^}]*url\(\s*["\']?https?://', text)


def test_ui_font_stack_uses_manrope_first() -> None:
    css = _CSS_PATH.read_text(encoding="utf-8")
    match = re.search(r"--font-sans:\s*([^;]+);", css)
    assert match is not None
    assert match.group(1).strip().startswith('"Manrope"')


def test_form_controls_inherit_the_ui_font_instead_of_the_browser_default() -> None:
    css = _CSS_PATH.read_text(encoding="utf-8")
    rule = re.search(r"button,\s*input,\s*select,\s*textarea\s*\{([^}]*)\}", css)
    assert rule is not None
    assert "font-family: inherit" in rule.group(1)


def test_technical_monospace_stack_is_unaffected_by_the_font_swap() -> None:
    css = _CSS_PATH.read_text(encoding="utf-8")
    match = re.search(r"--font-mono:\s*([^;]+);", css)
    assert match is not None
    assert "Manrope" not in match.group(1)


def test_wordmark_image_remains_the_brand_not_typed_manrope_text() -> None:
    for template_name in ("base.html", "login.html", "landing.html"):
        text = (_TEMPLATES_DIR / template_name).read_text(encoding="utf-8")
        assert 'class="wordmark' in text
        brand_lockup = re.search(r'<a class="brand"[^>]*>.*?</a>', text, re.DOTALL)
        assert brand_lockup is not None
        assert "<span>DocGuard</span>" not in brand_lockup.group(0)


def test_csp_still_allows_same_origin_fonts_without_widening_it() -> None:
    security = Path("app/web/security.py").read_text(encoding="utf-8")
    assert "font-src 'self'" in security
    assert "fonts.googleapis.com" not in security
    assert "fonts.gstatic.com" not in security
