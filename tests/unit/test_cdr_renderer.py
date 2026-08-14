from __future__ import annotations

from pathlib import Path

import pikepdf
import pymupdf
import pytest

from app.cdr.registry import build_worker_cdr_config
from app.core.config import AppEnvironment, Settings
from tests.fixtures.pdf_factory import (
    write_benign_pdf,
    write_encrypted_pdf,
    write_javascript_pdf,
)
from worker import cdr as cdr_module


def render(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    source: Path,
    settings: Settings | None = None,
) -> tuple[dict[str, object], Path]:
    output = tmp_path / "bound-output"
    output.touch(mode=0o600)
    ephemeral = tmp_path / "ephemeral.pdf"
    monkeypatch.setattr(cdr_module, "_OUTPUT_PATH", output)
    monkeypatch.setattr(cdr_module, "_EPHEMERAL_PDF_PATH", ephemeral)
    active_settings = settings or Settings(env=AppEnvironment.TEST)
    request = {"cdr": build_worker_cdr_config(active_settings).model_dump(mode="json")}
    return cdr_module.sanitize_pdf(source, request), output


def test_raster_cdr_preserves_pages_geometry_and_removes_active_structure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = write_javascript_pdf(tmp_path / "active.pdf")
    result, output = render(tmp_path, monkeypatch, source)

    assert result["status"] == "SUCCESS"
    assert result["page_count"] == 1
    assert output.stat().st_size == result["output_bytes"]
    with pikepdf.open(output) as pdf:
        assert len(pdf.pages) == 1
        assert "/OpenAction" not in pdf.Root
        assert "/Names" not in pdf.Root
        assert "/AcroForm" not in pdf.Root
        assert "/Metadata" not in pdf.Root
        assert "/Annots" not in pdf.pages[0].obj
        assert tuple(float(value) for value in pdf.pages[0].MediaBox[2:]) == (612.0, 792.0)
        assert not pdf.docinfo
    with pymupdf.open(output) as rendered:
        assert rendered[0].get_text().strip() == ""


def test_raster_cdr_preserves_multi_page_order_and_count(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = write_benign_pdf(tmp_path / "three.pdf", pages=3)
    result, output = render(tmp_path, monkeypatch, source)

    assert result["status"] == "SUCCESS"
    assert result["page_count"] == 3
    with pikepdf.open(output) as pdf:
        assert len(pdf.pages) == 3


def test_raster_cdr_rejects_encryption_page_pixel_and_output_limits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    encrypted = write_encrypted_pdf(tmp_path / "encrypted.pdf")
    encrypted_result, _ = render(tmp_path, monkeypatch, encrypted)
    assert encrypted_result["failure_code"] == "encrypted"

    two_pages = write_benign_pdf(tmp_path / "two.pdf", pages=2)
    page_limited = Settings(env=AppEnvironment.TEST, cdr_max_pages=1)
    page_result, _ = render(tmp_path, monkeypatch, two_pages, page_limited)
    assert page_result["failure_code"] == "page_limit"

    pixel_limited = Settings(env=AppEnvironment.TEST, cdr_max_pixels_per_page=1)
    pixel_result, _ = render(tmp_path, monkeypatch, two_pages, pixel_limited)
    assert pixel_result["failure_code"] == "pixel_limit"

    output_limited = Settings(env=AppEnvironment.TEST, cdr_max_output_bytes=100)
    output_result, _ = render(tmp_path, monkeypatch, two_pages, output_limited)
    assert output_result["failure_code"] == "output_limit"


def test_sanitizer_fingerprint_changes_with_security_limits() -> None:
    normal = build_worker_cdr_config(Settings(env=AppEnvironment.TEST))
    changed = build_worker_cdr_config(Settings(env=AppEnvironment.TEST, cdr_max_pages=10))

    assert normal.sanitizer_version == changed.sanitizer_version == "1.0.0"
    assert normal.sanitizer_fingerprint != changed.sanitizer_fingerprint
