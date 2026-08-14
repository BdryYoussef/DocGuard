"""Fixed PDF CDR identity and worker-side bounds shared across the trust boundary."""

from __future__ import annotations

import hashlib
import json

PDF_CDR_VERSION = "1.0.0"
PDF_CDR_RENDERER = "PyMuPDF"
PDF_CDR_RENDERER_VERSION = "1.28.2"
PDF_CDR_ENGINE_VERSION = "1.28.2"
PDF_CDR_DPI = 150
PDF_CDR_COLORSPACE = "RGB"
PDF_CDR_MAX_PAGES = 100
PDF_CDR_MAX_WIDTH_POINTS = 2_000.0
PDF_CDR_MAX_HEIGHT_POINTS = 2_000.0
PDF_CDR_MAX_WIDTH_PIXELS = 4_200
PDF_CDR_MAX_HEIGHT_PIXELS = 4_200
PDF_CDR_MAX_PIXELS_PER_PAGE = 16_000_000
PDF_CDR_MAX_TOTAL_PIXELS = 80_000_000
PDF_CDR_MAX_RASTER_BYTES = 240_000_000
PDF_CDR_MAX_OUTPUT_BYTES = 64 * 1024 * 1024
PDF_CDR_METADATA_POLICY = "minimal-empty"
PDF_CDR_OUTPUT_MODE = "raster-images-only"


def sanitizer_definition() -> dict[str, object]:
    return {
        "colorspace": PDF_CDR_COLORSPACE,
        "dpi": PDF_CDR_DPI,
        "engine_version": PDF_CDR_ENGINE_VERSION,
        "max_height_pixels": PDF_CDR_MAX_HEIGHT_PIXELS,
        "max_height_points": PDF_CDR_MAX_HEIGHT_POINTS,
        "max_output_bytes": PDF_CDR_MAX_OUTPUT_BYTES,
        "max_pages": PDF_CDR_MAX_PAGES,
        "max_pixels_per_page": PDF_CDR_MAX_PIXELS_PER_PAGE,
        "max_raster_bytes": PDF_CDR_MAX_RASTER_BYTES,
        "max_total_pixels": PDF_CDR_MAX_TOTAL_PIXELS,
        "max_width_pixels": PDF_CDR_MAX_WIDTH_PIXELS,
        "max_width_points": PDF_CDR_MAX_WIDTH_POINTS,
        "metadata_policy": PDF_CDR_METADATA_POLICY,
        "output_mode": PDF_CDR_OUTPUT_MODE,
        "renderer": PDF_CDR_RENDERER,
        "renderer_version": PDF_CDR_RENDERER_VERSION,
        "sanitizer_version": PDF_CDR_VERSION,
    }


def compute_sanitizer_fingerprint() -> str:
    payload = json.dumps(sanitizer_definition(), separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


PDF_CDR_FINGERPRINT = compute_sanitizer_fingerprint()

__all__ = [name for name in globals() if name.startswith("PDF_CDR_")] + [
    "compute_sanitizer_fingerprint",
    "sanitizer_definition",
]
