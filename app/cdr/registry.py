"""Trusted sanitizer configuration and deterministic identity."""

from __future__ import annotations

import hashlib
import json

from app.core.config import Settings
from app.orchestrator.contract import PdfCdrRequestConfig
from docguard_contract.cdr import (
    PDF_CDR_COLORSPACE,
    PDF_CDR_DPI,
    PDF_CDR_ENGINE_VERSION,
    PDF_CDR_METADATA_POLICY,
    PDF_CDR_OUTPUT_MODE,
    PDF_CDR_RENDERER,
    PDF_CDR_RENDERER_VERSION,
    PDF_CDR_VERSION,
)


def sanitizer_definition(settings: Settings) -> dict[str, object]:
    return {
        "colorspace": PDF_CDR_COLORSPACE,
        "dpi": PDF_CDR_DPI,
        "engine_version": PDF_CDR_ENGINE_VERSION,
        "max_height_pixels": settings.cdr_max_height_pixels,
        "max_height_points": settings.cdr_max_height_points,
        "max_output_bytes": settings.cdr_max_output_bytes,
        "max_pages": settings.cdr_max_pages,
        "max_pixels_per_page": settings.cdr_max_pixels_per_page,
        "max_raster_bytes": settings.cdr_max_raster_bytes,
        "max_total_pixels": settings.cdr_max_total_pixels,
        "max_width_pixels": settings.cdr_max_width_pixels,
        "max_width_points": settings.cdr_max_width_points,
        "metadata_policy": PDF_CDR_METADATA_POLICY,
        "output_mode": PDF_CDR_OUTPUT_MODE,
        "renderer": PDF_CDR_RENDERER,
        "renderer_version": PDF_CDR_RENDERER_VERSION,
        "sanitizer_version": PDF_CDR_VERSION,
    }


def sanitizer_fingerprint(settings: Settings) -> str:
    encoded = json.dumps(sanitizer_definition(settings), separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def build_worker_cdr_config(settings: Settings) -> PdfCdrRequestConfig:
    return PdfCdrRequestConfig(
        sanitizer_version=PDF_CDR_VERSION,
        sanitizer_fingerprint=sanitizer_fingerprint(settings),
        dpi=PDF_CDR_DPI,
        max_pages=settings.cdr_max_pages,
        max_width_points=settings.cdr_max_width_points,
        max_height_points=settings.cdr_max_height_points,
        max_width_pixels=settings.cdr_max_width_pixels,
        max_height_pixels=settings.cdr_max_height_pixels,
        max_pixels_per_page=settings.cdr_max_pixels_per_page,
        max_total_pixels=settings.cdr_max_total_pixels,
        max_raster_bytes=settings.cdr_max_raster_bytes,
        max_output_bytes=settings.cdr_max_output_bytes,
    )


def sanitizer_registry_is_valid(settings: Settings) -> bool:
    try:
        config = build_worker_cdr_config(settings)
    except ValueError:
        return False
    return len(config.sanitizer_fingerprint) == 64


__all__ = [
    "build_worker_cdr_config",
    "sanitizer_definition",
    "sanitizer_fingerprint",
    "sanitizer_registry_is_valid",
]
