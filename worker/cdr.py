"""Destructive raster-only PDF reconstruction inside the hostile-input worker."""

from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path
from time import monotonic_ns

import pymupdf

from docguard_contract import ANALYSIS_SCHEMA_VERSION
from docguard_contract.cdr import (
    PDF_CDR_COLORSPACE,
    PDF_CDR_ENGINE_VERSION,
    PDF_CDR_METADATA_POLICY,
    PDF_CDR_OUTPUT_MODE,
    PDF_CDR_RENDERER,
    PDF_CDR_RENDERER_VERSION,
    PDF_CDR_VERSION,
)

_OUTPUT_PATH = Path("/output/document")
_EPHEMERAL_PDF_PATH = Path("/work/reconstructed.pdf")
_CONFIG_KEYS = frozenset(
    {
        "sanitizer_version",
        "sanitizer_fingerprint",
        "dpi",
        "max_pages",
        "max_width_points",
        "max_height_points",
        "max_width_pixels",
        "max_height_pixels",
        "max_pixels_per_page",
        "max_total_pixels",
        "max_raster_bytes",
        "max_output_bytes",
    }
)


class ControlledCdrFailure(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def sanitize_pdf(sample_path: Path, request: dict[str, object]) -> dict[str, object]:
    started_ns = monotonic_ns()
    config = _validated_config(request.get("cdr"))
    page_count = 0
    total_pixels = 0
    try:
        if not _OUTPUT_PATH.is_file():
            raise ControlledCdrFailure("render_failed")
        with pymupdf.open(sample_path) as source:  # type: ignore[no-untyped-call]
            if source.needs_pass:
                raise ControlledCdrFailure("encrypted")
            page_count = source.page_count
            if page_count < 1 or page_count > _integer(config, "max_pages"):
                raise ControlledCdrFailure("page_limit")
            output = pymupdf.open()  # type: ignore[no-untyped-call]
            try:
                for page_index in range(page_count):
                    source_page = source.load_page(page_index)
                    rect = source_page.rect
                    width_points = float(rect.width)
                    height_points = float(rect.height)
                    if (
                        not math.isfinite(width_points)
                        or not math.isfinite(height_points)
                        or width_points <= 0
                        or height_points <= 0
                        or width_points > _number(config, "max_width_points")
                        or height_points > _number(config, "max_height_points")
                    ):
                        raise ControlledCdrFailure("pixel_limit")
                    dpi = _integer(config, "dpi")
                    width_pixels = math.ceil(width_points * dpi / 72)
                    height_pixels = math.ceil(height_points * dpi / 72)
                    pixels = width_pixels * height_pixels
                    total_pixels += pixels
                    if (
                        width_pixels > _integer(config, "max_width_pixels")
                        or height_pixels > _integer(config, "max_height_pixels")
                        or pixels > _integer(config, "max_pixels_per_page")
                        or total_pixels > _integer(config, "max_total_pixels")
                        or total_pixels * 3 > _integer(config, "max_raster_bytes")
                    ):
                        raise ControlledCdrFailure("pixel_limit")
                    pixmap = source_page.get_pixmap(
                        dpi=dpi,
                        colorspace=pymupdf.csRGB,
                        alpha=False,
                        annots=False,
                    )
                    if (pixmap.width != width_pixels or pixmap.height != height_pixels) and (
                        pixmap.width > _integer(config, "max_width_pixels")
                        or pixmap.height > _integer(config, "max_height_pixels")
                    ):
                        raise ControlledCdrFailure("pixel_limit")
                    output_page = output.new_page(width=width_points, height=height_points)
                    output_page.insert_image(  # type: ignore[no-untyped-call]
                        output_page.rect, pixmap=pixmap, keep_proportion=False
                    )
                output.set_metadata({})
                output.save(  # type: ignore[no-untyped-call]
                    _EPHEMERAL_PDF_PATH,
                    garbage=4,
                    clean=True,
                    deflate=True,
                    deflate_images=True,
                    no_new_id=True,
                    preserve_metadata=False,
                    use_objstms=1,
                    reproducible=True,
                )
            finally:
                output.close()  # type: ignore[no-untyped-call]
        output_bytes = _EPHEMERAL_PDF_PATH.stat().st_size
        if output_bytes < 1 or output_bytes > _integer(config, "max_output_bytes"):
            raise ControlledCdrFailure("output_limit")
        with _EPHEMERAL_PDF_PATH.open("rb") as source, _OUTPUT_PATH.open("r+b") as target:
            copied = 0
            while chunk := source.read(64 * 1024):
                copied += len(chunk)
                if copied > _integer(config, "max_output_bytes"):
                    raise ControlledCdrFailure("output_limit")
                target.write(chunk)
            target.truncate()
            target.flush()
        if copied != output_bytes:
            raise ControlledCdrFailure("render_failed")
        return _result(
            config,
            started_ns=started_ns,
            status="SUCCESS",
            page_count=page_count,
            total_pixels=total_pixels,
            output_bytes=output_bytes,
            failure_code=None,
        )
    except ControlledCdrFailure as exc:
        return _result(
            config,
            started_ns=started_ns,
            status="FAILED",
            page_count=page_count,
            total_pixels=total_pixels,
            output_bytes=_bounded_output_size(config),
            failure_code=exc.code,
        )
    except (OSError, RuntimeError, ValueError, pymupdf.FileDataError, pymupdf.mupdf.FzErrorBase):
        return _result(
            config,
            started_ns=started_ns,
            status="FAILED",
            page_count=page_count,
            total_pixels=total_pixels,
            output_bytes=_bounded_output_size(config),
            failure_code="malformed",
        )


def _validated_config(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != _CONFIG_KEYS:
        raise ValueError("invalid CDR configuration")
    config = dict(value)
    if config.get("sanitizer_version") != PDF_CDR_VERSION:
        raise ValueError("unsupported sanitizer version")
    definition = {
        "colorspace": PDF_CDR_COLORSPACE,
        "dpi": _integer(config, "dpi"),
        "engine_version": PDF_CDR_ENGINE_VERSION,
        "max_height_pixels": _integer(config, "max_height_pixels"),
        "max_height_points": _number(config, "max_height_points"),
        "max_output_bytes": _integer(config, "max_output_bytes"),
        "max_pages": _integer(config, "max_pages"),
        "max_pixels_per_page": _integer(config, "max_pixels_per_page"),
        "max_raster_bytes": _integer(config, "max_raster_bytes"),
        "max_total_pixels": _integer(config, "max_total_pixels"),
        "max_width_pixels": _integer(config, "max_width_pixels"),
        "max_width_points": _number(config, "max_width_points"),
        "metadata_policy": PDF_CDR_METADATA_POLICY,
        "output_mode": PDF_CDR_OUTPUT_MODE,
        "renderer": PDF_CDR_RENDERER,
        "renderer_version": PDF_CDR_RENDERER_VERSION,
        "sanitizer_version": PDF_CDR_VERSION,
    }
    payload = json.dumps(definition, separators=(",", ":"), sort_keys=True).encode("utf-8")
    if config.get("sanitizer_fingerprint") != hashlib.sha256(payload).hexdigest():
        raise ValueError("sanitizer fingerprint mismatch")
    return config


def _integer(config: dict[str, object], key: str) -> int:
    value = config.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{key} must be an integer")
    return value


def _number(config: dict[str, object], key: str) -> float:
    value = config.get(key)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{key} must be numeric")
    return float(value)


def _bounded_output_size(config: dict[str, object]) -> int:
    try:
        size = _OUTPUT_PATH.stat().st_size
    except OSError:
        return 0
    return min(size, _integer(config, "max_output_bytes"))


def _result(
    config: dict[str, object],
    *,
    started_ns: int,
    status: str,
    page_count: int,
    total_pixels: int,
    output_bytes: int,
    failure_code: str | None,
) -> dict[str, object]:
    return {
        "schema_version": ANALYSIS_SCHEMA_VERSION,
        "operation": "SANITIZE_PDF",
        "status": status,
        "sanitizer_version": PDF_CDR_VERSION,
        "sanitizer_fingerprint": config["sanitizer_fingerprint"],
        "renderer_version": pymupdf.VersionBind,
        "engine_version": pymupdf.VersionFitz,
        "page_count": page_count,
        "total_pixels": total_pixels,
        "output_bytes": output_bytes,
        "duration_ms": max(0, (monotonic_ns() - started_ns) // 1_000_000),
        "failure_code": failure_code,
    }


__all__ = ["sanitize_pdf"]
