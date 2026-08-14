"""Bounded static VBA metadata extraction using worker-only oletools."""

from __future__ import annotations

import logging
import struct
import unicodedata
from dataclasses import dataclass, field
from typing import Any

import olefile
from oletools import olevba

from worker.analyzers.office_types import OfficeAnalysisLimits, OfficeApplication
from worker.constants import OFFICE_OLE_PARSER_VERSION, OFFICE_VBA_PARSER_VERSION

_AUTOEXEC_NAMES = frozenset(
    {
        "auto_close",
        "auto_open",
        "autoclose",
        "autoexec",
        "autoexit",
        "autonew",
        "autoopen",
        "document_beforeclose",
        "document_close",
        "document_new",
        "document_open",
        "presentation_open",
        "presentation_slideshowbegin",
        "workbook_activate",
        "workbook_beforeclose",
        "workbook_close",
        "workbook_open",
        "worksheet_calculate",
    }
)
_EXECUTION_INDICATORS: dict[str, str] = {
    "cmd.exe": "command_shell",
    "create": "process_creation",
    "createobject": "com_object_creation",
    "encodedcommand": "powershell",
    "invoke-command": "powershell",
    "invoke-expression": "powershell",
    "powershell": "powershell",
    "run": "process_launch",
    "scripting.filesystemobject": "scripting_host",
    "shell": "process_launch",
    "shell.application": "process_launch",
    "shellexecute": "process_launch",
    "start-process": "powershell",
    "wscript.shell": "scripting_host",
}
_EXPECTED_ERRORS = (
    IndexError,
    KeyError,
    OSError,
    RuntimeError,
    TypeError,
    UnicodeError,
    ValueError,
    struct.error,
    olevba.FileOpenError,
)
_BIDI_CONTROLS = frozenset("\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")


@dataclass(slots=True)
class VbaAnalysis:
    macro_detected: bool = False
    project_count: int = 0
    module_count: int = 0
    source_bytes_inspected: int = 0
    module_names: list[str] = field(default_factory=list)
    autoexec_triggers: set[str] = field(default_factory=set)
    indicator_classes: set[str] = field(default_factory=set)
    indicator_names: set[str] = field(default_factory=set)
    partial_reasons: set[str] = field(default_factory=set)
    parser_exception: str | None = None


def analyze_vba_blob(
    data: bytes,
    *,
    display_name: str,
    application: OfficeApplication,
    limits: OfficeAnalysisLimits,
) -> VbaAnalysis:
    del application  # olevba determines supported VBA semantics from the project itself.
    result = VbaAnalysis()
    result.project_count = 1
    if len(data) > limits.max_vba_project_bytes:
        result.partial_reasons.add("vba_project_size_limit")
        return result
    if olevba.__version__ != OFFICE_VBA_PARSER_VERSION or olefile.__version__ != (
        OFFICE_OLE_PARSER_VERSION
    ):
        raise RuntimeError("unexpected Office parser version")

    parser: Any | None = None
    loggers = [logging.getLogger(name) for name in ("oletools", "olevba", "olefile")]
    prior_disabled = [logger.disabled for logger in loggers]
    for logger in loggers:
        logger.disabled = True
    try:
        parser = olevba.VBA_Parser(
            display_name,
            data=data,
            relaxed=False,
            disable_pcode=True,
        )
        parser.no_xlm = True
        result.macro_detected = bool(parser.detect_vba_macros())
        if not result.macro_detected:
            return result
        projects = getattr(parser, "vba_projects", None)
        if isinstance(projects, list):
            result.project_count = max(1, len(projects))
            if not projects:
                result.partial_reasons.add("orphan_vba_stream")
        for module_index, (_, _, module_name, source) in enumerate(parser.extract_macros()):
            if module_index >= limits.max_vba_modules:
                result.partial_reasons.add("vba_module_limit")
                break
            source_text = _source_text(source)
            encoded = source_text.encode("utf-8", errors="replace")
            remaining = limits.max_vba_source_bytes - result.source_bytes_inspected
            if remaining <= 0:
                result.partial_reasons.add("vba_source_size_limit")
                break
            if len(encoded) > remaining:
                encoded = encoded[:remaining]
                source_text = encoded.decode("utf-8", errors="ignore")
                result.partial_reasons.add("vba_source_size_limit")
            result.source_bytes_inspected += len(encoded)
            result.module_count += 1
            if len(result.module_names) < limits.max_metadata_entries:
                result.module_names.append(_safe_text(str(module_name), limits, hard_limit=128))
            _scan_source(source_text, result, limits)
    except _EXPECTED_ERRORS as exc:
        result.parser_exception = type(exc).__name__
        result.partial_reasons.add("vba_parser_error")
    finally:
        if parser is not None:
            close = getattr(parser, "close", None)
            if callable(close):
                close()
        for logger, disabled in zip(loggers, prior_disabled, strict=True):
            logger.disabled = disabled
    if result.macro_detected and result.module_count == 0:
        result.partial_reasons.add("vba_source_unavailable")
    return result


def _scan_source(source: str, result: VbaAnalysis, limits: OfficeAnalysisLimits) -> None:
    scanner = olevba.VBA_Scanner(source)
    for kind, keyword, _ in scanner.scan(include_decoded_strings=False, deobfuscate=False):
        if not isinstance(kind, str) or not isinstance(keyword, str):
            continue
        normalized = keyword.casefold().strip()
        if (
            kind == "AutoExec"
            and normalized in _AUTOEXEC_NAMES
            and len(result.autoexec_triggers) < limits.max_metadata_entries
        ):
            result.autoexec_triggers.add(_safe_text(keyword, limits, hard_limit=128))
        if kind != "Suspicious":
            continue
        indicator_class = _EXECUTION_INDICATORS.get(normalized)
        if indicator_class is None:
            continue
        if len(result.indicator_names) < limits.max_metadata_entries:
            result.indicator_names.add(_safe_text(keyword, limits, hard_limit=128))
            result.indicator_classes.add(indicator_class)


def _source_text(value: object) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    raise TypeError("VBA parser returned a non-text module")


def _safe_text(value: str, limits: OfficeAnalysisLimits, *, hard_limit: int) -> str:
    normalized = unicodedata.normalize("NFC", value)
    sanitized = "".join(
        character
        for character in normalized
        if character not in _BIDI_CONTROLS and not unicodedata.category(character).startswith("C")
    )
    return sanitized[: min(hard_limit, limits.max_metadata_string_length)] or "unnamed"


__all__ = ["VbaAnalysis", "analyze_vba_blob"]
