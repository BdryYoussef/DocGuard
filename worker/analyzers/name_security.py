"""Shared deterministic filename-deception primitives for worker analyzers."""

from __future__ import annotations

from pathlib import PurePath

DANGEROUS_EXTENSIONS = frozenset(
    {
        "bat",
        "cmd",
        "com",
        "cpl",
        "dll",
        "exe",
        "hta",
        "jar",
        "js",
        "jse",
        "lnk",
        "msi",
        "pif",
        "ps1",
        "scr",
        "vbe",
        "vbs",
        "wsf",
        "wsh",
    }
)

BUSINESS_EXTENSIONS = frozenset(
    {
        "csv",
        "doc",
        "docm",
        "docx",
        "odp",
        "ods",
        "odt",
        "pdf",
        "ppt",
        "pptm",
        "pptx",
        "rtf",
        "txt",
        "xls",
        "xlsm",
        "xlsx",
    }
)

BIDI_CONTROLS = frozenset("\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")


def basename_segments(value: str) -> list[str]:
    basename = PurePath(value.replace("\\", "/")).name
    return basename.casefold().split(".")


def final_extension(value: str) -> str | None:
    segments = basename_segments(value)
    return segments[-1] if len(segments) > 1 else None


def has_dangerous_double_extension(value: str) -> bool:
    segments = basename_segments(value)
    return (
        len(segments) >= 3
        and segments[-1] in DANGEROUS_EXTENSIONS
        and any(segment in BUSINESS_EXTENSIONS for segment in segments[1:-1])
    )


def bidi_codepoints(value: str, *, maximum: int = 16) -> list[str]:
    return [f"U+{ord(character):04X}" for character in value if character in BIDI_CONTROLS][
        :maximum
    ]


__all__ = [
    "BIDI_CONTROLS",
    "BUSINESS_EXTENSIONS",
    "DANGEROUS_EXTENSIONS",
    "basename_segments",
    "bidi_codepoints",
    "final_extension",
    "has_dangerous_double_extension",
]
