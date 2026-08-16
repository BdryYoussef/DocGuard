"""Bounded lexical fallback scan for PDFs the structural parser cannot fully trust.

Scope, deliberately narrow:

When qpdf/pikepdf rejects a PDF outright, or only partially recovers it, the normal
structural traversal in `worker.analyzers.pdf` may see few or none of the document's
real indicator objects — not because they are absent, but because the parser could
not reach them. This module recovers *bounded, non-authoritative* evidence in that
situation by searching the raw file bytes for a fixed, small set of PDF name-object
keywords (`/JavaScript`, `/OpenAction`, ...).

This is a name-token scan, not a parser:

- It decodes only the standard PDF name `#XX` hex-escape syntax (ISO 32000-1 §7.3.5)
  globally across the byte stream, then performs a bounded literal substring search.
- It does not tokenize PDF syntax, resolve indirect objects, apply stream filters,
  decompress content, or distinguish a real name-object delimiter context from an
  incidental byte sequence inside binary/compressed data.
- A match is lexical evidence only. It is never promoted to a structurally-confirmed
  finding (`PDF_JAVASCRIPT`, `PDF_XFA`, ...) — see `worker.analyzers.pdf` for that
  distinction, enforced by construction: this module never emits those finding codes.
- It performs no execution, evaluation, decompression-for-discovery, network access,
  or recursion. It is a single bounded linear pass over a size-capped byte prefix.

Every indicator token is a PDF *name object* keyword and therefore always begins
with `/` in valid PDF syntax; ordinary document prose (a PDF string, not a name)
never matches, so casual mentions of these words in visible text are not
mistaken for active-content evidence.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_HEX_ESCAPE_RE = re.compile(rb"#([0-9a-fA-F]{2})")

# Fixed, intentionally small vocabulary. Each entry is the bare PDF name-object
# keyword (without the leading `/`) that a viewer would recognize structurally.
FALLBACK_INDICATOR_TOKENS: tuple[str, ...] = (
    "JavaScript",
    "JS",
    "OpenAction",
    "AA",
    "AcroForm",
    "XFA",
    "Launch",
    "EmbeddedFile",
    "EmbeddedFiles",
    "ImportData",
    "SubmitForm",
    "GoToE",
    "URI",
)


@dataclass(frozen=True, slots=True)
class PdfFallbackLimits:
    max_scan_bytes: int = 8 * 1024 * 1024
    max_hit_count: int = 9_999

    def __post_init__(self) -> None:
        if self.max_scan_bytes <= 0 or self.max_hit_count <= 0:
            raise ValueError("PDF fallback limits must be positive")


DEFAULT_PDF_FALLBACK_LIMITS = PdfFallbackLimits()


@dataclass(frozen=True, slots=True)
class PdfFallbackScan:
    indicator_counts: dict[str, int] = field(default_factory=dict)
    truncated: bool = False

    @property
    def indicators(self) -> tuple[str, ...]:
        return tuple(sorted(self.indicator_counts))


def _decode_name_hex_escapes(data: bytes) -> bytes:
    """Decode `#XX` hex escapes anywhere in `data` (ISO 32000-1 name-object syntax).

    This is a mechanical byte substitution, not a PDF parser: it does not know or
    care whether a given `#XX` sequence is really inside a name object.
    """
    return _HEX_ESCAPE_RE.sub(lambda match: bytes([int(match.group(1), 16)]), data)


def scan_for_fallback_indicators(
    raw_bytes: bytes,
    *,
    limits: PdfFallbackLimits = DEFAULT_PDF_FALLBACK_LIMITS,
) -> PdfFallbackScan:
    """Bounded, deterministic, non-executing lexical scan for known PDF name tokens.

    Only counts a token as present when it appears immediately after a `/` byte,
    matching PDF name-object syntax — never a bare word in ordinary text.
    """
    truncated = len(raw_bytes) > limits.max_scan_bytes
    window = raw_bytes[: limits.max_scan_bytes]
    decoded = _decode_name_hex_escapes(window)

    counts: dict[str, int] = {}
    for token in FALLBACK_INDICATOR_TOKENS:
        needle = b"/" + token.encode("ascii")
        # Decoding `#XX` escapes is a superset of the literal bytes for any region
        # that had no escapes at all, so a single pass over `decoded` catches both
        # obfuscated and plain occurrences without double-counting either.
        hits = decoded.count(needle)
        if hits <= 0:
            continue
        counts[token] = min(hits, limits.max_hit_count)
    return PdfFallbackScan(indicator_counts=counts, truncated=truncated)


__all__ = [
    "DEFAULT_PDF_FALLBACK_LIMITS",
    "FALLBACK_INDICATOR_TOKENS",
    "PdfFallbackLimits",
    "PdfFallbackScan",
    "scan_for_fallback_indicators",
]
