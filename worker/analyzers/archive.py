"""Bounded worker-only ZIP inspection that never extracts archive members."""

from __future__ import annotations

import hashlib
import io
import platform
import re
import stat
import unicodedata
import zipfile
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO

from worker.analyzers.archive_types import (
    DEFAULT_ARCHIVE_LIMITS,
    ArchiveAnalysis,
    ArchiveAnalysisLimits,
    ArchiveParserStatus,
    ArchiveRoutingError,
)
from worker.analyzers.file_type import FileFamily
from worker.analyzers.name_security import (
    BIDI_CONTROLS,
    DANGEROUS_EXTENSIONS,
    bidi_codepoints,
    final_extension,
    has_dangerous_double_extension,
)
from worker.findings import finding_payload

_READ_CHUNK_BYTES = 64 * 1024
_ZIP_SIGNATURES = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
_WINDOWS_ROOT = re.compile(r"^[A-Za-z]:[\\/]")


class _ResourceStop(RuntimeError):
    """Internal bounded traversal signal, never exposed across the contract."""


@dataclass(slots=True)
class _State:
    limits: ArchiveAnalysisLimits
    archive_count: int = 0
    entry_count: int = 0
    members_inspected: int = 0
    directories_seen: int = 0
    actual_decompressed_bytes: int = 0
    compressed_bytes_considered: int = 0
    nested_archives_detected: int = 0
    nested_archive_bytes_materialized: int = 0
    repeated_nested_archives: int = 0
    encrypted_count: int = 0
    unsupported_method_count: int = 0
    symlink_count: int = 0
    traversal_count: int = 0
    absolute_path_count: int = 0
    duplicate_count: int = 0
    dangerous_member_count: int = 0
    double_extension_count: int = 0
    bidi_member_count: int = 0
    member_names_truncated: int = 0
    retained_name_count: int = 0
    parser_exception: str | None = None
    partial_reasons: set[str] = field(default_factory=set)
    resource_reasons: set[str] = field(default_factory=set)
    malformed_reasons: set[str] = field(default_factory=set)
    unsupported_methods: set[int] = field(default_factory=set)
    seen_nested_digests: set[str] = field(default_factory=set)
    traversal_records: list[dict[str, object]] = field(default_factory=list)
    absolute_path_records: list[dict[str, object]] = field(default_factory=list)
    symlink_records: list[dict[str, object]] = field(default_factory=list)
    duplicate_records: list[dict[str, object]] = field(default_factory=list)
    dangerous_records: list[dict[str, object]] = field(default_factory=list)
    double_extension_records: list[dict[str, object]] = field(default_factory=list)
    bidi_records: list[dict[str, object]] = field(default_factory=list)
    encrypted_records: list[dict[str, object]] = field(default_factory=list)
    nesting_records: list[dict[str, object]] = field(default_factory=list)

    def partial(self, reason: str) -> None:
        self.partial_reasons.add(reason)

    def resource(self, reason: str) -> None:
        self.resource_reasons.add(reason)
        self.partial(reason)

    def malformed(self, reason: str, exc: BaseException | None = None) -> None:
        self.malformed_reasons.add(reason)
        self.partial(reason)
        if exc is not None and self.parser_exception is None:
            self.parser_exception = type(exc).__name__


def analyze_archive(
    path: Path,
    *,
    detected_family: FileFamily,
    limits: ArchiveAnalysisLimits = DEFAULT_ARCHIVE_LIMITS,
) -> ArchiveAnalysis:
    """Inspect one content-identified ZIP and bounded nested ZIP containers."""

    if detected_family not in {FileFamily.ZIP, FileFamily.OOXML_CANDIDATE}:
        raise ArchiveRoutingError("archive analyzer requires content-identified ZIP input")
    state = _State(limits=limits)
    try:
        container_size = path.stat().st_size
    except OSError as exc:
        state.malformed("archive_input_unavailable", exc)
        return _result(state)
    _inspect_archive(path, container_size=container_size, depth=0, state=state)
    return _result(state)


def _inspect_archive(
    source: Path | BinaryIO,
    *,
    container_size: int,
    depth: int,
    state: _State,
) -> None:
    state.compressed_bytes_considered += container_size
    if state.compressed_bytes_considered > state.limits.max_compressed_bytes_considered:
        state.resource("compressed_input_limit")
        return
    try:
        archive = zipfile.ZipFile(source, mode="r")
    except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
        state.malformed("malformed_nested_archive" if depth else "malformed_archive", exc)
        return

    state.archive_count += 1
    with archive:
        try:
            infos = archive.infolist()
        except (OSError, EOFError, zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
            state.malformed("central_directory_error", exc)
            return
        state.entry_count += len(infos)
        if len(infos) > state.limits.max_zip_entries:
            state.resource("zip_entry_limit")
            infos = infos[: state.limits.max_zip_entries]

        seen_names: dict[str, str] = {}
        for info in infos:
            if state.members_inspected >= state.limits.max_members_inspected:
                state.resource("member_inspection_limit")
                return
            state.members_inspected += 1
            _inspect_name(info, depth=depth, seen_names=seen_names, state=state)
            if info.is_dir():
                state.directories_seen += 1
                continue
            if _is_symlink(info):
                state.symlink_count += 1
                _retain_record(state.symlink_records, info.filename, depth, state)
                continue
            if info.flag_bits & 0x1:
                state.encrypted_count += 1
                state.partial("encrypted_member")
                _retain_record(state.encrypted_records, info.filename, depth, state)
                continue
            if info.compress_type not in _supported_compression_methods():
                _unsupported_method(info.compress_type, state)
                continue
            try:
                nested = _read_member(archive, info, state)
            except _ResourceStop:
                return
            except NotImplementedError:
                _unsupported_method(info.compress_type, state)
                continue
            except (OSError, EOFError, RuntimeError, zipfile.BadZipFile, zlib.error) as exc:
                state.malformed("member_decompression_error", exc)
                continue
            if nested is None:
                continue
            state.nested_archives_detected += 1
            next_depth = depth + 1
            if next_depth > state.limits.max_nesting_depth:
                state.partial("nesting_depth_limit")
                _retain_record(state.nesting_records, info.filename, next_depth, state)
                continue
            digest = hashlib.sha256(nested).hexdigest()
            if digest in state.seen_nested_digests:
                state.repeated_nested_archives += 1
                continue
            state.seen_nested_digests.add(digest)
            _inspect_archive(
                io.BytesIO(nested),
                container_size=len(nested),
                depth=next_depth,
                state=state,
            )


def _inspect_name(
    info: zipfile.ZipInfo,
    *,
    depth: int,
    seen_names: dict[str, str],
    state: _State,
) -> None:
    name = info.filename
    portable = name.replace("\\", "/")
    if any(segment == ".." for segment in portable.split("/")):
        state.traversal_count += 1
        _retain_record(
            state.traversal_records,
            name,
            depth,
            state,
            category_limit=state.limits.max_traversal_records,
        )
    if portable.startswith("/") or _WINDOWS_ROOT.match(name) is not None:
        state.absolute_path_count += 1
        _retain_record(
            state.absolute_path_records,
            name,
            depth,
            state,
            category_limit=state.limits.max_traversal_records,
        )

    normalized = _collision_key(name)
    previous = seen_names.get(normalized)
    if previous is not None:
        state.duplicate_count += 1
        if len(state.duplicate_records) < state.limits.max_duplicate_records and _can_retain_name(
            state
        ):
            state.duplicate_records.append(
                {
                    "member_name": _safe_member_name(name, state),
                    "collides_with": _safe_member_name(previous, state),
                    "archive_depth": depth,
                    "collision_kind": "exact" if name == previous else "portable_normalized",
                }
            )
    else:
        seen_names[normalized] = name

    extension = final_extension(name)
    if extension in DANGEROUS_EXTENSIONS:
        state.dangerous_member_count += 1
        _retain_record(
            state.dangerous_records,
            name,
            depth,
            state,
            extra={"extension": extension},
        )
    if has_dangerous_double_extension(name):
        state.double_extension_count += 1
        _retain_record(
            state.double_extension_records,
            name,
            depth,
            state,
            extra={"final_extension": extension},
        )
    observed_bidi = bidi_codepoints(name)
    if observed_bidi:
        state.bidi_member_count += 1
        _retain_record(
            state.bidi_records,
            name,
            depth,
            state,
            extra={"codepoints": observed_bidi},
        )


def _read_member(archive: zipfile.ZipFile, info: zipfile.ZipInfo, state: _State) -> bytes | None:
    member_bytes = 0
    nested_data: bytearray | None = None
    with archive.open(info, mode="r") as stream:
        first = stream.read(_next_read_size(member_bytes, state, preferred=4))
        member_bytes = _account_actual_bytes(first, member_bytes, state)
        if first.startswith(_ZIP_SIGNATURES):
            nested_data = bytearray()
            _append_nested(first, nested_data, state)
        while first:
            chunk = stream.read(
                _next_read_size(
                    member_bytes,
                    state,
                    preferred=_READ_CHUNK_BYTES,
                    nested=bool(nested_data is not None),
                )
            )
            if not chunk:
                break
            member_bytes = _account_actual_bytes(chunk, member_bytes, state)
            if nested_data is not None:
                _append_nested(chunk, nested_data, state)
            first = chunk
    return bytes(nested_data) if nested_data is not None else None


def _next_read_size(
    member_bytes: int,
    state: _State,
    *,
    preferred: int,
    nested: bool = False,
) -> int:
    maximum = min(
        preferred,
        state.limits.max_member_bytes - member_bytes + 1,
        state.limits.max_total_decompressed_bytes - state.actual_decompressed_bytes + 1,
    )
    if nested:
        maximum = min(
            maximum,
            state.limits.max_nested_archive_bytes - state.nested_archive_bytes_materialized + 1,
        )
    return max(1, maximum)


def _account_actual_bytes(chunk: bytes, member_bytes: int, state: _State) -> int:
    member_bytes += len(chunk)
    state.actual_decompressed_bytes += len(chunk)
    if member_bytes > state.limits.max_member_bytes:
        state.resource("member_actual_byte_limit")
        raise _ResourceStop
    if state.actual_decompressed_bytes > state.limits.max_total_decompressed_bytes:
        state.resource("total_actual_byte_limit")
        raise _ResourceStop
    return member_bytes


def _append_nested(chunk: bytes, target: bytearray, state: _State) -> None:
    if state.nested_archive_bytes_materialized + len(chunk) > (
        state.limits.max_nested_archive_bytes
    ):
        state.resource("nested_materialization_limit")
        raise _ResourceStop
    target.extend(chunk)
    state.nested_archive_bytes_materialized += len(chunk)


def _unsupported_method(method: int, state: _State) -> None:
    state.unsupported_method_count += 1
    state.unsupported_methods.add(method)
    state.partial("unsupported_compression_method")


def _is_symlink(info: zipfile.ZipInfo) -> bool:
    unix_mode = (info.external_attr >> 16) & 0xFFFF
    return info.create_system == 3 and stat.S_ISLNK(unix_mode)


def _collision_key(name: str) -> str:
    portable = unicodedata.normalize("NFC", name).replace("\\", "/")
    pieces = [piece for piece in portable.split("/") if piece not in {"", "."}]
    prefix = "/" if portable.startswith("/") else ""
    return prefix + "/".join(pieces)


def _retain_record(
    target: list[dict[str, object]],
    name: str,
    depth: int,
    state: _State,
    *,
    extra: dict[str, object] | None = None,
    category_limit: int | None = None,
) -> None:
    maximum = category_limit or state.limits.max_suspicious_member_names
    if len(target) >= maximum or not _can_retain_name(state):
        return
    record: dict[str, object] = {
        "member_name": _safe_member_name(name, state),
        "archive_depth": depth,
    }
    if extra:
        record.update(extra)
    target.append(record)


def _can_retain_name(state: _State) -> bool:
    if state.retained_name_count >= state.limits.max_suspicious_member_names:
        return False
    state.retained_name_count += 1
    return True


def _safe_member_name(name: str, state: _State) -> str:
    maximum = min(
        state.limits.max_member_name_length,
        state.limits.max_metadata_string_length,
    )
    represented = "".join(
        (
            f"\\u{ord(character):04x}"
            if character in BIDI_CONTROLS or unicodedata.category(character).startswith("C")
            else character
        )
        for character in name
    )
    if len(represented) > maximum:
        state.member_names_truncated += 1
    return represented[:maximum] or "unnamed-member"


def _supported_compression_methods() -> dict[int, str]:
    methods = {
        zipfile.ZIP_STORED: "stored",
        zipfile.ZIP_DEFLATED: "deflate",
        zipfile.ZIP_BZIP2: "bzip2",
        zipfile.ZIP_LZMA: "lzma",
    }
    zstandard = getattr(zipfile, "ZIP_ZSTANDARD", None)
    if isinstance(zstandard, int):
        methods[zstandard] = "zstandard"
    return methods


def _result(state: _State) -> ArchiveAnalysis:
    findings = _findings(state)
    if len(findings) > state.limits.max_findings:
        state.resource("finding_limit")
        findings = _findings(state)
        mandatory = {
            "ARCHIVE_MALFORMED",
            "ARCHIVE_NESTING_LIMIT",
            "ARCHIVE_RESOURCE_LIMIT",
            "ARCHIVE_PARTIAL_ANALYSIS",
        }
        required = [item for item in findings if item["code"] in mandatory]
        optional = [item for item in findings if item["code"] not in mandatory]
        findings = (optional[: state.limits.max_findings - len(required)] + required)[
            : state.limits.max_findings
        ]

    if state.malformed_reasons:
        parser_status = ArchiveParserStatus.MALFORMED
    elif state.partial_reasons:
        parser_status = ArchiveParserStatus.PARTIAL
    else:
        parser_status = ArchiveParserStatus.COMPLETE
    metadata: dict[str, object] = {
        "family": "ZIP",
        "parser": "python-zipfile",
        "python_runtime_version": platform.python_version(),
        "zlib_version": zlib.ZLIB_VERSION,
        "parser_status": parser_status.value,
        "supported_compression_methods": list(_supported_compression_methods().values()),
        "archive_count": state.archive_count,
        "entry_count": state.entry_count,
        "members_inspected": state.members_inspected,
        "directory_count": state.directories_seen,
        "nested_archive_count": state.nested_archives_detected,
        "repeated_nested_archive_count": state.repeated_nested_archives,
        "actual_decompressed_bytes": state.actual_decompressed_bytes,
        "compressed_bytes_considered": state.compressed_bytes_considered,
        "nested_archive_bytes_materialized": state.nested_archive_bytes_materialized,
        "encrypted_member_count": state.encrypted_count,
        "unsupported_compression_member_count": state.unsupported_method_count,
        "unsupported_compression_methods": sorted(state.unsupported_methods),
        "member_names_truncated": state.member_names_truncated,
        "partial_reasons": sorted(state.partial_reasons),
    }
    if state.parser_exception is not None:
        metadata["parser_exception"] = state.parser_exception
    return ArchiveAnalysis(parser_status, tuple(findings), metadata)


def _findings(state: _State) -> list[dict[str, object]]:
    findings: list[dict[str, object]] = []
    observations = (
        (
            "ARCHIVE_PATH_TRAVERSAL",
            state.traversal_count,
            state.traversal_records,
        ),
        (
            "ARCHIVE_ABSOLUTE_PATH",
            state.absolute_path_count,
            state.absolute_path_records,
        ),
        ("ARCHIVE_SYMLINK", state.symlink_count, state.symlink_records),
        ("ARCHIVE_DUPLICATE_MEMBER", state.duplicate_count, state.duplicate_records),
        (
            "ARCHIVE_DANGEROUS_MEMBER",
            state.dangerous_member_count,
            state.dangerous_records,
        ),
        (
            "ARCHIVE_MEMBER_DOUBLE_EXTENSION",
            state.double_extension_count,
            state.double_extension_records,
        ),
        (
            "ARCHIVE_MEMBER_BIDI_OVERRIDE",
            state.bidi_member_count,
            state.bidi_records,
        ),
        ("ARCHIVE_ENCRYPTED", state.encrypted_count, state.encrypted_records),
    )
    for code, count, records in observations:
        if count:
            findings.append(finding_payload(code, {"count": count, "members": records}))
    if "nesting_depth_limit" in state.partial_reasons:
        findings.append(
            finding_payload(
                "ARCHIVE_NESTING_LIMIT",
                {
                    "maximum_depth": state.limits.max_nesting_depth,
                    "members": state.nesting_records,
                },
            )
        )
    if state.resource_reasons:
        findings.append(
            finding_payload(
                "ARCHIVE_RESOURCE_LIMIT",
                {"reasons": sorted(state.resource_reasons)},
            )
        )
    if state.malformed_reasons:
        findings.append(
            finding_payload(
                "ARCHIVE_MALFORMED",
                {
                    "reasons": sorted(state.malformed_reasons),
                    "parser_exception": state.parser_exception,
                },
            )
        )
    if state.partial_reasons:
        findings.append(
            finding_payload(
                "ARCHIVE_PARTIAL_ANALYSIS",
                {"reasons": sorted(state.partial_reasons)},
            )
        )
    return findings


__all__ = ["analyze_archive"]
