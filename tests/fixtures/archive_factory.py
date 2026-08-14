"""Harmless deterministic ZIP fixtures for bounded archive tests."""

from __future__ import annotations

import io
import stat
import struct
import warnings
import zipfile
from pathlib import Path


def archive_bytes(
    members: list[tuple[str, bytes]],
    *,
    compression: int = zipfile.ZIP_DEFLATED,
) -> bytes:
    target = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(target, mode="w", compression=compression) as archive:
            for name, data in members:
                archive.writestr(name, data)
    return target.getvalue()


def write_archive(
    path: Path,
    members: list[tuple[str, bytes]],
    *,
    compression: int = zipfile.ZIP_DEFLATED,
) -> Path:
    path.write_bytes(archive_bytes(members, compression=compression))
    return path


def nested_archive_bytes(depth: int, *, leaf_name: str = "leaf.txt") -> bytes:
    payload = archive_bytes([(leaf_name, b"controlled nested fixture")])
    for level in range(depth):
        payload = archive_bytes([(f"nested-{level}.zip", payload)])
    return payload


def symlink_archive_bytes() -> bytes:
    target = io.BytesIO()
    info = zipfile.ZipInfo("controlled-link")
    info.create_system = 3
    info.external_attr = (stat.S_IFLNK | 0o777) << 16
    with zipfile.ZipFile(target, mode="w") as archive:
        archive.writestr(info, "../outside-target")
    return target.getvalue()


def encrypted_metadata_archive_bytes() -> bytes:
    return _patch_flag_bits(archive_bytes([("secret.txt", b"not encrypted fixture data")]), 0x1)


def unsupported_method_archive_bytes(method: int = 99) -> bytes:
    data = bytearray(archive_bytes([("unsupported.bin", b"controlled fixture")]))
    local = data.find(b"PK\x03\x04")
    central = data.find(b"PK\x01\x02")
    if local < 0 or central < 0:
        raise AssertionError("fixture ZIP headers are absent")
    struct.pack_into("<H", data, local + 8, method)
    struct.pack_into("<H", data, central + 10, method)
    return bytes(data)


def corrupt_crc_archive_bytes() -> bytes:
    data = bytearray(archive_bytes([("corrupt.txt", b"controlled fixture")]))
    local = data.find(b"PK\x03\x04")
    central = data.find(b"PK\x01\x02")
    if local < 0 or central < 0:
        raise AssertionError("fixture ZIP headers are absent")
    crc = struct.unpack_from("<I", data, central + 16)[0] ^ 0xFFFFFFFF
    struct.pack_into("<I", data, local + 14, crc)
    struct.pack_into("<I", data, central + 16, crc)
    return bytes(data)


def data_descriptor_archive_bytes() -> bytes:
    class _NonSeekable(io.BytesIO):
        def seekable(self) -> bool:
            return False

        def seek(self, *args: object, **kwargs: object) -> int:
            del args, kwargs
            raise io.UnsupportedOperation

    target = _NonSeekable()
    with zipfile.ZipFile(target, mode="w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("descriptor.txt", b"controlled descriptor fixture")
    return target.getvalue()


def small_zip64_archive_bytes() -> bytes:
    target = io.BytesIO()
    with zipfile.ZipFile(target, mode="w", allowZip64=True) as archive:
        info = zipfile.ZipInfo("zip64.txt")
        with archive.open(info, mode="w", force_zip64=True) as member:
            member.write(b"controlled ZIP64 fixture")
    return target.getvalue()


def _patch_flag_bits(payload: bytes, flag: int) -> bytes:
    data = bytearray(payload)
    local = data.find(b"PK\x03\x04")
    central = data.find(b"PK\x01\x02")
    if local < 0 or central < 0:
        raise AssertionError("fixture ZIP headers are absent")
    local_flags = struct.unpack_from("<H", data, local + 6)[0] | flag
    central_flags = struct.unpack_from("<H", data, central + 8)[0] | flag
    struct.pack_into("<H", data, local + 6, local_flags)
    struct.pack_into("<H", data, central + 8, central_flags)
    return bytes(data)


__all__ = [
    "archive_bytes",
    "corrupt_crc_archive_bytes",
    "data_descriptor_archive_bytes",
    "encrypted_metadata_archive_bytes",
    "nested_archive_bytes",
    "small_zip64_archive_bytes",
    "symlink_archive_bytes",
    "unsupported_method_archive_bytes",
    "write_archive",
]
