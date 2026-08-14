"""Bounded streaming storage and hashing without interpreting document content."""

from __future__ import annotations

import hashlib
import os
import secrets
import stat
from collections.abc import AsyncIterator
from dataclasses import dataclass
from pathlib import Path

from app.core.errors import DocGuardError
from app.storage.paths import StoragePaths, generate_storage_key

STREAM_WRITE_CHUNK_BYTES = 64 * 1024


class UploadTooLarge(ValueError):
    pass


class EmptyUpload(ValueError):
    pass


class StorageFailure(DocGuardError):
    pass


@dataclass(frozen=True, slots=True)
class StoredDocument:
    storage_key: str
    path: Path
    sha256: str
    size_bytes: int


@dataclass(frozen=True, slots=True)
class TemporaryCdrOutput:
    path: Path


def create_cdr_output(paths: StoragePaths) -> TemporaryCdrOutput:
    path = paths.work / f".cdr-{secrets.token_hex(16)}.part"
    try:
        descriptor = os.open(
            path,
            os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
        )
        os.close(descriptor)
    except OSError as exc:
        raise StorageFailure("CDR output allocation failed") from exc
    return TemporaryCdrOutput(path)


def finalize_cdr_output(output: TemporaryCdrOutput, *, maximum_bytes: int) -> tuple[str, int]:
    try:
        descriptor = _open_regular_read_only(output.path)
        try:
            digest, size_bytes = _hash_descriptor(descriptor, maximum_bytes=maximum_bytes)
            if size_bytes == 0:
                raise StorageFailure("CDR produced an empty output")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        output.path.chmod(0o400)
        return digest, size_bytes
    except OSError as exc:
        raise StorageFailure("CDR output finalization failed") from exc


def store_private_copy(
    source_path: Path,
    *,
    paths: StoragePaths,
    area: str,
    maximum_bytes: int,
    expected_sha256: str,
) -> StoredDocument:
    """Copy opaque bytes without interpretation and atomically finalize them read-only."""

    if area not in {"quarantine", "sanitized"}:
        raise ValueError("private copy target must be quarantine or sanitized")
    key = generate_storage_key()
    final_path = paths.resolve(area, key)
    staging_directory = paths.incoming if area == "quarantine" else paths.work
    temporary_path = staging_directory / f".{key}.{secrets.token_hex(8)}.part"
    source_descriptor: int | None = None
    target_descriptor: int | None = None
    finalized = False
    try:
        source_descriptor = _open_regular_read_only(source_path)
        target_descriptor = os.open(
            temporary_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
        )
        digest = hashlib.sha256()
        size_bytes = 0
        while True:
            chunk = os.read(source_descriptor, STREAM_WRITE_CHUNK_BYTES)
            if not chunk:
                break
            size_bytes += len(chunk)
            if size_bytes > maximum_bytes:
                raise StorageFailure("private object exceeds configured maximum")
            digest.update(chunk)
            _write_all(target_descriptor, chunk)
        observed_sha256 = digest.hexdigest()
        if size_bytes == 0 or observed_sha256 != expected_sha256:
            raise StorageFailure("private object integrity check failed")
        os.fsync(target_descriptor)
        os.close(target_descriptor)
        target_descriptor = None
        temporary_path.chmod(0o400)
        os.replace(temporary_path, final_path)
        _fsync_directory(final_path.parent)
        finalized = True
        return StoredDocument(key, final_path, observed_sha256, size_bytes)
    except OSError as exc:
        raise StorageFailure("private object copy failed") from exc
    finally:
        if source_descriptor is not None:
            os.close(source_descriptor)
        if target_descriptor is not None:
            os.close(target_descriptor)
        if not finalized:
            temporary_path.unlink(missing_ok=True)
            final_path.unlink(missing_ok=True)


def remove_cdr_output(output: TemporaryCdrOutput) -> None:
    try:
        output.path.unlink(missing_ok=True)
    except OSError as exc:
        raise StorageFailure("CDR temporary cleanup failed") from exc


def verify_private_document(
    path: Path, *, expected_sha256: str, expected_size: int, maximum_bytes: int
) -> bool:
    try:
        if stat.S_IMODE(path.stat(follow_symlinks=False).st_mode) != 0o400:
            return False
        descriptor = _open_regular_read_only(path)
        try:
            observed_sha256, size_bytes = _hash_descriptor(descriptor, maximum_bytes=maximum_bytes)
        finally:
            os.close(descriptor)
    except (OSError, StorageFailure):
        return False
    return observed_sha256 == expected_sha256 and size_bytes == expected_size


async def stream_document_to_quarantine(
    chunks: AsyncIterator[bytes],
    *,
    paths: StoragePaths,
    maximum_bytes: int,
) -> StoredDocument:
    """Store one raw body atomically while enforcing its actual streamed size."""

    key = generate_storage_key()
    final_path = paths.resolve("quarantine", key)
    temporary_path = paths.incoming / f".{key}.{secrets.token_hex(8)}.part"
    descriptor: int | None = None
    finalized = False
    digest = hashlib.sha256()
    size_bytes = 0
    try:
        descriptor = os.open(
            temporary_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
        )
        async for received in chunks:
            if not received:
                continue
            for offset in range(0, len(received), STREAM_WRITE_CHUNK_BYTES):
                piece = received[offset : offset + STREAM_WRITE_CHUNK_BYTES]
                size_bytes += len(piece)
                if size_bytes > maximum_bytes:
                    raise UploadTooLarge(
                        f"upload exceeds configured maximum of {maximum_bytes} bytes"
                    )
                digest.update(piece)
                _write_all(descriptor, piece)

        if size_bytes == 0:
            raise EmptyUpload("zero-byte documents are not accepted")
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        temporary_path.chmod(0o400)
        os.replace(temporary_path, final_path)
        _fsync_directory(paths.quarantine)
        finalized = True
        return StoredDocument(
            storage_key=key,
            path=final_path,
            sha256=digest.hexdigest(),
            size_bytes=size_bytes,
        )
    except (UploadTooLarge, EmptyUpload):
        raise
    except OSError as exc:
        raise StorageFailure("document storage failed") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if not finalized:
            temporary_path.unlink(missing_ok=True)
            final_path.unlink(missing_ok=True)


def remove_stored_document(document: StoredDocument) -> None:
    try:
        document.path.unlink(missing_ok=True)
    except OSError as exc:
        raise StorageFailure("stored document cleanup failed") from exc


def _write_all(descriptor: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("short write while storing upload")
        view = view[written:]


def _open_regular_read_only(path: Path) -> int:
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    if not stat.S_ISREG(os.fstat(descriptor).st_mode):
        os.close(descriptor)
        raise StorageFailure("private source is not a regular file")
    return descriptor


def _hash_descriptor(descriptor: int, *, maximum_bytes: int) -> tuple[str, int]:
    digest = hashlib.sha256()
    size_bytes = 0
    while True:
        chunk = os.read(descriptor, STREAM_WRITE_CHUNK_BYTES)
        if not chunk:
            break
        size_bytes += len(chunk)
        if size_bytes > maximum_bytes:
            raise StorageFailure("private object exceeds configured maximum")
        digest.update(chunk)
    return digest.hexdigest(), size_bytes


def _fsync_directory(directory: Path) -> None:
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
