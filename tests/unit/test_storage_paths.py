import hashlib
from pathlib import Path

import pytest

from app.storage.ingestion import StorageFailure, store_private_copy, verify_private_document
from app.storage.paths import (
    InvalidStorageKey,
    StoragePaths,
    generate_storage_key,
    normalize_display_filename,
)


def test_generated_storage_key_resolves_below_root(tmp_path: Path) -> None:
    paths = StoragePaths(tmp_path)
    key = generate_storage_key()

    resolved = paths.resolve("quarantine", key)

    assert resolved.parent == tmp_path.resolve() / "quarantine"
    assert resolved.is_relative_to(tmp_path.resolve())


@pytest.mark.parametrize("key", ["../escape", "a/../../escape", "f" * 31, "G" * 32])
def test_storage_key_cannot_escape_root(tmp_path: Path, key: str) -> None:
    with pytest.raises(InvalidStorageKey):
        StoragePaths(tmp_path).resolve("incoming", key)


@pytest.mark.parametrize("key", ["/tmp/sample", "C:\\sample", "//server/share"])
def test_absolute_storage_paths_are_rejected(tmp_path: Path, key: str) -> None:
    with pytest.raises(InvalidStorageKey):
        StoragePaths(tmp_path).resolve("quarantine", key)


def test_original_filename_is_normalized_only_as_metadata() -> None:
    assert normalize_display_filename("../../payroll.pdf\x00") == ".._.._payroll.pdf"


def test_private_copy_is_atomic_read_only_opaque_and_hash_verified(tmp_path: Path) -> None:
    paths = StoragePaths(tmp_path / "private")
    paths.initialize()
    source = tmp_path / "candidate"
    content = b"controlled generated artifact"
    source.write_bytes(content)
    source.chmod(0o400)
    digest = hashlib.sha256(content).hexdigest()

    stored = store_private_copy(
        source,
        paths=paths,
        area="sanitized",
        maximum_bytes=1_024,
        expected_sha256=digest,
    )

    assert stored.path.parent == paths.sanitized
    assert stored.path.name == stored.storage_key
    assert stored.path.stat().st_mode & 0o777 == 0o400
    assert verify_private_document(
        stored.path,
        expected_sha256=digest,
        expected_size=len(content),
        maximum_bytes=1_024,
    )
    assert list(paths.work.iterdir()) == []


def test_private_copy_hash_mismatch_leaves_no_partial_artifact(tmp_path: Path) -> None:
    paths = StoragePaths(tmp_path / "private")
    paths.initialize()
    source = tmp_path / "candidate"
    source.write_bytes(b"controlled")
    source.chmod(0o400)

    with pytest.raises(StorageFailure, match="integrity"):
        store_private_copy(
            source,
            paths=paths,
            area="sanitized",
            maximum_bytes=1_024,
            expected_sha256="0" * 64,
        )

    assert list(paths.sanitized.iterdir()) == []
    assert list(paths.work.iterdir()) == []
