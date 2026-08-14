"""Storage key and path primitives that never depend on uploaded filenames."""

from __future__ import annotations

import re
import secrets
import stat
import unicodedata
from dataclasses import dataclass
from pathlib import Path, PurePath

from app.core.constants import OPAQUE_STORAGE_KEY_BYTES

_STORAGE_KEY_RE = re.compile(r"^[0-9a-f]{32}$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_BIDI_CONTROLS = frozenset("\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")


class InvalidStorageKey(ValueError):
    """Raised when a value is not a server-generated opaque storage key."""


def generate_storage_key() -> str:
    return secrets.token_hex(OPAQUE_STORAGE_KEY_BYTES)


def validate_storage_key(key: str) -> str:
    if PurePath(key).is_absolute() or not _STORAGE_KEY_RE.fullmatch(key):
        raise InvalidStorageKey("storage key must be exactly 32 lowercase hexadecimal characters")
    return key


def normalize_display_filename(filename: str, *, max_length: int = 255) -> str:
    """Normalize hostile filename metadata without making it suitable for storage paths."""

    value = unicodedata.normalize("NFC", filename)
    value = _CONTROL_RE.sub("", value).strip()
    value = "".join(character for character in value if character not in _BIDI_CONTROLS)
    value = value.replace("/", "_").replace("\\", "_")
    if value in {"", ".", ".."}:
        return "unnamed-document"
    return value[:max_length]


@dataclass(frozen=True, slots=True)
class StoragePaths:
    root: Path

    def __post_init__(self) -> None:
        object.__setattr__(self, "root", self.root.absolute())

    @property
    def incoming(self) -> Path:
        return self.root / "incoming"

    @property
    def quarantine(self) -> Path:
        return self.root / "quarantine"

    @property
    def sanitized(self) -> Path:
        return self.root / "sanitized"

    @property
    def work(self) -> Path:
        return self.root / "work"

    def initialize(self, *, strict_existing_permissions: bool = False) -> None:
        _reject_symlink_components(self.root)
        root_existed = self.root.exists()
        if strict_existing_permissions and root_existed:
            _require_private_directory(self.root)
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        if not strict_existing_permissions or not root_existed:
            self.root.chmod(0o700)
        for directory in (self.incoming, self.quarantine, self.sanitized, self.work):
            existed = directory.exists()
            if strict_existing_permissions and existed:
                _require_private_directory(directory)
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            if not stat.S_ISDIR(directory.stat(follow_symlinks=False).st_mode):
                raise RuntimeError("storage area is not a real directory")
            if not strict_existing_permissions or not existed:
                directory.chmod(0o700)

    def resolve(self, area: str, storage_key: str) -> Path:
        key = validate_storage_key(storage_key)
        directories = {
            "incoming": self.incoming,
            "quarantine": self.quarantine,
            "sanitized": self.sanitized,
            "work": self.work,
        }
        try:
            base = directories[area]
        except KeyError as exc:
            raise ValueError(f"unknown storage area: {area}") from exc

        candidate = (base / key).resolve()
        if not candidate.is_relative_to(self.root) or candidate.parent != base:
            raise InvalidStorageKey("resolved storage path escaped its storage area")
        return candidate


def _reject_symlink_components(path: Path) -> None:
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        if (current.exists() or current.is_symlink()) and current.is_symlink():
            raise RuntimeError("storage path must not contain symbolic links")


def _require_private_directory(path: Path) -> None:
    metadata = path.stat(follow_symlinks=False)
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o700:
        raise RuntimeError("existing production storage directory permissions are unsafe")
