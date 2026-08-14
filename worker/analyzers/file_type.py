"""Content identification through the local libmagic-backed `file` utility."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

_FILE_COMMAND = "/usr/bin/file"
_FILE_TIMEOUT_SECONDS = 2.0
_MAX_DESCRIPTION_BYTES = 2_048


class FileFamily(StrEnum):
    PDF = "PDF"
    ZIP = "ZIP"
    OOXML_CANDIDATE = "OOXML_CANDIDATE"
    OLE_COMPOUND = "OLE_COMPOUND"
    WINDOWS_EXECUTABLE = "WINDOWS_EXECUTABLE"
    TEXT = "TEXT"
    UNKNOWN = "UNKNOWN"


class IdentificationError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class FileIdentification:
    mime: str
    family: FileFamily
    description: str

    @property
    def supported(self) -> bool:
        return self.family is not FileFamily.UNKNOWN


def identify_file(sample_path: Path) -> FileIdentification:
    mime = _run_file(("--brief", "--mime-type", "--", str(sample_path)))
    description = _run_file(("--brief", "--", str(sample_path)))
    return FileIdentification(
        mime=mime,
        family=_classify(mime, description),
        description=description,
    )


def _run_file(arguments: tuple[str, ...]) -> str:
    try:
        completed = subprocess.run(  # noqa: S603 - fixed absolute libmagic frontend
            [_FILE_COMMAND, *arguments],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
            timeout=_FILE_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise IdentificationError("libmagic execution failed") from exc
    if completed.returncode != 0:
        raise IdentificationError("libmagic returned a failure status")
    output = completed.stdout[:_MAX_DESCRIPTION_BYTES].decode("utf-8", errors="replace").strip()
    if not output:
        raise IdentificationError("libmagic returned an empty identification")
    return output


def _classify(mime: str, description: str) -> FileFamily:
    normalized_mime = mime.casefold()
    normalized_description = description.casefold()
    if normalized_mime == "application/pdf" or "pdf document" in normalized_description:
        return FileFamily.PDF
    if normalized_mime in {
        "application/vnd.microsoft.portable-executable",
        "application/x-dosexec",
    } or normalized_description.startswith(("pe32", "pe ", "ms-dos executable")):
        return FileFamily.WINDOWS_EXECUTABLE
    if normalized_mime in {
        "application/msword",
        "application/encrypted",
        "application/vnd.ms-excel",
        "application/vnd.ms-powerpoint",
        "application/x-ole-storage",
    } or any(marker in normalized_description for marker in ("composite document file", "cdfv2 ")):
        return FileFamily.OLE_COMPOUND
    if "officedocument" in normalized_mime or any(
        marker in normalized_description
        for marker in (
            "microsoft word 2007+",
            "microsoft excel 2007+",
            "microsoft powerpoint 2007+",
        )
    ):
        return FileFamily.OOXML_CANDIDATE
    if normalized_mime in {"application/zip", "application/x-zip"} or "zip archive" in (
        normalized_description
    ):
        return FileFamily.ZIP
    if normalized_mime.startswith("text/") or normalized_description.endswith(" text"):
        return FileFamily.TEXT
    return FileFamily.UNKNOWN
