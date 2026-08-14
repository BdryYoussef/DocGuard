"""Controlled sandbox self-test probe; never used to inspect submitted content."""

from __future__ import annotations

import json
import os
import resource
import socket
import sys
import time
import zipfile
from pathlib import Path

from docguard_contract.cdr import PDF_CDR_ENGINE_VERSION, PDF_CDR_RENDERER_VERSION
from worker.constants import (
    OFFICE_OLE_PARSER_VERSION,
    OFFICE_PYPARSING_VERSION,
    OFFICE_VBA_PARSER_VERSION,
    OFFICE_XML_PARSER_VERSION,
    PDF_ENGINE_VERSION,
    PDF_PARSER_VERSION,
    YARA_PYTHON_VERSION,
    YARA_RUNTIME_VERSION,
)
from worker.yara_engine import rule_pack_path, yara_production_self_test


def _cannot_write(path: Path) -> bool:
    try:
        with path.open("ab") as stream:
            stream.write(b"x")
    except OSError:
        return True
    return False


def _network_blocked() -> bool:
    interfaces = {name for _, name in socket.if_nameindex()}
    if not interfaces or not interfaces.issubset({"lo"}):
        return False
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(0.25)
    try:
        sock.connect(("1.1.1.1", 53))
    except OSError:
        return True
    finally:
        sock.close()
    return False


def _capabilities_dropped() -> bool:
    status = Path("/proc/self/status").read_text(encoding="utf-8")
    capability_values = {
        key: int(value, 16)
        for line in status.splitlines()
        if (key := line.partition(":")[0]) in {"CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"}
        for value in [line.partition(":")[2].strip()]
    }
    return len(capability_values) == 5 and all(value == 0 for value in capability_values.values())


def _resource_limits_applied(request: dict[str, object]) -> bool:
    expected = (
        (resource.RLIMIT_AS, _required_int(request, "memory_limit")),
        (resource.RLIMIT_NOFILE, _required_int(request, "open_files_limit")),
        (resource.RLIMIT_FSIZE, _required_int(request, "file_size_limit")),
        (resource.RLIMIT_CPU, _required_int(request, "cpu_limit")),
        (resource.RLIMIT_CORE, 0),
    )
    return all(resource.getrlimit(limit) == (value, value) for limit, value in expected)


def _required_int(request: dict[str, object], key: str) -> int:
    value = request.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{key} must be an integer")
    return value


def _worker_dependencies_load() -> bool:
    try:
        import defusedxml
        import olefile
        import pikepdf
        import pymupdf
        import pyparsing
        import yara
        from oletools import olevba
    except ImportError:
        return False
    return all(
        (
            pikepdf.__version__ == PDF_PARSER_VERSION,
            pikepdf.__libqpdf_version__ == PDF_ENGINE_VERSION,
            olevba.__version__ == OFFICE_VBA_PARSER_VERSION,
            olefile.__version__ == OFFICE_OLE_PARSER_VERSION,
            defusedxml.__version__ == OFFICE_XML_PARSER_VERSION,
            pyparsing.__version__ == OFFICE_PYPARSING_VERSION,
            yara.__version__ == YARA_PYTHON_VERSION,
            yara.YARA_VERSION == YARA_RUNTIME_VERSION,
            pymupdf.VersionBind == PDF_CDR_RENDERER_VERSION,
            pymupdf.VersionFitz == PDF_CDR_ENGINE_VERSION,
        )
    )


def _archive_runtime_loads() -> bool:
    try:
        import bz2
        import lzma
        import zlib
    except ImportError:
        return False
    del bz2, lzma, zlib
    return all(
        isinstance(getattr(zipfile, name, None), int)
        for name in ("ZIP_STORED", "ZIP_DEFLATED", "ZIP_BZIP2", "ZIP_LZMA")
    )


def main() -> int:
    request = json.loads(sys.stdin.read())
    mode = request.get("mode", "boundary")
    if mode == "sleep":
        time.sleep(30)
        return 0
    if mode == "output":
        stream = sys.stderr if request.get("stream") == "stderr" else sys.stdout
        stream.write("X" * int(request.get("bytes", 1_000_000)))
        return 0
    if mode == "cdr_boundary":
        output = Path("/output/document")
        output.write_bytes(b"cdr-output-ok")
        result = {
            "output_writable": output.read_bytes() == b"cdr-output-ok",
            "output_contained": (
                _cannot_write(Path("/output/escape"))
                and len(list(Path("/output").iterdir())) == 1
                and _cannot_write(Path("/input/document"))
                and not Path("/opt/docguard-runtime/app").exists()
                and not Path(str(request["project_path"])).exists()
                and not Path(str(request["sanitized_path"])).exists()
                and not Path(str(request["parent_sentinel_path"])).exists()
                and "DOCGUARD_PARENT_SECRET" not in os.environ
                and _network_blocked()
                and _capabilities_dropped()
                and _resource_limits_applied(request)
            ),
            "resource_limits_applied": _resource_limits_applied(request),
        }
        sys.stdout.write(json.dumps(result, separators=(",", ":"), sort_keys=True))
        return 0

    input_path = Path("/input/document")
    work_probe = Path("/work/probe")
    outside_probe = Path("/outside-probe")
    work_probe.write_bytes(b"work-ok")
    result = {
        "process_executes": True,
        "network_blocked": _network_blocked(),
        "parent_file_hidden": not Path(str(request["parent_sentinel_path"])).exists(),
        "parent_environment_hidden": "DOCGUARD_PARENT_SECRET" not in os.environ,
        "outside_write_blocked": _cannot_write(outside_probe),
        "input_readable": input_path.read_bytes() == b"docguard-self-test",
        "input_read_only": _cannot_write(input_path),
        "work_writable": work_probe.read_bytes() == b"work-ok",
        "trusted_paths_hidden": (
            not Path(str(request["project_path"])).exists()
            and not Path("/opt/docguard-runtime/app").exists()
        ),
        "capabilities_dropped": _capabilities_dropped(),
        "resource_limits_applied": _resource_limits_applied(request),
        "worker_dependencies_load": _worker_dependencies_load(),
        "renderer_runtime_loads": _worker_dependencies_load(),
        "archive_runtime_loads": _archive_runtime_loads(),
        "yara_rule_pack_qualifies": yara_production_self_test(),
        "yara_rules_read_only": rule_pack_path().is_file() and _cannot_write(rule_pack_path()),
    }
    sys.stdout.write(json.dumps(result, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
