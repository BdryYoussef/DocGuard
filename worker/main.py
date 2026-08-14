"""Dependency-free worker entry point for one disposable analysis process."""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from time import monotonic_ns

from docguard_contract import ANALYSIS_SCHEMA_VERSION, WORKER_VERSION
from worker.analyzers.file_type import FileFamily, IdentificationError, identify_file
from worker.analyzers.filename import claimed_extension, security_findings


def _parse_request(raw: str) -> dict[str, object]:
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("request must be an object")
    if value.get("schema_version") != ANALYSIS_SCHEMA_VERSION:
        raise ValueError("unsupported schema version")
    sample_path = value.get("sample_path")
    if not isinstance(sample_path, str) or not Path(sample_path).is_absolute():
        raise ValueError("sample path must be absolute")
    return value


def _run_pdf_analysis(
    sample_path: Path, detected_family: FileFamily
) -> tuple[list[dict[str, object]], dict[str, object], bool]:
    # The parser module is imported only after libmagic identifies PDF content.
    from worker.analyzers.pdf import analyze_pdf

    analysis = analyze_pdf(sample_path, detected_family=detected_family)
    return list(analysis.findings), analysis.metadata, analysis.complete


def _run_office_analysis(
    sample_path: Path, detected_family: FileFamily
) -> tuple[list[dict[str, object]], dict[str, object], bool, str] | None:
    # Office parsers are imported only after libmagic identifies a compatible container.
    from worker.analyzers.office import analyze_office

    analysis = analyze_office(sample_path, detected_family=detected_family)
    if analysis is None:
        return None
    return (
        list(analysis.findings),
        analysis.metadata,
        analysis.complete,
        analysis.detected_type,
    )


def _run_archive_analysis(
    sample_path: Path, detected_family: FileFamily
) -> tuple[list[dict[str, object]], dict[str, object], bool, str]:
    # Generic ZIP parsing occurs only after content identification and the OOXML gate.
    from worker.analyzers.archive import analyze_archive

    analysis = analyze_archive(sample_path, detected_family=detected_family)
    return (
        list(analysis.findings),
        analysis.metadata,
        analysis.complete,
        analysis.detected_type,
    )


def _run_yara_analysis(
    sample_path: Path,
) -> tuple[list[dict[str, object]], dict[str, object], bool]:
    # YARA scans only the fixed top-level sample after structural analysis.
    from worker.yara_engine import scan_top_level_file

    analysis = scan_top_level_file(sample_path)
    return list(analysis.findings), analysis.metadata, analysis.complete


def main() -> int:
    result: dict[str, object]
    try:
        request = _parse_request(sys.stdin.read())
        sample_path = Path(str(request["sample_path"]))
        if request.get("operation", "ANALYZE") == "SANITIZE_PDF":
            from worker.cdr import sanitize_pdf

            result = sanitize_pdf(sample_path, request)
            sys.stdout.write(
                json.dumps(result, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
            )
            return 0
        if request.get("operation", "ANALYZE") != "ANALYZE":
            raise ValueError("unsupported worker operation")
        started_at = datetime.now(UTC)
        started_ns = monotonic_ns()
        size_bytes = sample_path.stat().st_size
        identification = identify_file(sample_path)
        filename = request.get("original_filename", "unnamed-document")
        content_type = request.get("claimed_content_type")
        if not isinstance(filename, str) or not isinstance(content_type, (str, type(None))):
            raise ValueError("invalid filename metadata")
        findings = security_findings(filename, identification, content_type)
        pdf_metadata: dict[str, object] | None = None
        pdf_complete = True
        office_metadata: dict[str, object] | None = None
        office_complete = True
        archive_metadata: dict[str, object] | None = None
        archive_complete = True
        yara_metadata: dict[str, object] | None = None
        yara_complete = True
        detected_type = identification.family.value
        if identification.family is FileFamily.PDF:
            pdf_findings, pdf_metadata, pdf_complete = _run_pdf_analysis(
                sample_path, identification.family
            )
            findings.extend(pdf_findings)
        if identification.family in {
            FileFamily.ZIP,
            FileFamily.OOXML_CANDIDATE,
            FileFamily.OLE_COMPOUND,
        }:
            office_analysis = _run_office_analysis(sample_path, identification.family)
            if office_analysis is not None:
                office_findings, office_metadata, office_complete, detected_type = office_analysis
                findings.extend(office_findings)
            elif identification.family in {FileFamily.ZIP, FileFamily.OOXML_CANDIDATE}:
                (
                    archive_findings,
                    archive_metadata,
                    archive_complete,
                    detected_type,
                ) = _run_archive_analysis(sample_path, identification.family)
                findings.extend(archive_findings)
        yara_findings, yara_metadata, yara_complete = _run_yara_analysis(sample_path)
        findings.extend(yara_findings)
        completed_at = datetime.now(UTC)
        status = "SUCCESS" if identification.supported else "UNSUPPORTED"
        if identification.family is FileFamily.PDF and not pdf_complete:
            status = "FAILED"
        if office_metadata is not None and not office_complete:
            status = "FAILED"
        if archive_metadata is not None and not archive_complete:
            status = "FAILED"
        if not yara_complete:
            status = "FAILED"
        analyzer_metadata: dict[str, object] = {
            "analyzer": "libmagic-file",
            "detected_mime": identification.mime,
            "signature_description": identification.description,
            "claimed_extension": claimed_extension(filename),
        }
        if pdf_metadata is not None:
            analyzer_metadata["pdf"] = pdf_metadata
        if office_metadata is not None:
            analyzer_metadata["office"] = office_metadata
        if archive_metadata is not None:
            analyzer_metadata["archive"] = archive_metadata
        if yara_metadata is not None:
            analyzer_metadata["yara"] = yara_metadata
        result = {
            "schema_version": ANALYSIS_SCHEMA_VERSION,
            "worker_version": WORKER_VERSION,
            "status": status,
            "detected_type": detected_type,
            "size_bytes": size_bytes,
            "findings": findings,
            "analyzer_metadata": analyzer_metadata,
            "started_at": started_at.isoformat(),
            "completed_at": completed_at.isoformat(),
            "duration_ms": max(0, (monotonic_ns() - started_ns) // 1_000_000),
        }
    except IdentificationError:
        completed_at = datetime.now(UTC)
        result = {
            "schema_version": ANALYSIS_SCHEMA_VERSION,
            "worker_version": WORKER_VERSION,
            "status": "FAILED",
            "detected_type": None,
            "size_bytes": sample_path.stat().st_size if "sample_path" in locals() else 0,
            "findings": [],
            "analyzer_metadata": {
                "analyzer": "libmagic-file",
                "error_code": "file_identification_failed",
            },
            "started_at": started_at.isoformat(),
            "completed_at": completed_at.isoformat(),
            "duration_ms": max(0, (monotonic_ns() - started_ns) // 1_000_000),
        }
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        print(f"worker request failed: {type(exc).__name__}", file=sys.stderr)
        return 2
    sys.stdout.write(json.dumps(result, ensure_ascii=False, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
