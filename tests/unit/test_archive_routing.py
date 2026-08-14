from __future__ import annotations

import io
import json
import sys
from pathlib import Path

import pytest

from app.orchestrator.contract import WorkerRequest
from tests.fixtures.archive_factory import archive_bytes
from tests.fixtures.office_factory import write_ooxml
from tests.unit.test_file_identification import inert_pe_fixture
from worker import main as worker_main
from worker.analyzers.office_types import OfficeApplication


def run_worker(
    path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    *,
    filename: str,
) -> dict[str, object]:
    request = WorkerRequest(
        job_id="c" * 32,
        sample_path=str(path.resolve()),
        original_filename=filename,
    )
    monkeypatch.setattr(sys, "stdin", io.StringIO(request.to_json()))
    assert worker_main.main() == 0
    payload = json.loads(capsys.readouterr().out)
    assert isinstance(payload, dict)
    return payload


def test_content_identified_generic_zip_routes_to_archive_analyzer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = tmp_path / "archive"
    path.write_bytes(archive_bytes([("fixture.txt", b"fixture")]))
    calls: list[Path] = []

    def controlled_archive(
        sample_path: Path, detected_family: object
    ) -> tuple[list[dict[str, object]], dict[str, object], bool, str]:
        del detected_family
        calls.append(sample_path)
        return [], {"parser_status": "COMPLETE"}, True, "ZIP"

    monkeypatch.setattr(worker_main, "_run_archive_analysis", controlled_archive)
    payload = run_worker(path, monkeypatch, capsys, filename="renamed.bin")

    assert calls == [path]
    assert payload["detected_type"] == "ZIP"


def test_valid_ooxml_keeps_office_precedence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = write_ooxml(tmp_path / "document", application=OfficeApplication.WORD)

    def forbidden_archive(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise AssertionError("valid OOXML reached generic archive analyzer")

    monkeypatch.setattr(worker_main, "_run_archive_analysis", forbidden_archive)
    payload = run_worker(path, monkeypatch, capsys, filename="document.zip")

    assert payload["detected_type"] == "OFFICE_WORD_OOXML"
    assert "office" in payload["analyzer_metadata"]  # type: ignore[operator]
    assert "archive" not in payload["analyzer_metadata"]  # type: ignore[operator]


def test_generic_zip_named_docx_remains_archive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = tmp_path / "generic"
    path.write_bytes(archive_bytes([("fixture.txt", b"fixture")]))

    payload = run_worker(path, monkeypatch, capsys, filename="invoice.docx")

    assert payload["detected_type"] == "ZIP"
    assert "archive" in payload["analyzer_metadata"]  # type: ignore[operator]
    assert "office" not in payload["analyzer_metadata"]  # type: ignore[operator]


def test_executable_named_zip_never_reaches_archive_parser(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = tmp_path / "executable"
    path.write_bytes(inert_pe_fixture())

    def forbidden_archive(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise AssertionError("executable reached generic archive analyzer")

    monkeypatch.setattr(worker_main, "_run_archive_analysis", forbidden_archive)
    payload = run_worker(path, monkeypatch, capsys, filename="invoice.zip")

    assert payload["detected_type"] == "WINDOWS_EXECUTABLE"
