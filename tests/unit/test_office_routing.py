from __future__ import annotations

import io
import json
import sys
from pathlib import Path

import pytest

from app.orchestrator.contract import WorkerRequest
from tests.fixtures.office_factory import write_classic_ole, write_generic_zip, write_ooxml
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
        job_id="b" * 32,
        sample_path=str(path.resolve()),
        original_filename=filename,
    )
    monkeypatch.setattr(sys, "stdin", io.StringIO(request.to_json()))
    assert worker_main.main() == 0
    payload = json.loads(capsys.readouterr().out)
    assert isinstance(payload, dict)
    return payload


def test_content_identified_ooxml_and_ole_route_to_office_analyzer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    docx = write_ooxml(tmp_path / "word", application=OfficeApplication.WORD)
    ole = write_classic_ole(tmp_path / "classic")

    docx_payload = run_worker(docx, monkeypatch, capsys, filename="renamed.bin")
    ole_payload = run_worker(ole, monkeypatch, capsys, filename="renamed.bin")

    assert docx_payload["detected_type"] == "OFFICE_WORD_OOXML"
    assert ole_payload["detected_type"] == "OFFICE_WORD_OLE"


def test_generic_zip_is_not_promoted_to_office(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    payload = run_worker(
        write_generic_zip(tmp_path / "generic.zip"),
        monkeypatch,
        capsys,
        filename="invoice.docx",
    )

    assert payload["detected_type"] == "ZIP"
    assert "office" not in payload["analyzer_metadata"]  # type: ignore[operator]
    assert "archive" in payload["analyzer_metadata"]  # type: ignore[operator]


@pytest.mark.parametrize("filename", ["invoice.docx", "invoice.xls"])
def test_executable_masquerade_never_reaches_office_parser(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    filename: str,
) -> None:
    path = tmp_path / "executable"
    path.write_bytes(inert_pe_fixture())

    def forbidden_office_analysis(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise AssertionError("executable reached Office parser")

    monkeypatch.setattr(worker_main, "_run_office_analysis", forbidden_office_analysis)
    payload = run_worker(path, monkeypatch, capsys, filename=filename)

    assert payload["detected_type"] == "WINDOWS_EXECUTABLE"
    codes = {item["code"] for item in payload["findings"]}  # type: ignore[index]
    assert "FILE_EXECUTABLE_MASQUERADE" in codes
