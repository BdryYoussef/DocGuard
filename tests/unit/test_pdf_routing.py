from __future__ import annotations

import io
import json
import sys
from pathlib import Path

import pytest

from app.orchestrator.contract import WorkerRequest
from tests.fixtures.pdf_factory import write_benign_pdf
from tests.unit.test_file_identification import inert_pe_fixture
from worker import main as worker_main


def run_worker_main(
    path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    *,
    filename: str,
) -> dict[str, object]:
    request = WorkerRequest(
        job_id="a" * 32,
        sample_path=str(path.resolve()),
        original_filename=filename,
    )
    monkeypatch.setattr(sys, "stdin", io.StringIO(request.to_json()))
    assert worker_main.main() == 0
    payload = json.loads(capsys.readouterr().out)
    assert isinstance(payload, dict)
    return payload


def test_content_identified_pdf_routes_to_pdf_analyzer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = write_benign_pdf(tmp_path / "document")
    calls: list[Path] = []

    def controlled_pdf_analysis(
        sample_path: Path, detected_family: object
    ) -> tuple[list[dict[str, object]], dict[str, object], bool]:
        del detected_family
        calls.append(sample_path)
        return [], {"parser_status": "COMPLETE"}, True

    monkeypatch.setattr(worker_main, "_run_pdf_analysis", controlled_pdf_analysis)

    payload = run_worker_main(path, monkeypatch, capsys, filename="document.bin")

    assert calls == [path]
    assert payload["detected_type"] == "PDF"


@pytest.mark.parametrize("kind", ["text", "renamed-executable"])
def test_non_pdf_content_never_routes_to_pdf_analyzer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    kind: str,
) -> None:
    path = tmp_path / "sample"
    if kind == "text":
        path.write_text("harmless fixture", encoding="utf-8")
    else:
        path.write_bytes(inert_pe_fixture())

    def forbidden_pdf_analysis(
        sample_path: Path, detected_family: object
    ) -> tuple[list[dict[str, object]], dict[str, object], bool]:
        del sample_path, detected_family
        raise AssertionError("non-PDF content reached the PDF analyzer")

    monkeypatch.setattr(worker_main, "_run_pdf_analysis", forbidden_pdf_analysis)

    payload = run_worker_main(path, monkeypatch, capsys, filename="invoice.pdf")

    assert payload["detected_type"] in {"TEXT", "WINDOWS_EXECUTABLE"}
