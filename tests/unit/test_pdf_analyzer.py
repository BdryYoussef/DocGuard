from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.fixtures.pdf_factory import (
    HARMLESS_SCRIPT,
    write_acroform_pdf,
    write_action_chain_pdf,
    write_action_classes_pdf,
    write_action_cycle_pdf,
    write_additional_action_pdf,
    write_benign_pdf,
    write_embedded_file_pdf,
    write_encrypted_pdf,
    write_javascript_name_tree_pdf,
    write_javascript_pdf,
    write_launch_action_pdf,
    write_malformed_pdf,
    write_multiple_actions_pdf,
    write_open_action_pdf,
    write_open_destination_pdf,
    write_uri_action_chain_pdf,
    write_uri_action_pdf,
)
from worker.analyzers.file_type import FileFamily
from worker.analyzers.pdf import (
    PdfAnalysis,
    PdfAnalysisLimits,
    PdfParserStatus,
    PdfRoutingError,
    analyze_pdf,
)


def analyze(path: Path, limits: PdfAnalysisLimits | None = None) -> PdfAnalysis:
    arguments = {"detected_family": FileFamily.PDF}
    if limits is not None:
        arguments["limits"] = limits  # type: ignore[assignment]
    return analyze_pdf(path, **arguments)  # type: ignore[arg-type]


def codes(result: PdfAnalysis) -> set[str]:
    return {str(finding["code"]) for finding in result.findings}


def finding(result: PdfAnalysis, code: str) -> dict[str, object]:
    return next(item for item in result.findings if item["code"] == code)


def test_benign_and_multipage_pdf_have_bounded_correct_metadata(tmp_path: Path) -> None:
    result = analyze(write_benign_pdf(tmp_path / "benign.pdf", pages=3))

    assert result.parser_status is PdfParserStatus.COMPLETE
    assert result.findings == ()
    assert result.metadata["page_count"] == 3
    assert result.metadata["pages_inspected"] == 3
    assert result.metadata["parser_version"] == "10.11.0"
    assert len(json.dumps(result.metadata)) < 4_096


def test_javascript_action_and_name_tree_are_structurally_detected(tmp_path: Path) -> None:
    action = analyze(write_javascript_pdf(tmp_path / "action.pdf"))
    name_tree = analyze(write_javascript_name_tree_pdf(tmp_path / "name-tree.pdf"))

    assert {"PDF_JAVASCRIPT", "PDF_OPEN_ACTION"}.issubset(codes(action))
    assert codes(name_tree) == {"PDF_JAVASCRIPT"}
    name_tree_metadata = finding(name_tree, "PDF_JAVASCRIPT")["metadata"]
    assert isinstance(name_tree_metadata, dict)
    assert name_tree_metadata["name_tree_entry_count"] == 1
    assert HARMLESS_SCRIPT not in json.dumps(action.findings)
    assert HARMLESS_SCRIPT not in json.dumps(action.metadata)


def test_javascript_keyword_in_page_text_is_not_a_structural_finding(tmp_path: Path) -> None:
    result = analyze(write_benign_pdf(tmp_path / "text.pdf", keyword_text=True))

    assert "PDF_JAVASCRIPT" not in codes(result)
    assert result.parser_status is PdfParserStatus.COMPLETE


def test_open_additional_and_launch_actions_are_explainable(tmp_path: Path) -> None:
    open_action = analyze(write_open_action_pdf(tmp_path / "open.pdf"))
    open_destination = analyze(write_open_destination_pdf(tmp_path / "destination.pdf"))
    additional = analyze(write_additional_action_pdf(tmp_path / "additional.pdf"))
    launch = analyze(write_launch_action_pdf(tmp_path / "launch.pdf"))

    open_metadata = finding(open_action, "PDF_OPEN_ACTION")["metadata"]
    assert isinstance(open_metadata, dict)
    assert open_metadata == {"kind": "action", "action_type": "GoTo"}
    destination_metadata = finding(open_destination, "PDF_OPEN_ACTION")["metadata"]
    assert isinstance(destination_metadata, dict)
    assert destination_metadata == {"kind": "destination", "action_type": None}
    additional_metadata = finding(additional, "PDF_ADDITIONAL_ACTION")["metadata"]
    assert isinstance(additional_metadata, dict)
    assert additional_metadata["triggers"] == ["WC"]
    assert additional_metadata["action_types"] == ["GoTo"]
    assert {"PDF_OPEN_ACTION", "PDF_LAUNCH_ACTION"}.issubset(codes(launch))


def test_uri_action_retains_only_bounded_lexical_metadata(tmp_path: Path) -> None:
    result = analyze(write_uri_action_pdf(tmp_path / "uri.pdf"))

    metadata = finding(result, "PDF_EXTERNAL_URI")["metadata"]
    assert isinstance(metadata, dict)
    assert metadata["count"] == 1
    assert metadata["targets"] == [
        {
            "parse_status": "parsed",
            "scheme": "https",
            "hostname": "example.invalid",
        }
    ]
    serialized = json.dumps(metadata)
    assert "private-fixture" not in serialized
    assert "#fragment" not in serialized


def test_embedded_file_is_counted_without_extraction_or_path_use(tmp_path: Path) -> None:
    result = analyze(write_embedded_file_pdf(tmp_path / "attachment.pdf"))

    metadata = finding(result, "PDF_EMBEDDED_FILE")["metadata"]
    assert isinstance(metadata, dict)
    assert metadata["count"] == 1
    assert metadata["display_names"] == [".._.._harmless-note.txt"]
    assert not (tmp_path / "harmless-note.txt").exists()


@pytest.mark.parametrize("xfa", [False, True])
def test_acroform_and_xfa_are_capability_findings(tmp_path: Path, xfa: bool) -> None:
    result = analyze(write_acroform_pdf(tmp_path / f"form-{xfa}.pdf", xfa=xfa))

    assert "PDF_ACROFORM" in codes(result)
    assert ("PDF_XFA" in codes(result)) is xfa


def test_encrypted_pdf_is_partial_without_password_attempts(tmp_path: Path) -> None:
    result = analyze(write_encrypted_pdf(tmp_path / "encrypted.pdf"))

    assert result.parser_status is PdfParserStatus.PARTIAL
    assert {"PDF_ENCRYPTED", "PDF_PARTIAL_ANALYSIS"}.issubset(codes(result))
    assert result.metadata["parser_exception"] == "PasswordError"
    assert result.metadata["page_count"] is None


def test_malformed_pdf_returns_controlled_malformed_result(tmp_path: Path) -> None:
    result = analyze(write_malformed_pdf(tmp_path / "malformed.pdf"))

    assert result.parser_status is PdfParserStatus.MALFORMED
    assert codes(result) == {"PDF_MALFORMED", "PDF_PARTIAL_ANALYSIS"}
    assert result.metadata["parser_exception"] == "PdfError"


def test_multiple_action_types_are_discovered_without_unbounded_graph_walk(
    tmp_path: Path,
) -> None:
    result = analyze(write_multiple_actions_pdf(tmp_path / "multiple.pdf"))

    assert {
        "PDF_JAVASCRIPT",
        "PDF_OPEN_ACTION",
        "PDF_ADDITIONAL_ACTION",
        "PDF_LAUNCH_ACTION",
        "PDF_EXTERNAL_URI",
    }.issubset(codes(result))
    assert result.metadata["action_nodes_visited"] == 3


def test_action_walker_classifies_remote_form_data_and_unknown_actions(
    tmp_path: Path,
) -> None:
    result = analyze(write_action_classes_pdf(tmp_path / "classes.pdf"))

    assert result.metadata["action_types"] == {
        "GoTo": 1,
        "GoToR": 1,
        "ImportData": 1,
        "SubmitForm": 1,
        "Unknown:UnrecognizedFixtureAction": 1,
    }


def test_indirect_action_cycle_is_broken_by_visited_object_tracking(tmp_path: Path) -> None:
    result = analyze(write_action_cycle_pdf(tmp_path / "cycle.pdf"))

    assert result.parser_status is PdfParserStatus.COMPLETE
    assert result.metadata["action_nodes_visited"] == 1
    assert result.metadata["action_types"] == {"GoTo": 1}


@pytest.mark.parametrize(
    ("limits", "reason"),
    [
        (PdfAnalysisLimits(max_action_depth=2), "action_depth_limit"),
        (PdfAnalysisLimits(max_action_nodes=2), "action_node_limit"),
        (PdfAnalysisLimits(max_objects=2), "indirect_object_limit"),
        (PdfAnalysisLimits(max_pages=1), "page_limit"),
    ],
)
def test_low_configured_limits_create_partial_analysis(
    tmp_path: Path, limits: PdfAnalysisLimits, reason: str
) -> None:
    path = (
        write_benign_pdf(tmp_path / f"{reason}.pdf", pages=2)
        if reason == "page_limit"
        else write_action_chain_pdf(tmp_path / f"{reason}.pdf", action_count=10)
    )

    result = analyze(path, limits)

    assert result.parser_status is PdfParserStatus.PARTIAL
    assert "PDF_PARTIAL_ANALYSIS" in codes(result)
    assert reason in result.metadata["partial_reasons"]


def test_uri_metadata_length_is_capped(tmp_path: Path) -> None:
    result = analyze(
        write_uri_action_pdf(
            tmp_path / "long-uri.pdf",
            uri="https://" + "a" * 500 + ".example.invalid/private?secret=value",
        ),
        PdfAnalysisLimits(max_metadata_string_length=24),
    )

    metadata = finding(result, "PDF_EXTERNAL_URI")["metadata"]
    assert isinstance(metadata, dict)
    targets = metadata["targets"]
    assert isinstance(targets, list)
    assert all(
        len(value) <= 24
        for target in targets
        if isinstance(target, dict)
        for value in target.values()
        if isinstance(value, str)
    )


def test_uri_action_and_summary_limits_are_independent_and_fail_closed(
    tmp_path: Path,
) -> None:
    result = analyze(
        write_uri_action_chain_pdf(tmp_path / "many-uris.pdf", action_count=5),
        PdfAnalysisLimits(max_uri_count=2, max_uri_metadata_entries=1),
    )

    metadata = finding(result, "PDF_EXTERNAL_URI")["metadata"]
    assert isinstance(metadata, dict)
    assert metadata["count"] == 5
    assert metadata["targets_capped"] is True
    assert len(metadata["targets"]) == 1  # type: ignore[arg-type]
    assert result.parser_status is PdfParserStatus.PARTIAL
    assert "uri_action_limit" in result.metadata["partial_reasons"]


def test_pdf_analyzer_rejects_internal_non_pdf_routing(tmp_path: Path) -> None:
    path = tmp_path / "not-pdf"
    path.write_text("fixture", encoding="utf-8")

    with pytest.raises(PdfRoutingError):
        analyze_pdf(path, detected_family=FileFamily.TEXT)
