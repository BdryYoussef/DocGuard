"""Regression tests for the four PDF explainability improvements:

1. Bounded lexical fallback evidence when structural analysis is incomplete.
2. GoToE action-type recognition (no more "Unknown:GoToE").
3. External SubmitForm target detection (PDF_EXTERNAL_SUBMISSION).
4. Bounded behavior-indicator enrichment on structurally-confirmed PDF_JAVASCRIPT.

These reproduce the underlying PDF *structures* an external corpus exposed gaps
for, not specific external test files.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.fixtures.pdf_factory import (
    write_acroform_pdf,
    write_benign_pdf,
    write_external_submit_form_pdf,
    write_gotoe_additional_action_pdf,
    write_javascript_behavior_pdf,
    write_local_submit_form_pdf,
    write_malformed_pdf,
    write_malformed_pdf_with_benign_mentions,
    write_malformed_pdf_with_hex_escaped_indicator_name,
    write_malformed_pdf_with_indicator_names,
)
from worker.analyzers.file_type import FileFamily
from worker.analyzers.pdf import PdfAnalysis, PdfAnalysisLimits, PdfParserStatus, analyze_pdf
from worker.analyzers.pdf_fallback import (
    FALLBACK_INDICATOR_TOKENS,
    PdfFallbackLimits,
    scan_for_fallback_indicators,
)


def analyze(path: Path, limits: PdfAnalysisLimits | None = None) -> PdfAnalysis:
    arguments = {"detected_family": FileFamily.PDF}
    if limits is not None:
        arguments["limits"] = limits  # type: ignore[assignment]
    return analyze_pdf(path, **arguments)  # type: ignore[arg-type]


def codes(result: PdfAnalysis) -> set[str]:
    return {str(item["code"]) for item in result.findings}


def finding(result: PdfAnalysis, code: str) -> dict[str, object]:
    return next(item for item in result.findings if item["code"] == code)


# ---------------------------------------------------------------------------
# 1a. Fallback lexical scanner — pure unit tests, no PDF parsing involved.
# ---------------------------------------------------------------------------


def test_fallback_scan_finds_plain_name_tokens() -> None:
    scan = scan_for_fallback_indicators(b"<< /JavaScript true /OpenAction true >>")
    assert scan.indicator_counts == {"JavaScript": 1, "OpenAction": 1}
    assert scan.truncated is False


def test_fallback_scan_decodes_hex_escaped_name_tokens() -> None:
    encoded = "".join(f"#{byte:02x}" for byte in b"JavaScript")
    scan = scan_for_fallback_indicators(f"/{encoded} true".encode("ascii"))
    assert scan.indicator_counts == {"JavaScript": 1}


def test_fallback_scan_ignores_bare_words_without_a_leading_slash() -> None:
    scan = scan_for_fallback_indicators(
        b"(This casually mentions JavaScript and OpenAction in prose.)"
    )
    assert scan.indicator_counts == {}


def test_fallback_scan_distinguishes_similar_prefixed_tokens() -> None:
    scan = scan_for_fallback_indicators(b"/JavaScript /JS /AA /AcroForm")
    assert scan.indicator_counts == {"JavaScript": 1, "JS": 1, "AA": 1, "AcroForm": 1}


def test_fallback_scan_never_emits_a_token_outside_the_fixed_vocabulary() -> None:
    scan = scan_for_fallback_indicators(b"/JavaScript /TotallyMadeUpName")
    assert set(scan.indicator_counts) <= set(FALLBACK_INDICATOR_TOKENS)


def test_fallback_scan_hit_count_is_bounded() -> None:
    limits = PdfFallbackLimits(max_hit_count=5)
    scan = scan_for_fallback_indicators(b"/URI " * 100, limits=limits)
    assert scan.indicator_counts["URI"] == 5


def test_fallback_scan_reports_truncation_beyond_the_byte_cap() -> None:
    limits = PdfFallbackLimits(max_scan_bytes=8)
    scan = scan_for_fallback_indicators(b"0123456789/JavaScript", limits=limits)
    assert scan.truncated is True
    # The indicator token itself was outside the 8-byte scan window.
    assert scan.indicator_counts == {}


# ---------------------------------------------------------------------------
# 1b. Fallback evidence wired into the worker analyzer, fail-closed guarantees.
# ---------------------------------------------------------------------------


def test_parser_rejected_pdf_with_js_and_openaction_reports_bounded_fallback_evidence(
    tmp_path: Path,
) -> None:
    """Reproduces the class of case where a raw PDF's /OpenAction + /JavaScript
    were present in the bytes but the parser could not open the file at all."""
    path = write_malformed_pdf_with_indicator_names(
        tmp_path / "rejected.pdf", names=("JavaScript", "OpenAction")
    )
    result = analyze(path)

    assert result.parser_status is PdfParserStatus.MALFORMED
    assert result.complete is False
    assert codes(result) >= {"PDF_MALFORMED", "PDF_PARTIAL_ANALYSIS", "PDF_FALLBACK_INDICATOR"}
    # Not structurally confirmed — the parser never traversed this file.
    assert "PDF_JAVASCRIPT" not in codes(result)
    assert "PDF_OPEN_ACTION" not in codes(result)

    fallback = finding(result, "PDF_FALLBACK_INDICATOR")
    assert fallback["metadata"]["confidence"] == "lexical_only"
    assert set(fallback["metadata"]["indicators"]) == {"JavaScript", "OpenAction"}


def test_parser_rejected_pdf_with_acroform_and_xfa_reports_bounded_fallback_evidence(
    tmp_path: Path,
) -> None:
    path = write_malformed_pdf_with_indicator_names(
        tmp_path / "rejected.pdf", names=("AcroForm", "XFA")
    )
    result = analyze(path)

    assert result.parser_status is PdfParserStatus.MALFORMED
    assert result.complete is False
    fallback = finding(result, "PDF_FALLBACK_INDICATOR")
    assert set(fallback["metadata"]["indicators"]) == {"AcroForm", "XFA"}
    assert "PDF_ACROFORM" not in codes(result)
    assert "PDF_XFA" not in codes(result)


def test_parser_rejected_pdf_with_hex_escaped_token_still_reports_fallback_evidence(
    tmp_path: Path,
) -> None:
    path = write_malformed_pdf_with_hex_escaped_indicator_name(tmp_path / "obfuscated.pdf")
    result = analyze(path)

    fallback = finding(result, "PDF_FALLBACK_INDICATOR")
    assert "JavaScript" in fallback["metadata"]["indicators"]


def test_benign_prose_mentioning_indicator_words_does_not_produce_fallback_evidence(
    tmp_path: Path,
) -> None:
    path = write_malformed_pdf_with_benign_mentions(tmp_path / "benign-mentions.pdf")
    result = analyze(path)

    assert result.parser_status is PdfParserStatus.MALFORMED
    assert "PDF_FALLBACK_INDICATOR" not in codes(result)


def test_plain_malformed_pdf_without_indicators_reports_no_fallback_finding(
    tmp_path: Path,
) -> None:
    result = analyze(write_malformed_pdf(tmp_path / "malformed.pdf"))
    assert "PDF_FALLBACK_INDICATOR" not in codes(result)


def test_complete_analysis_never_runs_the_fallback_scan(tmp_path: Path) -> None:
    result = analyze(write_benign_pdf(tmp_path / "benign.pdf"))
    assert result.parser_status is PdfParserStatus.COMPLETE
    assert "PDF_FALLBACK_INDICATOR" not in codes(result)


def test_fallback_evidence_never_flips_analysis_completeness_to_true(tmp_path: Path) -> None:
    path = write_malformed_pdf_with_indicator_names(
        tmp_path / "rejected.pdf", names=("JavaScript", "OpenAction", "AcroForm", "XFA")
    )
    result = analyze(path)

    # However much fallback evidence exists, this must still fail closed.
    assert result.complete is False
    assert result.parser_status is not PdfParserStatus.COMPLETE
    assert "PDF_MALFORMED" in codes(result)


# ---------------------------------------------------------------------------
# 2. GoToE recognition.
# ---------------------------------------------------------------------------


def test_gotoe_additional_action_is_recognized_not_unknown(tmp_path: Path) -> None:
    result = analyze(write_gotoe_additional_action_pdf(tmp_path / "gotoe.pdf"))

    assert result.parser_status is PdfParserStatus.COMPLETE
    additional = finding(result, "PDF_ADDITIONAL_ACTION")
    assert additional["metadata"]["action_types"] == ["GoToE"]
    assert not any(
        str(name).startswith("Unknown:") for name in additional["metadata"]["action_types"]
    )
    assert result.metadata["action_types"] == {"GoToE": 1}


# ---------------------------------------------------------------------------
# 3. External SubmitForm detection.
# ---------------------------------------------------------------------------


def test_external_submit_form_is_reported_with_bounded_scheme_and_hostname(
    tmp_path: Path,
) -> None:
    path = write_external_submit_form_pdf(
        tmp_path / "submit.pdf", target="https://example.invalid/submit?secret=leak-me-not"
    )
    result = analyze(path)

    assert "PDF_EXTERNAL_SUBMISSION" in codes(result)
    submission = finding(result, "PDF_EXTERNAL_SUBMISSION")
    assert submission["metadata"]["count"] == 1
    target = submission["metadata"]["targets"][0]
    assert target["scheme"] == "https"
    assert target["hostname"] == "example.invalid"
    # No query string, full path, or full URL anywhere in the bounded metadata.
    serialized = str(submission["metadata"])
    assert "secret" not in serialized
    assert "leak-me-not" not in serialized
    assert "https://example.invalid/submit" not in serialized

    # The pre-existing action-type signal is unaffected.
    open_action = finding(result, "PDF_OPEN_ACTION")
    assert open_action["metadata"]["action_type"] == "SubmitForm"


def test_local_submit_form_target_does_not_produce_external_submission_finding(
    tmp_path: Path,
) -> None:
    result = analyze(write_local_submit_form_pdf(tmp_path / "local-submit.pdf"))
    assert "PDF_EXTERNAL_SUBMISSION" not in codes(result)
    assert finding(result, "PDF_OPEN_ACTION")["metadata"]["action_type"] == "SubmitForm"


# ---------------------------------------------------------------------------
# 4. Bounded JavaScript behavior indicators.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("script", "expected"),
    [
        ("this.submitForm({cURL: 'https://example.invalid/x'});", "external_submission_api"),
        ("app.launchURL('https://example.invalid/y');", "external_url_open_api"),
        ("var request = new XMLHttpRequest();", "external_network_api"),
        ("var value = this.getField('name').value;", "document_content_access"),
    ],
)
def test_structurally_confirmed_javascript_reports_bounded_behavior_indicators(
    tmp_path: Path, script: str, expected: str
) -> None:
    path = write_javascript_behavior_pdf(tmp_path / "behavior.pdf", script=script)
    result = analyze(path)

    javascript = finding(result, "PDF_JAVASCRIPT")
    assert expected in javascript["metadata"]["behavior_indicators"]
    # The raw script text must never appear anywhere in the finding metadata.
    assert script not in str(javascript["metadata"])


def test_benign_javascript_reports_no_behavior_indicators(tmp_path: Path) -> None:
    path = write_javascript_behavior_pdf(tmp_path / "benign-js.pdf", script="app.alert('hi');")
    result = analyze(path)

    javascript = finding(result, "PDF_JAVASCRIPT")
    assert javascript["metadata"]["behavior_indicators"] == []


def test_javascript_finding_metadata_never_contains_the_raw_script(tmp_path: Path) -> None:
    marker = "DOCGUARD_UNIQUE_MARKER_STRING_9f3a"
    path = write_javascript_behavior_pdf(
        tmp_path / "marked.pdf", script=f"app.alert('{marker}'); this.submitForm({{}});"
    )
    result = analyze(path)

    javascript = finding(result, "PDF_JAVASCRIPT")
    assert marker not in str(javascript["metadata"])
    assert marker not in str(result.metadata)


# ---------------------------------------------------------------------------
# Cross-cutting: existing structural findings remain unaffected.
# ---------------------------------------------------------------------------


def test_acroform_without_xfa_is_unaffected_by_the_new_findings(tmp_path: Path) -> None:
    result = analyze(write_acroform_pdf(tmp_path / "acroform.pdf"))
    assert codes(result) == {"PDF_ACROFORM"}
