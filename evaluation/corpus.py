"""The Phase 11A controlled evaluation corpus: ground truth and fixture materialization.

Every fixture is generated locally, deterministically, and inertly by composing the
existing test fixture factories under ``tests/fixtures`` (and two narrow local helpers
below for cases those factories do not already cover). Nothing here downloads samples,
executes macros/scripts/archive members, or fetches any external resource.

Ground truth (expected findings, acceptable decisions, completeness expectations) was
derived directly from the frozen Phase 10 policy registry (``app.policies.registry``)
and from the existing, already-reviewed unit/integration tests that exercise these same
fixtures — not guessed. Where a fixture can legitimately produce more than one plausible
finding combination (e.g. a bidirectional-override filename may or may not also trip a
type-mismatch check depending on the claimed extension family), ``acceptable_decisions``
lists every policy-consistent outcome rather than picking one arbitrarily, and
``allow_any_additional_findings`` is set instead of guessing an exhaustive finding set.

This module defines the detector's expected behavior; it does not run anything.
"""

from __future__ import annotations

import importlib
from pathlib import Path
from typing import Final

from evaluation.models import (
    CaseCategory,
    CaseClass,
    CdrExpectedOutcome,
    EvaluationCase,
    FixtureGenerator,
    GeneratorKind,
)
from tests.fixtures.yara_factory import EICAR_TEST_BYTES

CORPUS_VERSION: Final = "11A.1"

_PDF_FACTORY = "tests.fixtures.pdf_factory"
_OFFICE_FACTORY = "tests.fixtures.office_factory"
_ARCHIVE_FACTORY = "tests.fixtures.archive_factory"
_YARA_FACTORY = "tests.fixtures.yara_factory"
_FILE_ID_FIXTURES = "tests.unit.test_file_identification"
_THIS_MODULE = "evaluation.corpus"

_HARMLESS_PLAIN_MACRO_SOURCE = (
    'Attribute VB_Name = "Module1"\n'
    "Sub DoSomething()\n"
    "    Dim note As String\n"
    '    note = "DOCGUARD_CONTROLLED_FIXTURE_NO_AUTOEXEC"\n'
    "End Sub\n"
)


def _write(module: str, attribute: str, **kwargs: object) -> FixtureGenerator:
    return FixtureGenerator(
        module=module,
        attribute=attribute,
        kind=GeneratorKind.WRITE_PATH,
        kwargs=kwargs,  # type: ignore[arg-type]
    )


def _bytes_factory(module: str, attribute: str, **kwargs: object) -> FixtureGenerator:
    return FixtureGenerator(
        module=module,
        attribute=attribute,
        kind=GeneratorKind.BYTES_FACTORY,
        kwargs=kwargs,  # type: ignore[arg-type]
    )


def _const(module: str, attribute: str) -> FixtureGenerator:
    return FixtureGenerator(module=module, attribute=attribute, kind=GeneratorKind.BYTES_CONST)


def many_entries_archive_fixture(path: Path, *, count: int = 4_200) -> Path:
    """Compose ``write_archive`` with enough tiny members to exceed the default ZIP
    entry-count budget, so ARCHIVE_RESOURCE_LIMIT is reachable under production limits
    without materializing a large file."""
    from tests.fixtures.archive_factory import write_archive

    members = [(f"fixture-entry-{index}.txt", b"x") for index in range(count)]
    return write_archive(path, members)


def pdf_with_eicar_fixture(path: Path, *, pages: int = 1) -> Path:
    """A structurally benign PDF with the standard EICAR test string appended, so the
    top-level-file YARA scan reaches a hard-block on an otherwise-renderable PDF. Used
    to prove CDR must remain unavailable for a BLOCK-decision source document."""
    from tests.fixtures.pdf_factory import write_benign_pdf

    write_benign_pdf(path, pages=pages)
    with path.open("ab") as stream:
        stream.write(b"\n% DocGuard controlled trailing fixture\n")
        stream.write(EICAR_TEST_BYTES)
        stream.write(b"\n")
    return path


def _case(
    case_id: str,
    category: CaseCategory,
    case_class: CaseClass,
    description: str,
    filename: str,
    generator: FixtureGenerator,
    **kwargs: object,
) -> EvaluationCase:
    return EvaluationCase(
        case_id=case_id,
        category=category,
        case_class=case_class,
        description=description,
        filename=filename,
        generator=generator,
        **kwargs,  # type: ignore[arg-type]
    )


# ---------------------------------------------------------------------------
# A. BENIGN PDF
# ---------------------------------------------------------------------------
_BENIGN_PDF = (
    _case(
        "PDF-BEN-001",
        CaseCategory.BENIGN_PDF,
        CaseClass.BENIGN,
        "Single-page structurally plain PDF with no active content.",
        "quarterly-summary.pdf",
        _write(_PDF_FACTORY, "write_benign_pdf", pages=1),
        acceptable_decisions=("ALLOW",),
        expected_analysis_complete=True,
    ),
    _case(
        "PDF-BEN-002",
        CaseCategory.BENIGN_PDF,
        CaseClass.BENIGN,
        "Multi-page structurally plain PDF; verifies zero-finding scaling across pages.",
        "annual-report.pdf",
        _write(_PDF_FACTORY, "write_benign_pdf", pages=10),
        acceptable_decisions=("ALLOW",),
        expected_analysis_complete=True,
    ),
    _case(
        "PDF-BEN-003",
        CaseCategory.BENIGN_PDF,
        CaseClass.BENIGN,
        "Visible page text mentions '/JavaScript' as prose; must not be keyword-matched "
        "as an active-content finding.",
        "syntax-notes.pdf",
        _write(_PDF_FACTORY, "write_benign_pdf", pages=1, keyword_text=True),
        acceptable_decisions=("ALLOW",),
        expected_analysis_complete=True,
        notes="False-positive robustness control for PDF_JAVASCRIPT keyword matching.",
    ),
    _case(
        "PDF-BEN-004",
        CaseCategory.BENIGN_PDF,
        CaseClass.BENIGN,
        "Multi-page PDF combining benign prose that mentions active-content keywords.",
        "training-material.pdf",
        _write(_PDF_FACTORY, "write_benign_pdf", pages=4, keyword_text=True),
        acceptable_decisions=("ALLOW",),
        expected_analysis_complete=True,
    ),
)

# ---------------------------------------------------------------------------
# B. RISKY PDF
# ---------------------------------------------------------------------------
_RISKY_PDF = (
    _case(
        "PDF-RISK-001",
        CaseCategory.RISKY_PDF,
        CaseClass.RISKY,
        "OpenAction dictionary present (GoTo); low-severity, policy allows release.",
        "open-action.pdf",
        _write(_PDF_FACTORY, "write_open_action_pdf"),
        expected_findings=("PDF_OPEN_ACTION",),
        acceptable_decisions=("ALLOW",),
        expected_analysis_complete=True,
    ),
    _case(
        "PDF-RISK-002",
        CaseCategory.RISKY_PDF,
        CaseClass.RISKY,
        "AA (additional actions) dictionary present.",
        "additional-action.pdf",
        _write(_PDF_FACTORY, "write_additional_action_pdf"),
        expected_findings=("PDF_ADDITIONAL_ACTION",),
        acceptable_decisions=("ALLOW",),
        expected_analysis_complete=True,
    ),
    _case(
        "PDF-RISK-003",
        CaseCategory.RISKY_PDF,
        CaseClass.RISKY,
        "JavaScript OpenAction; compound auto-JS rule must escalate to QUARANTINE.",
        "javascript-open.pdf",
        _write(_PDF_FACTORY, "write_javascript_pdf"),
        expected_findings=("PDF_JAVASCRIPT", "PDF_OPEN_ACTION"),
        acceptable_decisions=("QUARANTINE",),
        expected_analysis_complete=True,
        cdr_case=True,
        cdr_expected_outcome=CdrExpectedOutcome.RECONSTRUCT_SUCCESS,
    ),
    _case(
        "PDF-RISK-004",
        CaseCategory.RISKY_PDF,
        CaseClass.RISKY,
        "JavaScript reachable only via the document Names/JavaScript tree, no OpenAction.",
        "javascript-name-tree.pdf",
        _write(_PDF_FACTORY, "write_javascript_name_tree_pdf"),
        expected_findings=("PDF_JAVASCRIPT",),
        acceptable_decisions=("REVIEW",),
        expected_analysis_complete=True,
    ),
    _case(
        "PDF-RISK-005",
        CaseCategory.RISKY_PDF,
        CaseClass.RISKY,
        "Launch action capable of invoking an external resource; mandatory QUARANTINE.",
        "launch-action.pdf",
        _write(_PDF_FACTORY, "write_launch_action_pdf"),
        expected_findings=("PDF_LAUNCH_ACTION", "PDF_OPEN_ACTION"),
        acceptable_decisions=("QUARANTINE",),
        expected_analysis_complete=True,
    ),
    _case(
        "PDF-RISK-006",
        CaseCategory.RISKY_PDF,
        CaseClass.RISKY,
        "Embedded file specification not recursively analyzed.",
        "embedded-attachment.pdf",
        _write(_PDF_FACTORY, "write_embedded_file_pdf"),
        expected_findings=("PDF_EMBEDDED_FILE",),
        acceptable_decisions=("REVIEW",),
        expected_analysis_complete=True,
        cdr_case=True,
    ),
    _case(
        "PDF-RISK-007",
        CaseCategory.RISKY_PDF,
        CaseClass.RISKY,
        "AcroForm with an XFA structure that DocGuard never renders or executes.",
        "xfa-form.pdf",
        _write(_PDF_FACTORY, "write_acroform_pdf", xfa=True),
        expected_findings=("PDF_ACROFORM", "PDF_XFA"),
        acceptable_decisions=("REVIEW",),
        expected_analysis_complete=True,
    ),
    _case(
        "PDF-RISK-008",
        CaseCategory.RISKY_PDF,
        CaseClass.RISKY,
        "Passive external URI action; DocGuard records bounded metadata and never fetches "
        "it. Ground truth is RISKY per the documented threat model even though the URI "
        "target itself is inert (see AGENTS.md section 17).",
        "external-uri.pdf",
        _write(_PDF_FACTORY, "write_uri_action_pdf"),
        expected_findings=("PDF_EXTERNAL_URI",),
        acceptable_decisions=("ALLOW",),
        expected_analysis_complete=True,
    ),
    _case(
        "PDF-RISK-009",
        CaseCategory.RISKY_PDF,
        CaseClass.RISKY,
        "Plain interactive AcroForm with no XFA content.",
        "acroform.pdf",
        _write(_PDF_FACTORY, "write_acroform_pdf"),
        expected_findings=("PDF_ACROFORM",),
        acceptable_decisions=("ALLOW",),
        expected_analysis_complete=True,
    ),
    _case(
        "PDF-RISK-010",
        CaseCategory.RISKY_PDF,
        CaseClass.RISKY,
        "Structurally benign, renderable PDF with a trailing EICAR test signature; proves "
        "a hard-blocked PDF source must never expose CDR.",
        "invoice-eicar.pdf",
        _write(_THIS_MODULE, "pdf_with_eicar_fixture"),
        expected_findings=("YARA_TEST_SIGNATURE",),
        acceptable_decisions=("BLOCK",),
        expected_analysis_complete=True,
        cdr_case=True,
        cdr_expected_outcome=CdrExpectedOutcome.BLOCK_INELIGIBLE,
    ),
    _case(
        "PDF-RISK-011",
        CaseCategory.RISKY_PDF,
        CaseClass.RISKY,
        "Password-protected/encrypted PDF; structural inspection cannot complete.",
        "encrypted.pdf",
        _write(_PDF_FACTORY, "write_encrypted_pdf"),
        expected_findings=("PDF_ENCRYPTED", "PDF_PARTIAL_ANALYSIS"),
        acceptable_decisions=("QUARANTINE",),
        expected_analysis_complete=False,
        fail_secure=True,
    ),
    _case(
        "PDF-RISK-012",
        CaseCategory.RISKY_PDF,
        CaseClass.RISKY,
        "Structurally damaged PDF (truncated object stream); analysis cannot be trusted.",
        "malformed.pdf",
        _write(_PDF_FACTORY, "write_malformed_pdf"),
        expected_findings=("PDF_MALFORMED", "PDF_PARTIAL_ANALYSIS"),
        acceptable_decisions=("QUARANTINE",),
        expected_analysis_complete=False,
        fail_secure=True,
    ),
)

# ---------------------------------------------------------------------------
# C. BENIGN OFFICE
# ---------------------------------------------------------------------------
_BENIGN_OFFICE = (
    _case(
        "OFF-BEN-001",
        CaseCategory.BENIGN_OFFICE,
        CaseClass.BENIGN,
        "Plain Word OOXML package, no macros or external content.",
        "memo.docx",
        _write(_OFFICE_FACTORY, "write_ooxml", application="WORD"),
        acceptable_decisions=("ALLOW",),
        expected_analysis_complete=True,
    ),
    _case(
        "OFF-BEN-002",
        CaseCategory.BENIGN_OFFICE,
        CaseClass.BENIGN,
        "Plain Excel OOXML package, no macros or external content.",
        "ledger.xlsx",
        _write(_OFFICE_FACTORY, "write_ooxml", application="EXCEL"),
        acceptable_decisions=("ALLOW",),
        expected_analysis_complete=True,
    ),
    _case(
        "OFF-BEN-003",
        CaseCategory.BENIGN_OFFICE,
        CaseClass.BENIGN,
        "Plain PowerPoint OOXML package, no macros or external content.",
        "briefing.pptx",
        _write(_OFFICE_FACTORY, "write_ooxml", application="POWERPOINT"),
        acceptable_decisions=("ALLOW",),
        expected_analysis_complete=True,
    ),
    _case(
        "OFF-BEN-004",
        CaseCategory.BENIGN_OFFICE,
        CaseClass.BENIGN,
        "Classic (pre-OOXML) compound-file Word document, no macro stream.",
        "legacy-memo.doc",
        _write(_OFFICE_FACTORY, "write_classic_ole"),
        acceptable_decisions=("ALLOW",),
        expected_analysis_complete=True,
    ),
    _case(
        "OFF-BEN-005",
        CaseCategory.BENIGN_OFFICE,
        CaseClass.BENIGN,
        "OOXML package with extra harmless internal ZIP entries; verifies benign package "
        "variety does not false-positive.",
        "packet.docx",
        _write(_OFFICE_FACTORY, "write_ooxml", application="WORD", extra_entries=10),
        acceptable_decisions=("ALLOW",),
        expected_analysis_complete=True,
    ),
    _case(
        "OFF-BEN-006",
        CaseCategory.BENIGN_OFFICE,
        CaseClass.BENIGN,
        "Plain Word OOXML with longer benign visible document text.",
        "policy-notes.docx",
        _write(
            _OFFICE_FACTORY,
            "write_ooxml",
            application="WORD",
            visible_text="This controlled fixture document contains only ordinary prose.",
        ),
        acceptable_decisions=("ALLOW",),
        expected_analysis_complete=True,
    ),
)

# ---------------------------------------------------------------------------
# D. RISKY OFFICE
# ---------------------------------------------------------------------------
_OFFICE_MACRO_NOTE = (
    "The controlled fixture VBA stream is not a full real vbaProject.bin structure, so "
    "oletools reports it as an orphan VBA stream and OFFICE_PARTIAL_ANALYSIS always "
    "accompanies macro findings from this factory; this is a known fixture-generator "
    "characteristic, not a detector defect."
)
_RISKY_OFFICE = (
    _case(
        "OFF-RISK-001",
        CaseCategory.RISKY_OFFICE,
        CaseClass.RISKY,
        "Macro-enabled OOXML with a VBA project but no autoexec or execution indicators.",
        "macro-plain.docm",
        _write(
            _OFFICE_FACTORY,
            "write_ooxml",
            application="WORD",
            macro_source=_HARMLESS_PLAIN_MACRO_SOURCE,
        ),
        expected_findings=("OFFICE_MACRO_ENABLED", "OFFICE_PARTIAL_ANALYSIS", "OFFICE_VBA_MACRO"),
        acceptable_decisions=("QUARANTINE",),
        expected_analysis_complete=False,
        notes=_OFFICE_MACRO_NOTE,
    ),
    _case(
        "OFF-RISK-002",
        CaseCategory.RISKY_OFFICE,
        CaseClass.RISKY,
        "Macro-enabled OOXML with an AutoOpen automatic-execution entry point.",
        "macro-autoexec.docm",
        _write(
            _OFFICE_FACTORY,
            "write_ooxml",
            application="WORD",
            macro_source="__HARMLESS_AUTOEXEC_SOURCE__",
        ),
        expected_findings=(
            "OFFICE_MACRO_ENABLED",
            "OFFICE_PARTIAL_ANALYSIS",
            "OFFICE_VBA_AUTOEXEC",
            "OFFICE_VBA_MACRO",
        ),
        acceptable_decisions=("QUARANTINE",),
        expected_analysis_complete=False,
        notes=_OFFICE_MACRO_NOTE,
    ),
    _case(
        "OFF-RISK-003",
        CaseCategory.RISKY_OFFICE,
        CaseClass.RISKY,
        "Macro-enabled OOXML with execution-capable constructs (WScript.Shell, Run).",
        "macro-execution-indicator.docm",
        _write(
            _OFFICE_FACTORY,
            "write_ooxml",
            application="WORD",
            macro_source="__HARMLESS_EXECUTION_INDICATOR_SOURCE__",
        ),
        expected_findings=(
            "OFFICE_MACRO_ENABLED",
            "OFFICE_PARTIAL_ANALYSIS",
            "OFFICE_VBA_EXECUTION_INDICATOR",
            "OFFICE_VBA_MACRO",
        ),
        acceptable_decisions=("QUARANTINE",),
        expected_analysis_complete=False,
        notes=_OFFICE_MACRO_NOTE,
    ),
    _case(
        "OFF-RISK-004",
        CaseCategory.RISKY_OFFICE,
        CaseClass.RISKY,
        "Macro combines an autoexec entry point with execution-capable constructs; the "
        "compound execution-chain rule must trigger.",
        "macro-autoexec-execution.docm",
        _write(
            _OFFICE_FACTORY,
            "write_ooxml",
            application="WORD",
            macro_source="__HARMLESS_AUTOEXEC_AND_EXECUTION_INDICATOR_SOURCE__",
        ),
        expected_findings=(
            "OFFICE_MACRO_ENABLED",
            "OFFICE_PARTIAL_ANALYSIS",
            "OFFICE_VBA_AUTOEXEC",
            "OFFICE_VBA_EXECUTION_INDICATOR",
            "OFFICE_VBA_MACRO",
        ),
        acceptable_decisions=("QUARANTINE",),
        expected_analysis_complete=False,
        notes=_OFFICE_MACRO_NOTE + " Exercises POLICY_COMPOUND_OFFICE_MACRO_EXECUTION_CHAIN.",
    ),
    _case(
        "OFF-RISK-005",
        CaseCategory.RISKY_OFFICE,
        CaseClass.RISKY,
        "Single passive external relationship (never fetched).",
        "external-link.docx",
        _write(_OFFICE_FACTORY, "write_ooxml", application="WORD", external_relationship=True),
        expected_findings=("OFFICE_EXTERNAL_RELATIONSHIP",),
        acceptable_decisions=("ALLOW",),
        expected_analysis_complete=True,
    ),
    _case(
        "OFF-RISK-006",
        CaseCategory.RISKY_OFFICE,
        CaseClass.RISKY,
        "External attached-template relationship (remote template injection shape).",
        "external-template.docx",
        _write(
            _OFFICE_FACTORY,
            "write_ooxml",
            application="WORD",
            external_relationship=True,
            external_template=True,
        ),
        expected_findings=("OFFICE_EXTERNAL_RELATIONSHIP", "OFFICE_EXTERNAL_TEMPLATE"),
        acceptable_decisions=("QUARANTINE",),
        expected_analysis_complete=True,
    ),
    _case(
        "OFF-RISK-007",
        CaseCategory.RISKY_OFFICE,
        CaseClass.RISKY,
        "Embedded OLE object plus ActiveX control structures, neither instantiated.",
        "embedded-activex.docx",
        _write(
            _OFFICE_FACTORY,
            "write_ooxml",
            application="WORD",
            embedded_object=True,
            activex=True,
        ),
        expected_findings=("OFFICE_ACTIVEX", "OFFICE_EMBEDDED_OBJECT"),
        acceptable_decisions=("QUARANTINE",),
        expected_analysis_complete=True,
    ),
    _case(
        "OFF-RISK-008",
        CaseCategory.RISKY_OFFICE,
        CaseClass.RISKY,
        "Classic compound-file Word document with an AutoOpen macro stream.",
        "legacy-macro.doc",
        _write(
            _OFFICE_FACTORY,
            "write_classic_ole",
            macro_source="__HARMLESS_AUTOEXEC_SOURCE__",
        ),
        expected_findings=("OFFICE_VBA_AUTOEXEC", "OFFICE_VBA_MACRO"),
        acceptable_decisions=("QUARANTINE",),
        allow_any_additional_findings=True,
        notes="Additional office-analysis-limitation findings are plausible for the "
        "synthetic classic-OLE macro stream and are not exhaustively enumerated.",
    ),
    _case(
        "OFF-RISK-009",
        CaseCategory.RISKY_OFFICE,
        CaseClass.RISKY,
        "Encrypted classic compound-file Office container; content cannot be inspected.",
        "encrypted.doc",
        _write(_OFFICE_FACTORY, "write_encrypted_office_ole"),
        expected_findings=("OFFICE_ENCRYPTED", "OFFICE_PARTIAL_ANALYSIS"),
        acceptable_decisions=("QUARANTINE",),
        expected_analysis_complete=False,
        fail_secure=True,
    ),
    _case(
        "OFF-RISK-010",
        CaseCategory.RISKY_OFFICE,
        CaseClass.RISKY,
        "Internally inconsistent OOXML package structure (content-types/relationships).",
        "inconsistent.docx",
        _write(_OFFICE_FACTORY, "write_inconsistent_ooxml"),
        expected_findings=("OFFICE_MALFORMED", "OFFICE_PARTIAL_ANALYSIS"),
        acceptable_decisions=("QUARANTINE",),
        expected_analysis_complete=False,
        fail_secure=True,
    ),
)

# ---------------------------------------------------------------------------
# E. BENIGN ARCHIVE
# ---------------------------------------------------------------------------
_BENIGN_ARCHIVE = (
    _case(
        "ARC-BEN-001",
        CaseCategory.BENIGN_ARCHIVE,
        CaseClass.BENIGN,
        "Ordinary ZIP with two harmless business-document members.",
        "documents.zip",
        _write(
            _ARCHIVE_FACTORY,
            "write_archive",
            members=[["harmless.txt", "fixture"], ["document.pdf", "%PDF fixture"]],
        ),
        acceptable_decisions=("ALLOW",),
        expected_analysis_complete=True,
    ),
    _case(
        "ARC-BEN-002",
        CaseCategory.BENIGN_ARCHIVE,
        CaseClass.BENIGN,
        "Empty ZIP archive with no members.",
        "empty.zip",
        _write(_ARCHIVE_FACTORY, "write_archive", members=[]),
        acceptable_decisions=("ALLOW",),
        expected_analysis_complete=True,
    ),
    _case(
        "ARC-BEN-003",
        CaseCategory.BENIGN_ARCHIVE,
        CaseClass.BENIGN,
        "ZIP with only directory entries and one empty file member.",
        "folder-only.zip",
        _write(
            _ARCHIVE_FACTORY,
            "write_archive",
            members=[["directory/", ""], ["directory/empty.txt", ""]],
        ),
        acceptable_decisions=("ALLOW",),
        expected_analysis_complete=True,
    ),
    _case(
        "ARC-BEN-004",
        CaseCategory.BENIGN_ARCHIVE,
        CaseClass.BENIGN,
        "ZIP written with a streamed data descriptor (non-seekable writer); a valid but "
        "less common structural variant.",
        "streamed.zip",
        _bytes_factory(_ARCHIVE_FACTORY, "data_descriptor_archive_bytes"),
        acceptable_decisions=("ALLOW",),
        expected_analysis_complete=True,
    ),
    _case(
        "ARC-BEN-005",
        CaseCategory.BENIGN_ARCHIVE,
        CaseClass.BENIGN,
        "Small ZIP64-format archive; a valid but less common structural variant.",
        "zip64.zip",
        _bytes_factory(_ARCHIVE_FACTORY, "small_zip64_archive_bytes"),
        acceptable_decisions=("ALLOW",),
        expected_analysis_complete=True,
    ),
)

# ---------------------------------------------------------------------------
# F. RISKY ARCHIVE
# ---------------------------------------------------------------------------
_RISKY_ARCHIVE = (
    _case(
        "ARC-RISK-001",
        CaseCategory.RISKY_ARCHIVE,
        CaseClass.RISKY,
        "Member name with a parent-directory traversal component.",
        "traversal.zip",
        _write(
            _ARCHIVE_FACTORY,
            "write_archive",
            members=[["../../evil.txt", "controlled fixture"]],
        ),
        expected_findings=("ARCHIVE_PATH_TRAVERSAL",),
        acceptable_decisions=("BLOCK",),
        expected_analysis_complete=True,
    ),
    _case(
        "ARC-RISK-002",
        CaseCategory.RISKY_ARCHIVE,
        CaseClass.RISKY,
        "Member with a POSIX rooted (absolute) path.",
        "absolute.zip",
        _write(
            _ARCHIVE_FACTORY,
            "write_archive",
            members=[["/etc/controlled-fixture.txt", "controlled fixture"]],
        ),
        expected_findings=("ARCHIVE_ABSOLUTE_PATH",),
        acceptable_decisions=("BLOCK",),
        expected_analysis_complete=True,
    ),
    _case(
        "ARC-RISK-003",
        CaseCategory.RISKY_ARCHIVE,
        CaseClass.RISKY,
        "Unix symbolic-link entry; the link target is never read or followed.",
        "symlink.zip",
        _bytes_factory(_ARCHIVE_FACTORY, "symlink_archive_bytes"),
        expected_findings=("ARCHIVE_SYMLINK",),
        acceptable_decisions=("BLOCK",),
        expected_analysis_complete=True,
    ),
    _case(
        "ARC-RISK-004",
        CaseCategory.RISKY_ARCHIVE,
        CaseClass.RISKY,
        "Member name with an execution-capable extension (.scr).",
        "dangerous-member.zip",
        _write(
            _ARCHIVE_FACTORY,
            "write_archive",
            members=[["invoice.scr", "controlled fixture"]],
        ),
        expected_findings=("ARCHIVE_DANGEROUS_MEMBER",),
        acceptable_decisions=("QUARANTINE",),
        expected_analysis_complete=True,
    ),
    _case(
        "ARC-RISK-005",
        CaseCategory.RISKY_ARCHIVE,
        CaseClass.RISKY,
        "Member disguises an execution-capable extension behind a document extension "
        "(double extension); the archive-member masquerade compound rule must trigger.",
        "double-extension.zip",
        _write(
            _ARCHIVE_FACTORY,
            "write_archive",
            members=[["invoice.pdf.exe", "controlled fixture"]],
        ),
        expected_findings=("ARCHIVE_DANGEROUS_MEMBER", "ARCHIVE_MEMBER_DOUBLE_EXTENSION"),
        acceptable_decisions=("QUARANTINE",),
        expected_analysis_complete=True,
    ),
    _case(
        "ARC-RISK-006",
        CaseCategory.RISKY_ARCHIVE,
        CaseClass.RISKY,
        "Member name uses bidirectional Unicode controls to visually disguise its "
        "execution-capable extension.",
        "bidi-member.zip",
        _write(
            _ARCHIVE_FACTORY,
            "write_archive",
            members=[["photo\u202egpj.scr", "controlled fixture"]],
        ),
        expected_findings=("ARCHIVE_DANGEROUS_MEMBER", "ARCHIVE_MEMBER_BIDI_OVERRIDE"),
        acceptable_decisions=("QUARANTINE",),
        expected_analysis_complete=True,
    ),
    _case(
        "ARC-RISK-007",
        CaseCategory.RISKY_ARCHIVE,
        CaseClass.RISKY,
        "Two members share an ambiguous normalized name.",
        "duplicate-members.zip",
        _write(
            _ARCHIVE_FACTORY,
            "write_archive",
            members=[["same.txt", "one"], ["same.txt", "two"]],
        ),
        expected_findings=("ARCHIVE_DUPLICATE_MEMBER",),
        acceptable_decisions=("REVIEW",),
        expected_analysis_complete=True,
    ),
    _case(
        "ARC-RISK-008",
        CaseCategory.RISKY_ARCHIVE,
        CaseClass.RISKY,
        "A ZIP member is flagged encrypted; DocGuard never decrypts or brute-forces it.",
        "encrypted-member.zip",
        _bytes_factory(_ARCHIVE_FACTORY, "encrypted_metadata_archive_bytes"),
        expected_findings=("ARCHIVE_ENCRYPTED", "ARCHIVE_PARTIAL_ANALYSIS"),
        acceptable_decisions=("QUARANTINE",),
        expected_analysis_complete=False,
        fail_secure=True,
    ),
    _case(
        "ARC-RISK-009",
        CaseCategory.RISKY_ARCHIVE,
        CaseClass.RISKY,
        "Nested ZIP-in-ZIP exceeds the configured inspection recursion depth.",
        "deep-nesting.zip",
        _bytes_factory(_ARCHIVE_FACTORY, "nested_archive_bytes", depth=6),
        expected_findings=("ARCHIVE_NESTING_LIMIT", "ARCHIVE_PARTIAL_ANALYSIS"),
        acceptable_decisions=("QUARANTINE",),
        expected_analysis_complete=False,
        fail_secure=True,
    ),
    _case(
        "ARC-RISK-010",
        CaseCategory.RISKY_ARCHIVE,
        CaseClass.RISKY,
        "ZIP entry count exceeds the configured member budget.",
        "many-entries.zip",
        _write(_THIS_MODULE, "many_entries_archive_fixture", count=4_200),
        expected_findings=("ARCHIVE_PARTIAL_ANALYSIS", "ARCHIVE_RESOURCE_LIMIT"),
        acceptable_decisions=("QUARANTINE",),
        expected_analysis_complete=False,
        fail_secure=True,
    ),
    _case(
        "ARC-RISK-011",
        CaseCategory.RISKY_ARCHIVE,
        CaseClass.RISKY,
        "Central-directory CRC is inconsistent with the local header; structurally damaged ZIP.",
        "corrupt-crc.zip",
        _bytes_factory(_ARCHIVE_FACTORY, "corrupt_crc_archive_bytes"),
        expected_findings=("ARCHIVE_MALFORMED",),
        acceptable_decisions=("QUARANTINE",),
        expected_analysis_complete=False,
        fail_secure=True,
        allow_any_additional_findings=True,
        notes="ARCHIVE_PARTIAL_ANALYSIS is expected to co-occur but is not asserted "
        "exactly to avoid over-fitting ground truth to undocumented parser detail.",
    ),
    _case(
        "ARC-RISK-012",
        CaseCategory.RISKY_ARCHIVE,
        CaseClass.RISKY,
        "Unsupported ZIP compression method; member data cannot be decompressed.",
        "unsupported-method.zip",
        _bytes_factory(_ARCHIVE_FACTORY, "unsupported_method_archive_bytes"),
        expected_findings=("ARCHIVE_PARTIAL_ANALYSIS",),
        acceptable_decisions=("QUARANTINE",),
        expected_analysis_complete=False,
        fail_secure=True,
    ),
)

# ---------------------------------------------------------------------------
# G. FILE IDENTITY / MASQUERADING
# ---------------------------------------------------------------------------
_FILE_IDENTITY = (
    _case(
        "FID-001",
        CaseCategory.FILE_IDENTITY,
        CaseClass.RISKY,
        "Filename ends in a dangerous extension following a document extension "
        "('invoice.pdf.exe') over otherwise-benign PDF content.",
        "invoice.pdf.exe",
        _write(_PDF_FACTORY, "write_benign_pdf", pages=1),
        expected_findings=("FILE_DOUBLE_EXTENSION",),
        allow_any_additional_findings=True,
        acceptable_decisions=("QUARANTINE", "REVIEW"),
        notes="FILE_TYPE_MISMATCH may co-occur depending on claimed-extension-family "
        "resolution; both REVIEW (double-extension only) and QUARANTINE (with the "
        "compound identity-deception rule) are policy-consistent outcomes.",
    ),
    _case(
        "FID-002",
        CaseCategory.FILE_IDENTITY,
        CaseClass.RISKY,
        "Filename contains a Unicode bidirectional override that can visually reorder "
        "the displayed extension, over otherwise-benign PDF content.",
        "invoice\u202efdp.exe",
        _write(_PDF_FACTORY, "write_benign_pdf", pages=1),
        expected_findings=("FILE_BIDI_OVERRIDE",),
        allow_any_additional_findings=True,
        acceptable_decisions=("QUARANTINE", "REVIEW"),
        notes="FILE_TYPE_MISMATCH may co-occur because the claimed final extension "
        "implies a non-PDF family; both outcomes are policy-consistent.",
    ),
    _case(
        "FID-003",
        CaseCategory.FILE_IDENTITY,
        CaseClass.RISKY,
        "Plain-text content uploaded under a filename that claims a PDF extension.",
        "report.pdf",
        _const(_YARA_FACTORY, "BENIGN_TEXT"),
        expected_findings=("FILE_TYPE_MISMATCH",),
        acceptable_additional_findings=("FILE_CLIENT_MIME_MISMATCH",),
        acceptable_decisions=("REVIEW",),
    ),
    _case(
        "FID-004",
        CaseCategory.FILE_IDENTITY,
        CaseClass.RISKY,
        "Windows executable content masquerading under a PDF filename and claimed content type.",
        "invoice.pdf",
        _bytes_factory(_FILE_ID_FIXTURES, "inert_pe_fixture"),
        expected_findings=(
            "FILE_CLIENT_MIME_MISMATCH",
            "FILE_EXECUTABLE_MASQUERADE",
            "FILE_TYPE_MISMATCH",
        ),
        acceptable_decisions=("BLOCK",),
        expected_analysis_complete=True,
    ),
    _case(
        "FID-005",
        CaseCategory.FILE_IDENTITY,
        CaseClass.BENIGN,
        "Ordinary dotted filename over matching PDF content; negative control proving "
        "an unremarkable dotted name is never flagged as a double extension.",
        "quarterly.report.pdf",
        _write(_PDF_FACTORY, "write_benign_pdf", pages=1),
        acceptable_decisions=("ALLOW",),
        expected_analysis_complete=True,
    ),
)

# ---------------------------------------------------------------------------
# H. YARA
# ---------------------------------------------------------------------------
_YARA = (
    _case(
        "YAR-001",
        CaseCategory.YARA,
        CaseClass.RISKY,
        "The standard EICAR anti-malware test string; a controlled test artifact, not "
        "real malware, must still hard-block per the trusted local test signature.",
        "eicar-test-fixture.txt",
        _const(_YARA_FACTORY, "EICAR_TEST_BYTES"),
        expected_findings=("YARA_TEST_SIGNATURE",),
        acceptable_decisions=("BLOCK",),
        expected_analysis_complete=True,
    ),
    _case(
        "YAR-002",
        CaseCategory.YARA,
        CaseClass.RISKY,
        "JavaScript PDF with a trailing PowerShell encoded-command heuristic pattern.",
        "javascript-with-powershell-pattern.pdf",
        _write(_YARA_FACTORY, "write_pdf_with_yara_pattern"),
        expected_findings=("PDF_JAVASCRIPT", "PDF_OPEN_ACTION", "YARA_HEURISTIC_MATCH"),
        acceptable_decisions=("QUARANTINE",),
        expected_analysis_complete=True,
    ),
    _case(
        "YAR-003",
        CaseCategory.YARA,
        CaseClass.BENIGN,
        "Prose discussing PowerShell academically; negative control for the encoded-"
        "command heuristic.",
        "powershell-notes.txt",
        _const(_YARA_FACTORY, "BENIGN_POWERSHELL_PROSE"),
        acceptable_decisions=("ALLOW",),
        expected_analysis_complete=True,
    ),
    _case(
        "YAR-004",
        CaseCategory.YARA,
        CaseClass.RISKY,
        "Bounded cmd.exe chained-invocation heuristic pattern.",
        "cmd-fixture.txt",
        _const(_YARA_FACTORY, "CMD_INVOCATION_PATTERN"),
        expected_findings=("YARA_HEURISTIC_MATCH",),
        acceptable_decisions=("QUARANTINE",),
        expected_analysis_complete=True,
    ),
    _case(
        "YAR-005",
        CaseCategory.YARA,
        CaseClass.BENIGN,
        "Prose discussing cmd.exe academically; negative control for the command-shell "
        "chain heuristic.",
        "cmd-notes.txt",
        _const(_YARA_FACTORY, "BENIGN_CMD_PROSE"),
        acceptable_decisions=("ALLOW",),
        expected_analysis_complete=True,
    ),
)

_DEFAULT_CONTENT_TYPE_CATEGORIES = frozenset(
    {CaseCategory.BENIGN_PDF, CaseCategory.RISKY_PDF, CaseCategory.FILE_IDENTITY}
)


def _with_default_content_type(case: EvaluationCase) -> EvaluationCase:
    """Every PDF-family and file-identity case claims 'application/pdf' by default,
    matching what a real client uploading a document named ``*.pdf`` would send. This
    keeps FILE_CLIENT_MIME_MISMATCH ground truth aligned with the claimed extension
    rather than defaulting to a generic octet-stream that would never mismatch."""
    if (
        case.claimed_content_type is not None
        or case.category not in _DEFAULT_CONTENT_TYPE_CATEGORIES
    ):
        return case
    return case.model_copy(update={"claimed_content_type": "application/pdf"})


CASES: tuple[EvaluationCase, ...] = tuple(
    _with_default_content_type(case)
    for case in (
        _BENIGN_PDF
        + _RISKY_PDF
        + _BENIGN_OFFICE
        + _RISKY_OFFICE
        + _BENIGN_ARCHIVE
        + _RISKY_ARCHIVE
        + _FILE_IDENTITY
        + _YARA
    )
)


def _resolve_kwargs(raw: dict[str, object]) -> dict[str, object]:
    resolved: dict[str, object] = {}
    for key, value in raw.items():
        if key == "application" and isinstance(value, str):
            from worker.analyzers.office_types import OfficeApplication

            resolved[key] = OfficeApplication[value]
        elif key == "macro_source" and isinstance(value, str) and value.startswith("__"):
            resolved[key] = _resolve_macro_source_placeholder(value)
        elif key == "members" and isinstance(value, list):
            resolved[key] = [(str(item[0]), str(item[1]).encode("utf-8")) for item in value]
        else:
            resolved[key] = value
    return resolved


def _resolve_macro_source_placeholder(placeholder: str) -> str:
    from tests.fixtures.office_factory import (
        HARMLESS_AUTOEXEC_SOURCE,
        HARMLESS_EXECUTION_INDICATOR_SOURCE,
    )

    if placeholder == "__HARMLESS_AUTOEXEC_SOURCE__":
        return HARMLESS_AUTOEXEC_SOURCE
    if placeholder == "__HARMLESS_EXECUTION_INDICATOR_SOURCE__":
        return HARMLESS_EXECUTION_INDICATOR_SOURCE
    if placeholder == "__HARMLESS_AUTOEXEC_AND_EXECUTION_INDICATOR_SOURCE__":
        return HARMLESS_AUTOEXEC_SOURCE + HARMLESS_EXECUTION_INDICATOR_SOURCE
    raise ValueError(f"unknown macro source placeholder: {placeholder}")


def materialize_case(case: EvaluationCase, directory: Path) -> Path:
    """Deterministically write ``case``'s fixture bytes under ``directory``.

    Resolves the generator reference dynamically so the manifest stays data, not code.
    Never executes any part of the generated document.
    """
    generator = case.generator
    module = importlib.import_module(generator.module)
    target: object = getattr(module, generator.attribute)
    kwargs = _resolve_kwargs(dict(generator.kwargs))
    path = directory / case.filename
    path.parent.mkdir(parents=True, exist_ok=True)

    if generator.kind is GeneratorKind.WRITE_PATH:
        if not callable(target):
            raise TypeError(f"generator {generator.module}.{generator.attribute} is not callable")
        result: object = target(path, **kwargs)
        if not isinstance(result, Path):
            raise TypeError(
                f"generator {generator.module}.{generator.attribute} did not return a Path"
            )
        return result
    if generator.kind is GeneratorKind.BYTES_FACTORY:
        if not callable(target):
            raise TypeError(f"generator {generator.module}.{generator.attribute} is not callable")
        data: object = target(**kwargs)
        if not isinstance(data, bytes | bytearray):
            raise TypeError(
                f"generator {generator.module}.{generator.attribute} did not return bytes"
            )
        path.write_bytes(bytes(data))
        return path
    if kwargs:
        raise ValueError("bytes-constant generators accept no kwargs")
    if not isinstance(target, bytes | bytearray):
        raise TypeError(f"generator {generator.module}.{generator.attribute} is not bytes")
    path.write_bytes(bytes(target))
    return path


__all__ = [
    "CASES",
    "CORPUS_VERSION",
    "many_entries_archive_fixture",
    "materialize_case",
    "pdf_with_eicar_fixture",
]
