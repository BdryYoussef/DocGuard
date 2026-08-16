"""Stable product finding definitions shared across the JSON boundary."""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Literal

type SeverityName = Literal["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


@dataclass(frozen=True, slots=True)
class FindingDefinition:
    code: str
    title: str
    description: str
    default_severity: SeverityName
    category: str
    mitre_techniques: tuple[str, ...] = ()


def _definition(
    code: str,
    title: str,
    description: str,
    severity: SeverityName,
    category: str,
    mitre_techniques: tuple[str, ...] = (),
) -> FindingDefinition:
    return FindingDefinition(
        code=code,
        title=title,
        description=description,
        default_severity=severity,
        category=category,
        mitre_techniques=mitre_techniques,
    )


_DEFINITIONS = (
    _definition(
        "FILE_DOUBLE_EXTENSION",
        "Dangerous double extension observed",
        "The filename ends in an executable-capable extension after a business-document extension.",
        "HIGH",
        "file-identity",
    ),
    _definition(
        "FILE_BIDI_OVERRIDE",
        "Bidirectional filename control observed",
        "The filename contains Unicode bidirectional controls that can alter its visual ordering.",
        "HIGH",
        "file-identity",
    ),
    _definition(
        "FILE_TYPE_MISMATCH",
        "Filename type does not match observed content",
        "The filename extension claims a different file family than the "
        "libmagic content identification.",
        "HIGH",
        "file-identity",
    ),
    _definition(
        "FILE_EXECUTABLE_MASQUERADE",
        "Executable content masquerades as a business document",
        "Libmagic identified Windows executable content while the filename claims "
        "a business-document extension.",
        "CRITICAL",
        "file-identity",
        ("T1036.008",),
    ),
    _definition(
        "FILE_CLIENT_MIME_MISMATCH",
        "Client content type differs from observed content",
        "The client-provided Content-Type differs from the libmagic identification; "
        "the client claim was not trusted for analysis.",
        "INFO",
        "file-identity",
    ),
    _definition(
        "PDF_JAVASCRIPT",
        "PDF JavaScript capability detected",
        "The PDF structure contains a JavaScript action or document JavaScript name-tree entry.",
        "MEDIUM",
        "pdf-active-content",
        ("T1204.002",),
    ),
    _definition(
        "PDF_OPEN_ACTION",
        "Automatic PDF open action detected",
        "The PDF catalog contains an OpenAction that a viewer may process when the document opens.",
        "MEDIUM",
        "pdf-actions",
    ),
    _definition(
        "PDF_ADDITIONAL_ACTION",
        "PDF additional actions detected",
        "The PDF contains one or more event-triggered additional-action dictionaries.",
        "MEDIUM",
        "pdf-actions",
    ),
    _definition(
        "PDF_LAUNCH_ACTION",
        "PDF launch action detected",
        "The PDF contains an action intended to launch an application, document, or resource.",
        "HIGH",
        "pdf-actions",
        ("T1204.002",),
    ),
    _definition(
        "PDF_EMBEDDED_FILE",
        "PDF embedded file structure detected",
        "The PDF contains one or more embedded-file specifications or payload structures.",
        "MEDIUM",
        "pdf-attachments",
    ),
    _definition(
        "PDF_ACROFORM",
        "PDF interactive AcroForm detected",
        "The PDF catalog contains an interactive AcroForm structure.",
        "LOW",
        "pdf-forms",
    ),
    _definition(
        "PDF_XFA",
        "PDF XFA form structure detected",
        "The PDF AcroForm contains an XFA structure; DocGuard does not execute or render XFA.",
        "MEDIUM",
        "pdf-forms",
    ),
    _definition(
        "PDF_EXTERNAL_URI",
        "PDF external URI action detected",
        "The PDF contains one or more URI actions; DocGuard records bounded lexical "
        "metadata and never fetches them.",
        "LOW",
        "pdf-external-reference",
    ),
    _definition(
        "PDF_EXTERNAL_SUBMISSION",
        "PDF form submission to an external target detected",
        "A structurally-confirmed SubmitForm action targets a URL-shaped destination "
        "with an explicit scheme; DocGuard records only bounded scheme/hostname "
        "metadata and never submits data or fetches the target.",
        "MEDIUM",
        "pdf-external-reference",
    ),
    _definition(
        "PDF_ENCRYPTED",
        "Encrypted PDF detected",
        "The PDF uses encryption or password protection, which is not inherently malicious.",
        "LOW",
        "pdf-analysis-limitation",
    ),
    _definition(
        "PDF_PARTIAL_ANALYSIS",
        "PDF analysis was incomplete",
        "Structural PDF inspection stopped before complete coverage; bounded metadata "
        "records the reason.",
        "MEDIUM",
        "pdf-analysis-limitation",
    ),
    _definition(
        "PDF_MALFORMED",
        "Malformed PDF structure detected",
        "The PDF parser reported structural damage, so complete analysis cannot be trusted.",
        "HIGH",
        "pdf-structure",
    ),
    _definition(
        "PDF_FALLBACK_INDICATOR",
        "Bounded lexical indicators observed in a structurally incomplete PDF",
        "Structural PDF analysis was incomplete or rejected, so DocGuard additionally "
        "searched the raw bytes for a fixed set of known PDF name-object keywords. "
        "This is a bounded, non-executing lexical scan, not confirmed PDF object "
        "traversal: a match here is not equivalent to, and must not be confused with, "
        "a structurally-confirmed finding such as PDF_JAVASCRIPT or PDF_XFA.",
        "MEDIUM",
        "pdf-analysis-limitation",
    ),
    _definition(
        "OFFICE_MACRO_ENABLED",
        "Macro-enabled Office structure detected",
        "The Office container declares macro-enabled content or a VBA project structure.",
        "LOW",
        "office-macros",
        ("T1204.002",),
    ),
    _definition(
        "OFFICE_VBA_MACRO",
        "Office VBA macro project detected",
        "One or more VBA projects or modules are structurally present in the Office document.",
        "MEDIUM",
        "office-macros",
        ("T1204.002",),
    ),
    _definition(
        "OFFICE_VBA_AUTOEXEC",
        "Office VBA auto-execution entry point detected",
        "Static VBA analysis identified an entry point that Office may invoke automatically.",
        "HIGH",
        "office-macros",
        ("T1059.005", "T1204.002"),
    ),
    _definition(
        "OFFICE_VBA_EXECUTION_INDICATOR",
        "Office VBA execution-capable indicator detected",
        "Static VBA analysis identified bounded APIs or constructs capable of launching commands, "
        "scripts, or processes; their presence does not prove maliciousness.",
        "HIGH",
        "office-macros",
        ("T1059.005",),
    ),
    _definition(
        "OFFICE_EXTERNAL_RELATIONSHIP",
        "External Office relationship detected",
        "The OOXML package contains one or more external relationships; DocGuard records only "
        "bounded lexical metadata and never fetches them.",
        "LOW",
        "office-external-reference",
    ),
    _definition(
        "OFFICE_EXTERNAL_TEMPLATE",
        "External Office template relationship detected",
        "The Word package references an external template; DocGuard does not fetch the target.",
        "HIGH",
        "office-external-reference",
        ("T1221",),
    ),
    _definition(
        "OFFICE_EMBEDDED_OBJECT",
        "Embedded Office object structure detected",
        "The Office container contains embedded OLE or package object structures that were not "
        "recursively analyzed.",
        "MEDIUM",
        "office-embedded-content",
    ),
    _definition(
        "OFFICE_ACTIVEX",
        "Office ActiveX structure detected",
        "The Office container contains ActiveX control structures; DocGuard does not instantiate "
        "or execute controls.",
        "MEDIUM",
        "office-active-content",
    ),
    _definition(
        "OFFICE_ENCRYPTED",
        "Encrypted Office document detected",
        "The Office container uses encryption that prevents complete structural inspection; "
        "encryption is not inherently malicious.",
        "LOW",
        "office-analysis-limitation",
    ),
    _definition(
        "OFFICE_PARTIAL_ANALYSIS",
        "Office analysis was incomplete",
        "Structural Office inspection stopped before complete coverage; bounded metadata records "
        "the reason.",
        "MEDIUM",
        "office-analysis-limitation",
    ),
    _definition(
        "OFFICE_MALFORMED",
        "Malformed Office structure detected",
        "The Office container or a required component is malformed, so complete analysis cannot "
        "be trusted.",
        "HIGH",
        "office-structure",
    ),
    _definition(
        "ARCHIVE_PATH_TRAVERSAL",
        "Archive path traversal observed",
        "The ZIP contains a member name with a parent-directory component that could escape an "
        "extraction root in another tool.",
        "HIGH",
        "archive-path",
    ),
    _definition(
        "ARCHIVE_ABSOLUTE_PATH",
        "Rooted archive member path observed",
        "The ZIP contains a POSIX, Windows drive-rooted, or UNC-style member path.",
        "HIGH",
        "archive-path",
    ),
    _definition(
        "ARCHIVE_SYMLINK",
        "Archive symbolic-link entry observed",
        "The ZIP contains a Unix symbolic-link entry; DocGuard did not follow or resolve it.",
        "HIGH",
        "archive-path",
    ),
    _definition(
        "ARCHIVE_DUPLICATE_MEMBER",
        "Ambiguous duplicate archive member observed",
        "The ZIP contains exact or conservatively normalized member-name collisions that may be "
        "handled inconsistently by extraction tools.",
        "MEDIUM",
        "archive-structure",
    ),
    _definition(
        "ARCHIVE_DANGEROUS_MEMBER",
        "Execution-capable archive member name observed",
        "The ZIP contains a member whose extension denotes executable, script, shortcut, library, "
        "or installer content; this does not by itself establish maliciousness.",
        "HIGH",
        "archive-member",
    ),
    _definition(
        "ARCHIVE_MEMBER_DOUBLE_EXTENSION",
        "Archive member uses a dangerous double extension",
        "The ZIP contains a member ending in an execution-capable extension after a "
        "business-document extension.",
        "HIGH",
        "archive-member",
        ("T1036.007",),
    ),
    _definition(
        "ARCHIVE_MEMBER_BIDI_OVERRIDE",
        "Bidirectional control observed in archive member name",
        "The ZIP contains a member name with Unicode bidirectional controls that can alter its "
        "visual ordering.",
        "HIGH",
        "archive-member",
        ("T1036.002",),
    ),
    _definition(
        "ARCHIVE_ENCRYPTED",
        "Encrypted archive member observed",
        "The ZIP marks one or more members as encrypted; DocGuard does not request passwords, "
        "decrypt, or brute-force them.",
        "LOW",
        "archive-analysis-limitation",
    ),
    _definition(
        "ARCHIVE_NESTING_LIMIT",
        "Archive nesting limit reached",
        "Nested ZIP inspection stopped at the configured recursion depth.",
        "MEDIUM",
        "archive-analysis-limitation",
    ),
    _definition(
        "ARCHIVE_RESOURCE_LIMIT",
        "Archive resource limit reached",
        "ZIP inspection stopped because an actual-byte, entry, member, container, materialization, "
        "or finding budget was exhausted.",
        "HIGH",
        "archive-analysis-limitation",
    ),
    _definition(
        "ARCHIVE_MALFORMED",
        "Malformed ZIP structure detected",
        "The ZIP or a nested ZIP could not be inspected reliably because archive structure or "
        "decompressed member data was malformed.",
        "HIGH",
        "archive-structure",
    ),
    _definition(
        "ARCHIVE_PARTIAL_ANALYSIS",
        "Archive analysis was incomplete",
        "ZIP inspection stopped before complete coverage; bounded metadata records the reason.",
        "MEDIUM",
        "archive-analysis-limitation",
    ),
    _definition(
        "YARA_TEST_SIGNATURE",
        "Controlled YARA test signature matched",
        "A trusted local anti-malware test signature matched; the test artifact is not real "
        "malware.",
        "HIGH",
        "yara-test-signature",
    ),
    _definition(
        "YARA_SIGNATURE_MATCH",
        "Trusted YARA signature matched",
        "A trusted local high-confidence signature matched the top-level submitted file.",
        "HIGH",
        "yara-signature",
    ),
    _definition(
        "YARA_HEURISTIC_MATCH",
        "Trusted YARA heuristic matched",
        "A trusted local behavioral or string-pattern rule matched the top-level submitted file; "
        "the observation is not proof of malware.",
        "MEDIUM",
        "yara-heuristic",
    ),
    _definition(
        "YARA_PARTIAL_ANALYSIS",
        "YARA analysis was incomplete",
        "YARA scanning stopped before complete coverage; bounded metadata records the reason.",
        "MEDIUM",
        "yara-analysis-limitation",
    ),
)

FINDING_DEFINITIONS = MappingProxyType({definition.code: definition for definition in _DEFINITIONS})

__all__ = ["FINDING_DEFINITIONS", "FindingDefinition", "SeverityName"]
