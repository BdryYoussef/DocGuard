"""Bounded semantic PDF inspection using worker-only pikepdf/qpdf."""

from __future__ import annotations

import unicodedata
from collections import Counter
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from urllib.parse import urlsplit

import pikepdf
from pikepdf import Array, Dictionary, Name, NameTree, Object, Stream

from worker.analyzers.file_type import FileFamily
from worker.analyzers.pdf_fallback import PdfFallbackLimits, scan_for_fallback_indicators
from worker.constants import PDF_PARSER_NAME, PDF_PARSER_VERSION
from worker.findings import finding_payload


@dataclass(frozen=True, slots=True)
class PdfAnalysisLimits:
    max_pages: int = 10_000
    max_objects: int = 100_000
    max_action_depth: int = 32
    max_action_nodes: int = 512
    max_action_type_names: int = 32
    max_metadata_string_length: int = 256
    max_uri_count: int = 128
    max_uri_metadata_entries: int = 32
    max_embedded_files: int = 128
    max_embedded_names: int = 32
    max_additional_triggers: int = 128
    max_additional_trigger_names: int = 32
    max_javascript_scan_bytes: int = 64 * 1024
    max_fallback_scan_bytes: int = 8 * 1024 * 1024

    def __post_init__(self) -> None:
        if any(
            value <= 0
            for value in (
                self.max_pages,
                self.max_objects,
                self.max_action_depth,
                self.max_action_nodes,
                self.max_action_type_names,
                self.max_metadata_string_length,
                self.max_uri_count,
                self.max_uri_metadata_entries,
                self.max_embedded_files,
                self.max_embedded_names,
                self.max_additional_triggers,
                self.max_additional_trigger_names,
                self.max_javascript_scan_bytes,
                self.max_fallback_scan_bytes,
            )
        ):
            raise ValueError("PDF analysis limits must be positive")


DEFAULT_PDF_LIMITS = PdfAnalysisLimits()


class PdfParserStatus(StrEnum):
    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    MALFORMED = "MALFORMED"


class PdfRoutingError(RuntimeError):
    """Raised when an internal caller bypasses content-family routing."""


@dataclass(frozen=True, slots=True)
class PdfAnalysis:
    parser_status: PdfParserStatus
    findings: tuple[dict[str, object], ...]
    metadata: dict[str, object]

    @property
    def complete(self) -> bool:
        return self.parser_status is PdfParserStatus.COMPLETE


type ObjectKey = tuple[str, int, int]


@dataclass(slots=True)
class _InspectionState:
    limits: PdfAnalysisLimits
    page_count: int | None = None
    object_count: int | None = None
    pages_inspected: int = 0
    objects_inspected: int = 0
    custom_objects_inspected: int = 0
    catalog_present: bool = False
    encrypted: bool = False
    acroform_present: bool = False
    xfa_present: bool = False
    form_field_count: int = 0
    open_action_present: bool = False
    open_action_kind: str | None = None
    open_action_type: str | None = None
    additional_action_count: int = 0
    additional_triggers_visited: int = 0
    additional_triggers: set[str] = field(default_factory=set)
    additional_trigger_names_capped: bool = False
    additional_action_types: set[str] = field(default_factory=set)
    visited_additional_holders: set[ObjectKey] = field(default_factory=set)
    action_nodes_visited: int = 0
    action_types: Counter[str] = field(default_factory=Counter)
    visited_actions: set[ObjectKey] = field(default_factory=set)
    javascript_action_count: int = 0
    javascript_name_tree_entries: int = 0
    javascript_name_tree_present: bool = False
    javascript_sources: set[str] = field(default_factory=set)
    javascript_behavior_indicators: set[str] = field(default_factory=set)
    launch_action_count: int = 0
    external_uri_count: int = 0
    uri_metadata: list[dict[str, object]] = field(default_factory=list)
    uri_metadata_capped: bool = False
    external_submission_count: int = 0
    submit_form_targets: list[dict[str, object]] = field(default_factory=list)
    submit_form_targets_capped: bool = False
    fallback_indicator_counts: dict[str, int] = field(default_factory=dict)
    fallback_scan_truncated: bool = False
    attachment_names: list[str] = field(default_factory=list)
    attachment_names_capped: bool = False
    attachment_specs: set[ObjectKey] = field(default_factory=set)
    embedded_payloads: set[ObjectKey] = field(default_factory=set)
    referenced_payloads: set[ObjectKey] = field(default_factory=set)
    named_attachment_count: int = 0
    embedded_limit_hit: bool = False
    warning_count: int = 0
    malformed: bool = False
    parser_exception: str | None = None
    partial_reasons: set[str] = field(default_factory=set)

    def partial(self, reason: str) -> None:
        self.partial_reasons.add(reason)

    def consume_custom_object(self) -> bool:
        if self.custom_objects_inspected >= self.limits.max_objects:
            self.partial("custom_object_limit")
            return False
        self.custom_objects_inspected += 1
        return True


_MAPPING_OBJECTS = (Dictionary, Stream)
_PARSER_EXCEPTIONS = (
    pikepdf.PdfError,
    pikepdf.DataDecodingError,
    pikepdf.DeletedObjectError,
)
_KNOWN_ACTION_TYPES = {
    "/GoTo": "GoTo",
    # Go-to-embedded: navigates into a destination inside an embedded/attached PDF.
    # ISO 32000-2 \u00a712.6.4.4. Recognizing it explicitly avoids reporting a real,
    # named action type as an unclassified "Unknown:GoToE".
    "/GoToE": "GoToE",
    "/GoToR": "GoToR",
    "/ImportData": "ImportData",
    "/JavaScript": "JavaScript",
    "/Launch": "Launch",
    "/SubmitForm": "SubmitForm",
    "/URI": "URI",
}
_BIDI_CONTROLS = frozenset("\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")

# Bounded, non-exhaustive substrings observed in structurally-confirmed JavaScript
# actions that DocGuard has already parsed (never executed). These are simple
# substring checks, not semantic analysis: presence is a heuristic indicator of an
# API *family* the script text references, not proof the script runs or succeeds.
_JS_BEHAVIOR_KEYWORDS: dict[str, tuple[str, ...]] = {
    "external_submission_api": (
        "submitForm",
        '"submitForm"',
        "importDataObject",
        '"importDataObject"',
    ),
    "external_url_open_api": (
        "getURL",
        '"getURL"',
        "launchURL",
        '"launchURL"',
        "openDoc",
        '"openDoc"',
    ),
    "external_network_api": (
        "fetch(",
        "XMLHttpRequest",
        "WebSocket",
        "SOAP.connect",
        "SOAP.request",
        "SOAP.streamDecode",
        "new Image",
    ),
    "document_content_access": (
        "getField(",
        "getPageNumWords(",
        "getPageNthWord(",
        "getAnnots(",
        "getOCGs(",
    ),
}


def analyze_pdf(
    sample_path: Path,
    *,
    detected_family: FileFamily,
    limits: PdfAnalysisLimits = DEFAULT_PDF_LIMITS,
) -> PdfAnalysis:
    if detected_family is not FileFamily.PDF:
        raise PdfRoutingError("PDF analyzer requires content-identified PDF input")
    if pikepdf.__version__ != PDF_PARSER_VERSION:
        raise RuntimeError("unexpected PDF parser version")

    state = _InspectionState(limits=limits)
    try:
        pdf = pikepdf.Pdf.open(
            sample_path,
            password="",
            suppress_warnings=True,
            attempt_recovery=True,
            inherit_page_attributes=False,
        )
    except pikepdf.PasswordError:
        state.encrypted = True
        state.parser_exception = "PasswordError"
        state.partial("password_required")
        _apply_fallback_scan(state, sample_path)
        return _result(state)
    except pikepdf.DependencyError as exc:
        state.parser_exception = type(exc).__name__
        state.partial("unsupported_pdf_feature")
        _apply_fallback_scan(state, sample_path)
        return _result(state)
    except pikepdf.PdfError as exc:
        state.malformed = True
        state.parser_exception = type(exc).__name__
        state.partial("parser_rejected_pdf")
        _apply_fallback_scan(state, sample_path)
        return _result(state)

    with pdf:
        try:
            _inspect_open_pdf(pdf, state)
        except pikepdf.DependencyError as exc:
            state.parser_exception = type(exc).__name__
            state.partial("unsupported_pdf_feature")
        except _PARSER_EXCEPTIONS as exc:
            state.malformed = True
            state.parser_exception = type(exc).__name__
            state.partial("parser_error_during_traversal")
        warnings = pdf.get_warnings()
        state.warning_count = len(warnings)
        if warnings:
            state.malformed = True
            state.partial("parser_recovery_warning")
    _apply_fallback_scan(state, sample_path)
    return _result(state)


def _apply_fallback_scan(state: _InspectionState, sample_path: Path) -> None:
    """Populate bounded lexical fallback evidence when structural coverage is not
    COMPLETE. A no-op whenever the structural traversal already fully succeeded —
    the fallback exists to recover evidence the parser could not reach, not to
    duplicate work when nothing was lost."""
    if not (state.malformed or state.partial_reasons):
        return
    fallback_limits = PdfFallbackLimits(max_scan_bytes=state.limits.max_fallback_scan_bytes)
    try:
        with sample_path.open("rb") as handle:
            raw_bytes = handle.read(fallback_limits.max_scan_bytes + 1)
    except OSError:
        return
    scan = scan_for_fallback_indicators(raw_bytes, limits=fallback_limits)
    state.fallback_indicator_counts = dict(scan.indicator_counts)
    state.fallback_scan_truncated = scan.truncated


def _inspect_open_pdf(pdf: pikepdf.Pdf, state: _InspectionState) -> None:
    state.encrypted = pdf.is_encrypted
    root = pdf.Root
    state.catalog_present = isinstance(root, _MAPPING_OBJECTS)
    state.page_count = len(pdf.pages)
    state.object_count = len(pdf.objects)

    if state.page_count > state.limits.max_pages:
        state.partial("page_limit")
    if state.object_count > state.limits.max_objects:
        state.partial("indirect_object_limit")

    _inspect_catalog(root, state)
    _inspect_pages(pdf, state)
    _inspect_named_attachments(pdf, state)
    _inspect_indirect_objects(pdf, state)


def _inspect_catalog(root: Object, state: _InspectionState) -> None:
    if not isinstance(root, _MAPPING_OBJECTS):
        state.partial("catalog_unavailable")
        return

    open_action = root.get(Name.OpenAction)
    if open_action is not None:
        state.open_action_present = True
        if _is_action(open_action):
            state.open_action_kind = "action"
            state.open_action_type = _action_type(open_action, state)
            _walk_action(open_action, state, source="OpenAction", depth=0)
        else:
            state.open_action_kind = "destination"

    _inspect_additional_actions(root, state, source="Catalog")
    _inspect_javascript_name_tree(root, state)

    acroform = root.get(Name.AcroForm)
    if isinstance(acroform, _MAPPING_OBJECTS):
        state.acroform_present = True
        state.xfa_present = Name.XFA in acroform
        _inspect_additional_actions(acroform, state, source="AcroForm")
        fields = acroform.get(Name.Fields)
        if isinstance(fields, Array):
            _inspect_form_fields(fields, state)


def _inspect_pages(pdf: pikepdf.Pdf, state: _InspectionState) -> None:
    page_limit = min(len(pdf.pages), state.limits.max_pages)
    for page_index in range(page_limit):
        page_object = pdf.pages[page_index].obj
        state.pages_inspected += 1
        _inspect_action_holder(page_object, state, source="Page")
        annotations = page_object.get(Name.Annots)
        if not isinstance(annotations, Array):
            continue
        for annotation in annotations:
            if not state.consume_custom_object():
                return
            if not isinstance(annotation, _MAPPING_OBJECTS):
                continue
            _inspect_action_holder(annotation, state, source="Annotation")
            file_spec = annotation.get(Name.FS)
            _observe_file_spec(file_spec, state)


def _inspect_form_fields(fields: Array, state: _InspectionState) -> None:
    stack = [(field, 0) for field in fields]
    visited: set[ObjectKey] = set()
    while stack:
        field_object, depth = stack.pop()
        if depth > state.limits.max_action_depth:
            state.partial("form_tree_depth_limit")
            continue
        if not state.consume_custom_object():
            return
        if not isinstance(field_object, _MAPPING_OBJECTS):
            continue
        key = _object_key(field_object)
        if key in visited:
            continue
        visited.add(key)
        state.form_field_count += 1
        _inspect_action_holder(field_object, state, source="FormField")
        children = field_object.get(Name.Kids)
        if isinstance(children, Array):
            stack.extend((child, depth + 1) for child in children)


def _inspect_javascript_name_tree(root: Object, state: _InspectionState) -> None:
    names = root.get(Name.Names)
    if not isinstance(names, _MAPPING_OBJECTS):
        return
    tree_object = names.get(Name.JavaScript)
    if tree_object is None:
        return
    state.javascript_name_tree_present = True
    state.javascript_sources.add("NameTree")
    try:
        tree = NameTree(tree_object, auto_repair=False)
        for index, key in enumerate(tree):
            if index >= state.limits.max_action_nodes:
                state.partial("javascript_name_tree_limit")
                break
            state.javascript_name_tree_entries += 1
            _walk_action(tree[key], state, source="NameTree", depth=0)
    except (*_PARSER_EXCEPTIONS, ValueError):
        state.partial("javascript_name_tree_invalid")


def _inspect_named_attachments(pdf: pikepdf.Pdf, state: _InspectionState) -> None:
    try:
        for index, name in enumerate(pdf.attachments):
            if index >= state.limits.max_embedded_files:
                state.embedded_limit_hit = True
                state.partial("embedded_file_limit")
                break
            state.named_attachment_count += 1
            _record_attachment_name(name, state)
            _observe_file_spec(pdf.attachments[name].obj, state)
    except (*_PARSER_EXCEPTIONS, ValueError):
        state.partial("embedded_file_name_tree_invalid")


def _inspect_indirect_objects(pdf: pikepdf.Pdf, state: _InspectionState) -> None:
    for index, obj in enumerate(pdf.objects):
        if index >= state.limits.max_objects:
            break
        state.objects_inspected += 1
        if not isinstance(obj, _MAPPING_OBJECTS):
            continue
        _inspect_action_holder(obj, state, source="Object")
        if _is_action(obj):
            _walk_action(obj, state, source="Object", depth=0)
        _observe_file_spec(obj, state)
        if obj.get(Name.Type) == Name.EmbeddedFile:
            _observe_embedded_payload(obj, state)
        associated_files = obj.get(Name.AF)
        if isinstance(associated_files, Array):
            for file_spec in associated_files:
                _observe_file_spec(file_spec, state)


def _inspect_action_holder(holder: Object, state: _InspectionState, *, source: str) -> None:
    action = holder.get(Name.A)
    if action is not None:
        _walk_action(action, state, source=source, depth=0)
    _inspect_additional_actions(holder, state, source=source)


def _inspect_additional_actions(holder: Object, state: _InspectionState, *, source: str) -> None:
    additional = holder.get(Name.AA)
    if not isinstance(additional, _MAPPING_OBJECTS):
        return
    holder_key = _object_key(holder)
    if holder_key in state.visited_additional_holders:
        return
    state.visited_additional_holders.add(holder_key)
    state.additional_action_count += 1
    for trigger, action in additional.items():
        if state.additional_triggers_visited >= state.limits.max_additional_triggers:
            state.partial("additional_action_trigger_limit")
            break
        state.additional_triggers_visited += 1
        if len(state.additional_triggers) < state.limits.max_additional_trigger_names:
            state.additional_triggers.add(_safe_name(trigger, state.limits))
        else:
            state.additional_trigger_names_capped = True
        _walk_action(action, state, source=f"{source}AA", depth=0)


def _walk_action(action: Object, state: _InspectionState, *, source: str, depth: int) -> None:
    if depth > state.limits.max_action_depth:
        state.partial("action_depth_limit")
        return
    if isinstance(action, Array):
        for child in action:
            _walk_action(child, state, source=source, depth=depth)
        return
    if not _is_action(action):
        return

    key = _object_key(action)
    if key in state.visited_actions:
        return
    if state.action_nodes_visited >= state.limits.max_action_nodes:
        state.partial("action_node_limit")
        return
    state.visited_actions.add(key)
    state.action_nodes_visited += 1

    action_type = _action_type(action, state)
    state.action_types[action_type] += 1
    if source.endswith("AA"):
        state.additional_action_types.add(action_type)
    if action_type == "JavaScript":
        state.javascript_action_count += 1
        state.javascript_sources.add(source)
        js_source = _read_javascript_source(action, state.limits)
        if js_source is not None:
            state.javascript_behavior_indicators.update(_javascript_behavior_indicators(js_source))
    elif action_type == "Launch":
        state.launch_action_count += 1
    elif action_type == "URI":
        state.external_uri_count += 1
        _record_uri(action.get(Name.URI), state)
    elif action_type == "SubmitForm":
        _record_submit_form_target(action, state)

    next_action = action.get(Name.Next)
    if next_action is not None:
        _walk_action(next_action, state, source=source, depth=depth + 1)


def _action_type(action: Object, state: _InspectionState) -> str:
    subtype = action.get(Name.S)
    raw_name = str(subtype) if isinstance(subtype, Name) else ""
    known = _KNOWN_ACTION_TYPES.get(raw_name)
    if known is not None:
        return known
    safe = _safe_name(subtype, state.limits) if subtype is not None else "missing"
    unknown_names = sum(name.startswith("Unknown:") for name in state.action_types)
    if unknown_names >= state.limits.max_action_type_names:
        return "Unknown:other"
    return f"Unknown:{safe}"


def _parse_target_metadata(raw_value: str, limits: PdfAnalysisLimits) -> dict[str, object]:
    """Bounded lexical parse of a URL-shaped target string: scheme and hostname
    only. Query strings, fragments, credentials, and the complete URL are always
    discarded. No DNS resolution, connection, or redirect ever occurs."""
    truncated = raw_value[: limits.max_metadata_string_length]
    try:
        parsed = urlsplit(truncated)
        scheme = _bounded_text(parsed.scheme.casefold(), limits, hard_limit=32)
        hostname = _bounded_text(parsed.hostname or "", limits, hard_limit=128)
        metadata: dict[str, object] = {"parse_status": "parsed"}
        if scheme:
            metadata["scheme"] = scheme
        if hostname:
            metadata["hostname"] = hostname
        return metadata
    except (UnicodeError, ValueError):
        return {"parse_status": "invalid"}


def _record_uri(uri_object: Object | None, state: _InspectionState) -> None:
    if state.external_uri_count > state.limits.max_uri_count:
        state.partial("uri_action_limit")
        return
    if len(state.uri_metadata) >= state.limits.max_uri_metadata_entries:
        state.uri_metadata_capped = True
        return
    if uri_object is None:
        state.uri_metadata.append({"parse_status": "missing"})
        return
    state.uri_metadata.append(_parse_target_metadata(str(uri_object), state.limits))


def _record_submit_form_target(action: Object, state: _InspectionState) -> None:
    """Record bounded target metadata only when a SubmitForm action's `/F` entry
    resolves to a URL-shaped string with an explicit scheme — i.e., a target that
    leaves the local document context. A target without a scheme is not reported
    here; the SubmitForm action itself is already captured via the action-type
    metadata on PDF_OPEN_ACTION/PDF_ADDITIONAL_ACTION regardless."""
    if len(state.submit_form_targets) >= state.limits.max_uri_metadata_entries:
        state.submit_form_targets_capped = True
        return
    target = action.get(Name.F)
    if isinstance(target, _MAPPING_OBJECTS):
        target = target.get(Name.F)
    if target is None:
        return
    try:
        raw_value = str(target)
    except _PARSER_EXCEPTIONS:
        return
    metadata = _parse_target_metadata(raw_value, state.limits)
    if metadata.get("parse_status") == "parsed" and "scheme" in metadata:
        state.submit_form_targets.append(metadata)
        state.external_submission_count += 1


def _read_javascript_source(action: Object, limits: PdfAnalysisLimits) -> str | None:
    """Read a bounded prefix of a structurally-confirmed `/JS` action's script
    text, for heuristic behavior-indicator matching only. Never returned,
    persisted, or logged in full; callers must only derive bounded category
    labels from it."""
    js = action.get(Name.JS)
    if js is None:
        return None
    try:
        if isinstance(js, Stream):
            raw = js.read_bytes()[: limits.max_javascript_scan_bytes]
            return raw.decode("latin-1", errors="ignore")
        return str(js)[: limits.max_javascript_scan_bytes]
    except _PARSER_EXCEPTIONS:
        return None


def _javascript_behavior_indicators(source: str) -> frozenset[str]:
    """Bounded, heuristic substring match against a fixed API-name vocabulary.
    Never claims semantic certainty: a match records only that the script text
    references a known API family, not that it executes or succeeds."""
    return frozenset(
        category
        for category, keywords in _JS_BEHAVIOR_KEYWORDS.items()
        if any(keyword in source for keyword in keywords)
    )


def _observe_file_spec(file_spec: Object | None, state: _InspectionState) -> None:
    if not isinstance(file_spec, _MAPPING_OBJECTS) or Name.EF not in file_spec:
        return
    key = _object_key(file_spec)
    if key not in state.attachment_specs:
        if len(state.attachment_specs) >= state.limits.max_embedded_files:
            state.embedded_limit_hit = True
            state.partial("embedded_file_limit")
            return
        state.attachment_specs.add(key)
        display_name = file_spec.get(Name.UF) or file_spec.get(Name.F)
        if display_name is not None:
            _record_attachment_name(str(display_name), state)

    embedded_files = file_spec.get(Name.EF)
    if isinstance(embedded_files, _MAPPING_OBJECTS):
        for _, payload in embedded_files.items():
            if isinstance(payload, Stream):
                payload_key = _object_key(payload)
                state.referenced_payloads.add(payload_key)
                _observe_embedded_payload(payload, state)


def _observe_embedded_payload(payload: Object, state: _InspectionState) -> None:
    key = _object_key(payload)
    if key in state.embedded_payloads:
        return
    if len(state.embedded_payloads) >= state.limits.max_embedded_files:
        state.embedded_limit_hit = True
        state.partial("embedded_file_limit")
        return
    state.embedded_payloads.add(key)


def _record_attachment_name(name: str, state: _InspectionState) -> None:
    normalized = unicodedata.normalize("NFC", name)
    safe = "".join(
        character
        for character in normalized
        if character not in _BIDI_CONTROLS and not unicodedata.category(character).startswith("C")
    )
    safe = safe.replace("/", "_").replace("\\", "_").strip()
    bounded = _bounded_text(safe or "unnamed-attachment", state.limits, hard_limit=128)
    if bounded in state.attachment_names:
        return
    if len(state.attachment_names) >= state.limits.max_embedded_names:
        state.attachment_names_capped = True
        return
    state.attachment_names.append(bounded)


def _result(state: _InspectionState) -> PdfAnalysis:
    embedded_count = max(state.named_attachment_count, len(state.attachment_specs))
    embedded_count += len(state.embedded_payloads - state.referenced_payloads)
    embedded_count = min(embedded_count, state.limits.max_embedded_files)

    findings: list[dict[str, object]] = []
    if state.javascript_name_tree_present or state.javascript_action_count:
        findings.append(
            finding_payload(
                "PDF_JAVASCRIPT",
                {
                    "action_count": state.javascript_action_count,
                    "name_tree_entry_count": state.javascript_name_tree_entries,
                    "sources": sorted(state.javascript_sources),
                    "behavior_indicators": sorted(state.javascript_behavior_indicators),
                },
            )
        )
    if state.open_action_present:
        findings.append(
            finding_payload(
                "PDF_OPEN_ACTION",
                {
                    "kind": state.open_action_kind,
                    "action_type": state.open_action_type,
                },
            )
        )
    if state.additional_action_count:
        findings.append(
            finding_payload(
                "PDF_ADDITIONAL_ACTION",
                {
                    "dictionary_count": state.additional_action_count,
                    "trigger_count": state.additional_triggers_visited,
                    "triggers": sorted(state.additional_triggers),
                    "trigger_names_capped": state.additional_trigger_names_capped,
                    "action_types": sorted(state.additional_action_types),
                },
            )
        )
    if state.launch_action_count:
        findings.append(
            finding_payload("PDF_LAUNCH_ACTION", {"action_count": state.launch_action_count})
        )
    if embedded_count:
        findings.append(
            finding_payload(
                "PDF_EMBEDDED_FILE",
                {
                    "count": embedded_count,
                    "count_capped": state.embedded_limit_hit,
                    "display_names_capped": state.attachment_names_capped,
                    "display_names": sorted(set(state.attachment_names))[
                        : state.limits.max_embedded_names
                    ],
                },
            )
        )
    if state.acroform_present:
        findings.append(finding_payload("PDF_ACROFORM", {"field_count": state.form_field_count}))
    if state.xfa_present:
        findings.append(finding_payload("PDF_XFA", {"present": True}))
    if state.external_uri_count:
        findings.append(
            finding_payload(
                "PDF_EXTERNAL_URI",
                {
                    "count": state.external_uri_count,
                    "targets_capped": state.uri_metadata_capped,
                    "targets": state.uri_metadata,
                },
            )
        )
    if state.external_submission_count:
        findings.append(
            finding_payload(
                "PDF_EXTERNAL_SUBMISSION",
                {
                    "count": state.external_submission_count,
                    "targets_capped": state.submit_form_targets_capped,
                    "targets": state.submit_form_targets,
                },
            )
        )
    if state.encrypted:
        findings.append(
            finding_payload(
                "PDF_ENCRYPTED", {"password_required": "password_required" in state.partial_reasons}
            )
        )
    if state.malformed:
        findings.append(
            finding_payload(
                "PDF_MALFORMED",
                {
                    "parser_exception": state.parser_exception,
                    "warning_count": state.warning_count,
                },
            )
        )
    if state.partial_reasons:
        findings.append(
            finding_payload("PDF_PARTIAL_ANALYSIS", {"reasons": sorted(state.partial_reasons)})
        )
    if state.fallback_indicator_counts:
        findings.append(
            finding_payload(
                "PDF_FALLBACK_INDICATOR",
                {
                    "confidence": "lexical_only",
                    "method": "lexical-name-token-scan",
                    "indicators": sorted(state.fallback_indicator_counts),
                    "indicator_counts": dict(sorted(state.fallback_indicator_counts.items())),
                    "scan_truncated": state.fallback_scan_truncated,
                },
            )
        )

    if state.malformed:
        parser_status = PdfParserStatus.MALFORMED
    elif state.partial_reasons:
        parser_status = PdfParserStatus.PARTIAL
    else:
        parser_status = PdfParserStatus.COMPLETE

    metadata: dict[str, object] = {
        "parser": PDF_PARSER_NAME,
        "parser_version": pikepdf.__version__,
        "qpdf_version": pikepdf.__libqpdf_version__,
        "parser_status": parser_status.value,
        "parser_exception": state.parser_exception,
        "page_count": state.page_count,
        "pages_inspected": state.pages_inspected,
        "object_count": state.object_count,
        "objects_inspected": state.objects_inspected,
        "catalog_present": state.catalog_present,
        "encrypted": state.encrypted,
        "acroform_present": state.acroform_present,
        "xfa_present": state.xfa_present,
        "embedded_file_count": embedded_count,
        "external_uri_count": state.external_uri_count,
        "javascript_action_count": state.javascript_action_count,
        "launch_action_count": state.launch_action_count,
        "action_nodes_visited": state.action_nodes_visited,
        "action_types": dict(sorted(state.action_types.items())),
        "warning_count": state.warning_count,
        "partial_reasons": sorted(state.partial_reasons),
    }
    return PdfAnalysis(parser_status, tuple(findings), metadata)


def _is_action(value: Object) -> bool:
    return isinstance(value, _MAPPING_OBJECTS) and isinstance(value.get(Name.S), Name)


def _object_key(value: Object) -> ObjectKey:
    if value.is_indirect:
        object_number, generation = value.objgen
        return ("indirect", object_number, generation)
    return ("direct", id(value), 0)


def _safe_name(value: object, limits: PdfAnalysisLimits) -> str:
    return _bounded_text(str(value).lstrip("/") or "unknown", limits, hard_limit=128)


def _bounded_text(value: str, limits: PdfAnalysisLimits, *, hard_limit: int | None = None) -> str:
    sanitized = "".join(
        character
        for character in value
        if character not in _BIDI_CONTROLS and not unicodedata.category(character).startswith("C")
    )
    maximum = limits.max_metadata_string_length
    if hard_limit is not None:
        maximum = min(maximum, hard_limit)
    return sanitized[:maximum]


__all__ = [
    "DEFAULT_PDF_LIMITS",
    "PdfAnalysis",
    "PdfAnalysisLimits",
    "PdfParserStatus",
    "PdfRoutingError",
    "analyze_pdf",
]
