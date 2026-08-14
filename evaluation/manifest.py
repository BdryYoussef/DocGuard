"""Strict, machine-readable corpus manifest: validation, load, and canonical dump.

The manifest is the ground-truth contract Phase 11B will execute against. Validation
here is deliberately strict and fails closed: an ambiguous or malformed manifest must
never silently execute as if it were valid.
"""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Sequence
from importlib import import_module
from pathlib import Path

from pydantic import ValidationError

from app.models.domain import Decision
from app.policies.registry import FINDING_POLICIES
from evaluation.models import EvaluationCase

DEFAULT_MANIFEST_PATH = Path(__file__).parent / "corpus_manifest.json"


class ManifestValidationError(RuntimeError):
    """The corpus manifest is incomplete, inconsistent, or otherwise unsafe to execute."""


def check_generator_resolvable(case: EvaluationCase) -> str | None:
    """Return an error string if ``case``'s generator reference cannot be imported."""
    try:
        module = import_module(case.generator.module)
    except ImportError as exc:
        return f"{case.case_id}: generator module {case.generator.module!r} not importable ({exc})"
    if not hasattr(module, case.generator.attribute):
        return (
            f"{case.case_id}: generator attribute "
            f"{case.generator.module}.{case.generator.attribute!r} does not exist"
        )
    return None


def check_hard_block_decision_consistency(case: EvaluationCase) -> str | None:
    """A case whose expected findings include a hard-block code must accept only BLOCK,
    because the trusted policy engine always escalates a hard-block finding to BLOCK
    regardless of any other finding present."""
    hard_block_codes = sorted(
        code
        for code in case.expected_findings
        if code in FINDING_POLICIES and FINDING_POLICIES[code].hard_block
    )
    if hard_block_codes and tuple(case.acceptable_decisions) != (Decision.BLOCK,):
        return (
            f"{case.case_id}: expected hard-block finding(s) {hard_block_codes} require "
            "acceptable_decisions to be exactly (BLOCK,)"
        )
    return None


def collect_manifest_errors(cases: Sequence[EvaluationCase]) -> list[str]:
    """Return every validation problem found across ``cases``; empty means valid.

    Per-case shape (unknown category/class/finding codes, contradictory CDR flags,
    malformed finding collections) is already enforced by :class:`EvaluationCase`'s own
    pydantic validators at construction time — a case object existing at all means that
    layer already passed. This function adds the cross-case and registry-consulting
    checks that cannot be expressed on a single case in isolation.
    """
    errors: list[str] = []

    ids = [case.case_id for case in cases]
    duplicates = sorted(code for code, count in Counter(ids).items() if count > 1)
    if duplicates:
        errors.append(f"duplicate case_id(s): {duplicates}")

    for case in cases:
        for check in (check_generator_resolvable, check_hard_block_decision_consistency):
            error = check(case)
            if error is not None:
                errors.append(error)

    return errors


def validate_manifest(cases: Sequence[EvaluationCase]) -> None:
    """Raise :class:`ManifestValidationError` if ``cases`` is not safe to execute."""
    errors = collect_manifest_errors(cases)
    if errors:
        raise ManifestValidationError("; ".join(errors))


def manifest_payload(cases: Sequence[EvaluationCase]) -> list[dict[str, object]]:
    """Deterministic, case_id-sorted JSON-safe payload for the manifest file."""
    ordered = sorted(cases, key=lambda case: case.case_id)
    return [case.model_dump(mode="json") for case in ordered]


def dump_manifest(cases: Sequence[EvaluationCase], path: Path = DEFAULT_MANIFEST_PATH) -> None:
    """Validate then write the canonical manifest JSON, sorted and newline-terminated."""
    validate_manifest(cases)
    payload = manifest_payload(cases)
    text = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    path.write_text(text, encoding="utf-8")


def load_manifest(path: Path = DEFAULT_MANIFEST_PATH) -> tuple[EvaluationCase, ...]:
    """Load, strictly parse, and cross-validate the manifest at ``path``.

    Raises :class:`ManifestValidationError` for anything unsafe: malformed JSON, a case
    that fails its own schema, duplicate IDs, unresolvable generators, or contradictory
    decision expectations.
    """
    try:
        text = path.read_text(encoding="utf-8")
        raw = json.loads(text)
    except (OSError, json.JSONDecodeError) as exc:
        raise ManifestValidationError(
            f"manifest at {path} could not be read as JSON: {exc}"
        ) from exc
    if not isinstance(raw, list):
        raise ManifestValidationError("manifest root must be a JSON array of cases")

    cases: list[EvaluationCase] = []
    parse_errors: list[str] = []
    for index, entry in enumerate(raw):
        identifier = entry.get("case_id", f"index {index}") if isinstance(entry, dict) else index
        try:
            # model_validate_json (not model_validate) is required: strict mode only
            # coerces JSON-native shapes (str -> enum, list -> tuple) when parsing JSON
            # text directly, matching how the rest of DocGuard round-trips ContractModel
            # payloads (see app.cdr.service._policy_evaluation).
            cases.append(EvaluationCase.model_validate_json(json.dumps(entry)))
        except ValidationError as exc:
            parse_errors.append(f"{identifier}: {exc}")
    if parse_errors:
        raise ManifestValidationError("; ".join(parse_errors))

    validate_manifest(cases)
    return tuple(sorted(cases, key=lambda case: case.case_id))


def generate_default_manifest() -> None:
    """Regenerate ``evaluation/corpus_manifest.json`` from :data:`evaluation.corpus.CASES`.

    A thin, explicit regeneration step rather than an import-time side effect, so the
    manifest file always reflects a deliberate, reviewable action.
    """
    from evaluation.corpus import CASES

    dump_manifest(CASES, DEFAULT_MANIFEST_PATH)


__all__ = [
    "DEFAULT_MANIFEST_PATH",
    "ManifestValidationError",
    "check_generator_resolvable",
    "check_hard_block_decision_consistency",
    "collect_manifest_errors",
    "dump_manifest",
    "generate_default_manifest",
    "load_manifest",
    "manifest_payload",
    "validate_manifest",
]
