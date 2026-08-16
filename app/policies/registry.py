"""Immutable, complete, fingerprinted DocGuard policy registry."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from types import MappingProxyType

from app.models.domain import Decision
from app.policies.version import POLICY_VERSION
from docguard_contract.findings import FINDING_DEFINITIONS


class PolicyRegistryError(RuntimeError):
    """The product policy is incomplete, inconsistent, or unexpectedly modified."""


@dataclass(frozen=True, slots=True)
class FindingPolicy:
    finding_code: str
    contribution: int
    explanation: str
    minimum_decision: Decision | None = None
    hard_block: bool = False
    tags: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class CompoundPolicy:
    name: str
    required_findings: frozenset[str]
    contribution: int
    explanation: str
    minimum_decision: Decision | None = None


def _policy(
    code: str,
    contribution: int,
    explanation: str,
    *,
    minimum: Decision | None = None,
    hard_block: bool = False,
    tags: tuple[str, ...] = (),
) -> FindingPolicy:
    return FindingPolicy(code, contribution, explanation, minimum, hard_block, tags)


_POLICIES = (
    _policy(
        "FILE_DOUBLE_EXTENSION",
        24,
        "A dangerous final extension follows a document extension.",
    ),
    _policy("FILE_BIDI_OVERRIDE", 24, "Bidirectional controls can visually disguise a filename."),
    _policy(
        "FILE_TYPE_MISMATCH",
        28,
        "Observed content conflicts with the filename's claimed family.",
    ),
    _policy(
        "FILE_EXECUTABLE_MASQUERADE",
        50,
        "Executable content is presented as a business document.",
        minimum=Decision.BLOCK,
        hard_block=True,
    ),
    _policy("FILE_CLIENT_MIME_MISMATCH", 2, "Client MIME metadata differs from observed content."),
    _policy("PDF_JAVASCRIPT", 20, "The PDF contains JavaScript capability."),
    _policy("PDF_OPEN_ACTION", 16, "The PDF contains an action processed when it opens."),
    _policy("PDF_ADDITIONAL_ACTION", 18, "The PDF contains event-triggered actions."),
    _policy(
        "PDF_LAUNCH_ACTION",
        45,
        "The PDF contains a launch action capable of invoking an external resource.",
        minimum=Decision.QUARANTINE,
    ),
    _policy("PDF_EMBEDDED_FILE", 24, "The PDF contains embedded content not recursively analyzed."),
    _policy("PDF_ACROFORM", 8, "The PDF contains an interactive form."),
    _policy(
        "PDF_XFA",
        24,
        "The PDF contains XFA content that DocGuard does not render or execute.",
    ),
    _policy("PDF_EXTERNAL_URI", 8, "The PDF contains a passive external URI reference."),
    # Explanatory enrichment of an already-scored SubmitForm action (captured via
    # PDF_OPEN_ACTION/PDF_ADDITIONAL_ACTION/PDF_ACROFORM). Zero contribution: this
    # finding adds no risk information the policy does not already account for, it
    # only names the destination as external. See docs/POLICY_ENGINE.md.
    _policy(
        "PDF_EXTERNAL_SUBMISSION",
        0,
        "A form-submission action targets an external destination.",
    ),
    _policy("PDF_ENCRYPTED", 8, "The PDF uses encryption; completeness is evaluated separately."),
    _policy(
        "PDF_PARTIAL_ANALYSIS",
        25,
        "PDF structural coverage was incomplete.",
        minimum=Decision.QUARANTINE,
    ),
    _policy(
        "PDF_MALFORMED",
        45,
        "Malformed PDF structure prevents reliable complete analysis.",
        minimum=Decision.QUARANTINE,
    ),
    # Purely explanatory: PDF_MALFORMED/PDF_PARTIAL_ANALYSIS (and the worker status
    # they accompany) already force QUARANTINE independent of this finding. Zero
    # contribution: bounded lexical evidence never adds risk score, and never turns
    # incomplete analysis into complete analysis. See docs/PDF_ANALYSIS.md.
    _policy(
        "PDF_FALLBACK_INDICATOR",
        0,
        "Bounded lexical name-token evidence was recovered from an incomplete PDF.",
    ),
    _policy("OFFICE_MACRO_ENABLED", 8, "The Office container is macro-enabled."),
    _policy("OFFICE_VBA_MACRO", 18, "The Office document contains a VBA project."),
    _policy("OFFICE_VBA_AUTOEXEC", 28, "A VBA automatic-execution entry point is present."),
    _policy(
        "OFFICE_VBA_EXECUTION_INDICATOR",
        30,
        "Static VBA analysis found execution-capable constructs.",
    ),
    _policy(
        "OFFICE_EXTERNAL_RELATIONSHIP",
        8,
        "The Office package contains a passive external relationship.",
    ),
    _policy(
        "OFFICE_EXTERNAL_TEMPLATE",
        42,
        "The Office document references a remote template.",
        minimum=Decision.QUARANTINE,
    ),
    _policy(
        "OFFICE_EMBEDDED_OBJECT",
        24,
        "The Office document contains embedded content not recursively analyzed.",
    ),
    _policy("OFFICE_ACTIVEX", 24, "The Office document contains ActiveX structures."),
    _policy(
        "OFFICE_ENCRYPTED",
        8,
        "Office encryption is present; analysis completeness is evaluated separately.",
    ),
    _policy(
        "OFFICE_PARTIAL_ANALYSIS",
        25,
        "Office structural coverage was incomplete.",
        minimum=Decision.QUARANTINE,
    ),
    _policy(
        "OFFICE_MALFORMED",
        45,
        "Malformed Office structure prevents reliable complete analysis.",
        minimum=Decision.QUARANTINE,
    ),
    _policy(
        "ARCHIVE_PATH_TRAVERSAL",
        50,
        "An archive member could traverse outside an extraction root.",
        minimum=Decision.BLOCK,
        hard_block=True,
    ),
    _policy(
        "ARCHIVE_ABSOLUTE_PATH",
        50,
        "An archive contains an absolute or rooted member path.",
        minimum=Decision.BLOCK,
        hard_block=True,
    ),
    _policy(
        "ARCHIVE_SYMLINK",
        45,
        "An archive symlink can create unsafe extraction semantics for end users.",
        minimum=Decision.BLOCK,
        hard_block=True,
    ),
    _policy("ARCHIVE_DUPLICATE_MEMBER", 20, "Duplicate member names create extraction ambiguity."),
    _policy(
        "ARCHIVE_DANGEROUS_MEMBER",
        42,
        "The archive contains an execution-capable member name.",
        minimum=Decision.QUARANTINE,
    ),
    _policy(
        "ARCHIVE_MEMBER_DOUBLE_EXTENSION",
        32,
        "An archive member disguises an execution-capable extension.",
    ),
    _policy(
        "ARCHIVE_MEMBER_BIDI_OVERRIDE",
        28,
        "An archive member uses bidirectional controls for visual deception.",
    ),
    _policy(
        "ARCHIVE_ENCRYPTED",
        8,
        "An encrypted archive member was not inspected; completeness is evaluated separately.",
    ),
    _policy(
        "ARCHIVE_NESTING_LIMIT",
        25,
        "Archive nesting exceeded the configured inspection depth.",
        minimum=Decision.QUARANTINE,
    ),
    _policy(
        "ARCHIVE_RESOURCE_LIMIT",
        35,
        "An archive resource budget stopped complete inspection.",
        minimum=Decision.QUARANTINE,
    ),
    _policy(
        "ARCHIVE_MALFORMED",
        45,
        "Malformed archive structure prevents reliable complete analysis.",
        minimum=Decision.QUARANTINE,
    ),
    _policy(
        "ARCHIVE_PARTIAL_ANALYSIS",
        25,
        "Archive structural coverage was incomplete.",
        minimum=Decision.QUARANTINE,
    ),
    _policy(
        "YARA_TEST_SIGNATURE",
        50,
        "The controlled anti-malware test signature matched.",
        minimum=Decision.BLOCK,
        hard_block=True,
    ),
    _policy(
        "YARA_SIGNATURE_MATCH",
        50,
        "A reviewed high-confidence local signature matched.",
        minimum=Decision.BLOCK,
        hard_block=True,
    ),
    _policy(
        "YARA_HEURISTIC_MATCH",
        42,
        "A trusted local heuristic pattern matched; this is not proof of malware.",
        minimum=Decision.QUARANTINE,
    ),
    _policy(
        "YARA_PARTIAL_ANALYSIS",
        25,
        "YARA coverage was incomplete.",
        minimum=Decision.QUARANTINE,
    ),
)

FINDING_POLICIES = MappingProxyType({policy.finding_code: policy for policy in _POLICIES})

COMPOUND_POLICIES = (
    CompoundPolicy(
        "POLICY_COMPOUND_PDF_AUTO_JS",
        frozenset({"PDF_JAVASCRIPT", "PDF_OPEN_ACTION"}),
        20,
        "PDF JavaScript is paired with automatic open-time triggering.",
        Decision.QUARANTINE,
    ),
    CompoundPolicy(
        "POLICY_COMPOUND_OFFICE_MACRO_EXECUTION_CHAIN",
        frozenset(
            {
                "OFFICE_VBA_MACRO",
                "OFFICE_VBA_AUTOEXEC",
                "OFFICE_VBA_EXECUTION_INDICATOR",
            }
        ),
        25,
        "A VBA project combines automatic execution with execution-capable constructs.",
        Decision.QUARANTINE,
    ),
    CompoundPolicy(
        "POLICY_COMPOUND_OFFICE_AUTOEXEC_YARA",
        frozenset({"OFFICE_VBA_AUTOEXEC", "YARA_HEURISTIC_MATCH"}),
        15,
        "Office auto-execution and a trusted YARA heuristic occur together.",
        Decision.QUARANTINE,
    ),
    CompoundPolicy(
        "POLICY_COMPOUND_ARCHIVE_MEMBER_MASQUERADE",
        frozenset({"ARCHIVE_DANGEROUS_MEMBER", "ARCHIVE_MEMBER_DOUBLE_EXTENSION"}),
        18,
        "An execution-capable archive member also uses a deceptive document extension.",
        Decision.QUARANTINE,
    ),
    CompoundPolicy(
        "POLICY_COMPOUND_FILE_IDENTITY_DECEPTION",
        frozenset({"FILE_DOUBLE_EXTENSION", "FILE_TYPE_MISMATCH"}),
        18,
        "Filename double-extension deception accompanies observed content mismatch.",
        Decision.QUARANTINE,
    ),
)

# Deliberately fixed after normalized review. Updating policy code requires updating this value.
POLICY_FINGERPRINT = "c6d18b6f67b79a91151567c99c8844c741820935ab9d4ad32bb131a30412469b"


def compute_policy_fingerprint() -> str:
    normalized = {
        "version": POLICY_VERSION,
        "findings": [
            {
                "code": policy.finding_code,
                "contribution": policy.contribution,
                "explanation": policy.explanation,
                "minimum_decision": (
                    policy.minimum_decision.value if policy.minimum_decision is not None else None
                ),
                "hard_block": policy.hard_block,
                "tags": list(policy.tags),
            }
            for policy in sorted(FINDING_POLICIES.values(), key=lambda item: item.finding_code)
        ],
        "compounds": [
            {
                "name": compound.name,
                "required_findings": sorted(compound.required_findings),
                "contribution": compound.contribution,
                "explanation": compound.explanation,
                "minimum_decision": (
                    compound.minimum_decision.value
                    if compound.minimum_decision is not None
                    else None
                ),
            }
            for compound in sorted(COMPOUND_POLICIES, key=lambda item: item.name)
        ],
    }
    payload = json.dumps(normalized, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def validate_policy_registry() -> None:
    if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", POLICY_VERSION) is None:
        raise PolicyRegistryError("policy version is invalid")
    known_codes = set(FINDING_DEFINITIONS)
    if set(FINDING_POLICIES) != known_codes:
        raise PolicyRegistryError("finding policy coverage is not exact")
    if len(_POLICIES) != len({policy.finding_code for policy in _POLICIES}):
        raise PolicyRegistryError("duplicate finding policy code")
    for code, policy in FINDING_POLICIES.items():
        if policy.finding_code != code or not 0 <= policy.contribution <= 100:
            raise PolicyRegistryError(f"invalid finding policy: {code}")
        if not policy.explanation or len(policy.explanation) > 500:
            raise PolicyRegistryError(f"invalid policy explanation: {code}")
        if policy.minimum_decision is Decision.ALLOW:
            raise PolicyRegistryError(f"redundant minimum decision: {code}")
        if policy.hard_block != (policy.minimum_decision is Decision.BLOCK):
            raise PolicyRegistryError(f"hard-block policy is inconsistent: {code}")
    names = [compound.name for compound in COMPOUND_POLICIES]
    if len(names) != len(set(names)):
        raise PolicyRegistryError("duplicate compound policy name")
    for compound in COMPOUND_POLICIES:
        if not compound.required_findings or not compound.required_findings <= known_codes:
            raise PolicyRegistryError(f"invalid compound findings: {compound.name}")
        if not 0 <= compound.contribution <= 100:
            raise PolicyRegistryError(f"invalid compound contribution: {compound.name}")
        if compound.minimum_decision in {Decision.ALLOW, Decision.BLOCK}:
            raise PolicyRegistryError(f"invalid compound minimum decision: {compound.name}")
    if compute_policy_fingerprint() != POLICY_FINGERPRINT:
        raise PolicyRegistryError("policy fingerprint mismatch")


def policy_registry_is_valid() -> bool:
    try:
        validate_policy_registry()
    except PolicyRegistryError:
        return False
    return True


__all__ = [
    "COMPOUND_POLICIES",
    "FINDING_POLICIES",
    "POLICY_FINGERPRINT",
    "CompoundPolicy",
    "FindingPolicy",
    "PolicyRegistryError",
    "compute_policy_fingerprint",
    "policy_registry_is_valid",
    "validate_policy_registry",
]
