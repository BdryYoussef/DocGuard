"""Phase 11 evaluation framework: corpus, manifest, metrics, and reporting.

Not a production dependency — nothing under ``app``, ``worker``, or ``docguard_contract``
imports this package. It exists to let Phase 11B benchmark the existing, frozen
detection model against a controlled, ground-truthed corpus. See docs/EVALUATION.md.
"""

from __future__ import annotations
