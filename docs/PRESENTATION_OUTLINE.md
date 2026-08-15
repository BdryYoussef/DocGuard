# DocGuard Presentation Outline

12 slides. No fabricated statistics — every number below is pulled directly from
`docs/EVALUATION.md`. Pair with `docs/DEFENSE_GUIDE.md` for full speaking notes and
`docs/DEMO.md` for the live walkthrough.

---

### Slide 1 — Title
- **Title**: DocGuard — An Isolated and Explainable Security Gateway for Untrusted
  Business Documents
- Subtitle: final academic release (v1.0.0)
- Visual: product name over a simple trust-boundary icon (locked box around a document).
- Speaker emphasis: state the exact product tagline once, verbatim — it's the claim
  everything else has to support.

### Slide 2 — Business context
- Small accounting/fiduciary-style offices handle CIN, tax, corporate, and bank
  documents daily.
- Files arrive by email, messaging, USB, client portal uploads.
- No dedicated security staff, no SOC, no enterprise security budget.
- The office's own systems are still a real target.
- Visual: simple inbound-document diagram (email/USB/portal → office staff).
- Speaker emphasis: this is a *specific, small* deployment target, not "enterprise."

### Slide 3 — Problem
- Opening an attacker-controlled PDF/Office/ZIP directly is a real, recurring risk.
- No budget for full AV suites, SOC tooling, or cloud sandboxing.
- Confidential documents cannot be casually uploaded to third-party scanners.
- Visual: a document icon with a warning badge, arrow toward "employee inbox."
- Speaker emphasis: frame this as *before a human opens the file*, not after.

### Slide 4 — Threat model
- Malicious PDFs/Office/archives, parser exploitation, filename deception, archive
  traversal/decompression abuse, credential/session attacks, CDR abuse.
- Assets: the documents themselves, operator credentials/sessions, sanitized
  artifacts, policy/rule integrity, audit history.
- Visual: short table (asset → representative threat).
- Speaker emphasis: name the concrete threats before showing the fix — the design
  should feel like an answer, not a given.

### Slide 5 — DocGuard concept
- A gateway: upload → isolated analysis → deterministic decision → optional CDR →
  audited release.
- Four decisions: ALLOW / REVIEW / QUARANTINE / BLOCK.
- Visual: the four-decision funnel.
- Speaker emphasis: say the ALLOW disclaimer here for the first time — it should be
  repeated, not a one-off footnote.

### Slide 6 — Architecture / trust boundary
- Trusted process (FastAPI, DB, policy, audit) never parses document bytes.
- Untrusted work (libmagic, PDF/Office/ZIP parsers, YARA, CDR rendering) runs only
  inside a disposable Bubblewrap sandbox: no network, no secrets, dropped
  capabilities, resource limits.
- Visual: the trust-boundary diagram from `docs/DEFENSE_GUIDE.md` §E.
- Speaker emphasis: **hostile parsing happens entirely outside the trusted process** —
  say this sentence exactly.

### Slide 7 — Analysis pipeline
- libmagic content identification (never trusts filename/claimed MIME) → routed
  analyzer (PDF / Office / archive) → fixed local YARA pack on the top-level file.
- Strict, versioned JSON contract back to the trusted side; the worker cannot set a
  score or decision.
- Visual: pipeline diagram, worker box highlighted as "disposable, one per document."
- Speaker emphasis: the worker *reports*, it never *decides*.

### Slide 8 — Policy + CDR
- Deterministic, versioned, fingerprinted policy: findings → bounded score → decision.
- CDR (PDF only): rasterize → rebuild → **re-analyze as an independent scan**.
- Source decision is immutable; BLOCK is never CDR-eligible.
- Visual: CDR flow (source scan → render → derived scan → re-analysis → approval).
- Speaker emphasis: "the sanitized file earns ALLOW the same way any upload would — by
  being re-analyzed, not by trust inherited from the renderer."

### Slide 9 — Security hardening
- Argon2id passwords, opaque hashed sessions, session-bound CSRF, exact-origin checks.
- Fail-closed: incomplete analysis is never promoted to ALLOW.
- Production topology: TLS-terminating Nginx → loopback Uvicorn → SQLite/private
  storage, systemd-hardened service.
- Visual: short bullet list, no diagram needed.
- Speaker emphasis: name fail-closed explicitly — it's the property the resilience
  demo proves live.

### Slide 10 — Evaluation methodology
- 59-case controlled, synthetic, **pre-registered** corpus (hashes frozen before
  execution).
- Executed once through the real Bubblewrap production path — not a mock, not the
  `unsafe-development` backend.
- Metrics: risky-case recall, finding-level recall, benign escalation, decision
  compliance, fail-secure rate, CDR recovery, latency.
- Visual: pre-registration hash + git-commit callout.
- Speaker emphasis: "pre-registered" — ground truth was frozen *before* the official
  run, not adjusted afterward.

### Slide 11 — Evaluation results
- 59 total cases — 41 risky, 18 benign.
- 41/41 risky-case detection recall.
- 72/72 expected findings detected.
- 0/18 benign cases escalated.
- 9/9 fail-secure cases non-release-eligible.
- CDR: 2/2 eligible cases recovered; BLOCK case correctly CDR-ineligible.
- Median latency 317 ms, p95 386 ms.
- Visual: results table, straight from `docs/EVALUATION.md`.
- Speaker emphasis: say "within the controlled synthetic corpus and documented
  detection model" every time a number is read aloud.

### Slide 12 — Demo / limitations / conclusion
- Live demo: benign ALLOW → suspicious PDF + CDR → BLOCK → audit trail.
- Limitations: static analysis only, synthetic 59-case corpus, single development
  host, no MFA/SSO, SQLite single-node target, no external AV/cloud integration.
- Future work: dynamic sandbox tier, larger independent corpus, MFA/SSO, multi-node.
- Closing line: DocGuard isolates hostile parsing, explains every decision, and fails
  closed when it cannot complete safely — it does not claim to detect all malware or
  prove a document is safe.
- Visual: three-column limitations / future-work / closing-statement layout.
- Speaker emphasis: end on the disclaimer, not on the 100% numbers — it is the more
  defensible closing statement.
