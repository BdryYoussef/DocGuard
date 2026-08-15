# DocGuard Defense Guide

A reference for explaining DocGuard clearly in a defense/jury setting without needing to
recite source code. Pair with `docs/PRESENTATION_OUTLINE.md` for slides and
`docs/DEMO.md` for the live walkthrough.

## A. 30-second pitch

> DocGuard is a security gateway that sits in front of untrusted business documents —
> PDFs, Office files, ZIP archives — before anyone in a small office opens them. It
> never lets a document's own bytes get parsed by the trusted application: all hostile
> parsing happens inside a disposable, sandboxed worker with no network and no access
> to secrets. A deterministic, versioned policy engine then turns the worker's
> structural findings into an explainable decision — ALLOW, REVIEW, QUARANTINE, or
> BLOCK — and can optionally reconstruct a flattened, re-analyzed version of a
> suspicious PDF instead of releasing the original.

## B. 2-minute project summary

DocGuard addresses a concrete, narrow problem: small offices that handle sensitive
paperwork (accounting, fiduciary, notarial-style work) routinely receive PDFs, Office
documents, and ZIP attachments by email or client upload, with no dedicated security
staff and no appetite for enterprise infrastructure. Opening a malicious attachment
directly is a real, recurring risk.

DocGuard's core design decision is a hard trust boundary: the FastAPI application,
database, and policy engine never interpret document bytes. Every document is streamed
to private storage untouched, then handed to a brand-new, disposable Bubblewrap sandbox
— a separate Linux namespace with no network, no secrets, dropped capabilities, and
strict resource limits — which performs libmagic content identification and, depending
on what it finds, structural PDF/Office/ZIP analysis and a small fixed YARA rule pack.
The worker returns a strictly validated, bounded JSON report; it never gets to set a
score or a decision itself.

A separate, versioned, fingerprinted policy engine in the trusted process turns that
report into one of four decisions. `ALLOW` and `BLOCK` are self-explanatory extremes;
`REVIEW` and `QUARANTINE` sit in between. For a `QUARANTINE`/`REVIEW` PDF, an operator
can request Content Disarm and Reconstruction (CDR): the PDF is rasterized to flat
images inside another sandboxed worker, producing a new PDF with no active content,
which is then **fully re-analyzed** as its own scan — it is never trusted just because
it came out of the CDR renderer. Only if that re-analysis also lands on `ALLOW` does an
approved, downloadable artifact exist; the original document's decision and quarantine
status never change.

The whole system fails closed: any analysis that cannot complete safely — encrypted,
malformed, resource-limited, timed out — stays non-release-eligible rather than
defaulting to `ALLOW`. This behavior, along with detection recall and false-escalation
rate, was measured against a 59-case controlled, synthetic, pre-registered corpus
executed through the real production isolation path (Phase 11), not asserted from
memory.

## C. Business problem

Context: small accounting/fiduciary-style offices routinely handle:

- CIN / national identity documents;
- tax documents;
- corporate records;
- bank statements / RIB documents;
- PDF, Office, and archive attachments from clients.

These arrive through email, messaging apps, USB drives, and client portal uploads.
There is typically no dedicated security staff, no SOC, and no budget for enterprise
endpoint security tooling — but the documents themselves are sensitive and the office's
own systems are a real target.

## D. Why DocGuard exists

DocGuard is positioned as a **document-security gateway** that intercepts a file
*before* any employee opens it in their normal tools (Word, Adobe Reader, a file
explorer). It does not try to be a general endpoint security product; it targets the
one recurring risk this kind of office actually faces: "a client just sent us a file,
should someone open it?"

## E. Architecture explanation

```
browser / operator
      |  (authenticated HTTPS, CSRF-protected)
      v
trusted FastAPI application  --  never parses document bytes
      |  (opaque bytes + SHA-256, no interpretation)
      v
private storage (quarantine)
      |  (one descriptor, read-only bind)
      v
disposable Bubblewrap worker  --  no network, no secrets, dropped capabilities
      |  (libmagic -> PDF / Office / archive analyzer -> YARA)
      v
strictly validated JSON contract  --  worker can never set score/decision
      |
      v
trusted, versioned, fingerprinted policy engine
      |
      v
ALLOW / REVIEW / QUARANTINE / BLOCK  --  persisted transactionally
      |
      +--> (QUARANTINE/REVIEW PDF only) CDR: rasterize -> re-analyze as new scan
      |         |
      |         v
      |     derived scan ALLOW? -> approved artifact download
      |
      +--> BLOCK / non-ALLOW: no download, source never released
```

The one sentence that matters most: **hostile parsing happens entirely outside the
trusted application process.** Everything the trusted side does with document bytes is
"copy them, hash them, hand a read-only file descriptor to a sandbox" — never "open
them with a library."

## F. Why Bubblewrap

Parsers are themselves an attack surface: a PDF or Office parser processing an
attacker-crafted file can be exploited like any other software. Rather than trying to
make parsing bug-free, DocGuard assumes parsers **will** eventually be exploited and
contains the blast radius: each document gets a fresh, disposable Bubblewrap sandbox
with new user/PID/network/IPC/UTS/mount namespaces, all capabilities dropped, no
network route, a cleared environment, cgroup memory/CPU/task limits, and `prlimit`
process limits. If a parser is compromised, the attacker lands in a namespace with no
secrets, no database, no home directory, and no way out — not inside the process that
holds credentials and makes the release decision.

## G. Why static analysis (not dynamic/behavioral sandboxing)

Static, structural analysis was chosen over full dynamic execution/behavioral
sandboxing for this scope because it is:

- lower infrastructure burden — no need to run and instrument full guest VMs/office
  applications for every submission;
- deterministic and reproducible — the same input always produces the same findings;
- explainable — every finding maps to a specific structural characteristic (an
  OpenAction, a VBA autoexec entry point, an archive symlink), not a black-box verdict;
- appropriate for a small-office proof-of-concept scope with one development host and
  no dedicated security operations team.

A dynamic/behavioral sandbox tier is explicitly acknowledged as reasonable future work
(section O), not something DocGuard already provides.

## H. Why no VirusTotal / third-party upload

The documents DocGuard processes are exactly the kind of material a fiduciary office
cannot casually hand to a third party: CINs, tax records, bank documents, client
corporate records. Uploading them to VirusTotal or an equivalent cloud service would
solve a detection problem by creating a confidentiality problem. DocGuard's policy is
explicit: no submitted document, filename, or extracted content is ever sent to an
external service.

## I. Why deterministic policy instead of ML

- **Auditability**: every score and decision can be traced to specific, named,
  versioned finding contributions — there is a paper trail, not a probability.
- **No training set**: there is no labeled corpus of real malicious business documents
  available to this project, and building one raises the exact confidentiality problem
  section H describes.
- **Reproducibility**: the same findings always produce the same decision; there is no
  model drift or retraining process to manage.
- **Explainability**: an operator (or a jury) can be shown exactly why a document was
  quarantined, in plain language, without needing to interpret a model's internals.
- **Manageable scope**: a fixed, reviewed policy registry is something one developer can
  fully specify, test, and defend within this project's timeframe.

## J. What ALLOW means

Use this wording exactly, every time:

> **ALLOW means DocGuard did not observe risky characteristics covered by the
> configured detection model.**
>
> ALLOW does **not** mean safe, clean, malware-free, or guaranteed benign.

The risk score is a **deterministic, policy-derived, explainable** number — not a
malware probability, not a confidence score, not an ML prediction.

## K. What CDR does

Content Disarm and Reconstruction (CDR), for eligible `QUARANTINE`/`REVIEW` PDFs only,
rasterizes each page to a flat RGB image inside a fresh sandboxed worker and rebuilds a
new PDF containing only those images — no JavaScript, no actions, no embedded files,
no forms can survive that process. Critically:

- the **source scan's decision never changes** — CDR is not a way to "fix" a verdict;
- the **source remains quarantined**; there is no route that releases the original
  bytes;
- the derived, rasterized PDF is **re-ingested as an independent scan** and goes
  through the full pipeline again (identification → PDF analysis → YARA → policy);
- a **BLOCK** source is never CDR-eligible — a hard block cannot be worked around by
  requesting reconstruction;
- only if the derived scan itself reaches `ALLOW` does an approved, downloadable
  artifact exist, and only that derived artifact — never the source — is downloadable.

## L. Fail-closed design

If analysis cannot safely complete — the PDF is encrypted, the Office package is
malformed, an archive hits its nesting or resource limit, the worker times out — the
scan is **not** release-eligible. Incompleteness is treated as a containment signal,
never silently upgraded to `ALLOW`. This was directly verified in the Phase 11
benchmark: all 9 pre-registered fail-secure cases ended non-release-eligible, and a
deliberately malformed case in the middle of a live sequence did not degrade the
application — the very next valid upload processed normally.

## M. Evaluation results

All figures below are from the Phase 11B official benchmark: 59 controlled, synthetic,
pre-registered fixtures executed once through the real Bubblewrap-isolated production
pipeline (see `docs/EVALUATION.md` for full methodology, hashes, and reproduction
instructions).

- 59 total cases — 41 risky, 18 benign.
- 41/41 risky-case detection recall (100%).
- 72/72 expected findings detected at the individual-finding level (100%).
- 0/18 benign cases escalated (0% false-escalation rate on the controlled benign set).
- 9/9 pre-registered fail-secure cases ended non-release-eligible (100%).
- CDR recovery: 2/2 eligible cases produced a release-eligible derived artifact; the
  1 BLOCK-decision CDR case was correctly ineligible.
- Median per-case latency 317 ms; p95 386 ms (real Bubblewrap sandbox, one development
  host).

**Always state the qualifier**: these results hold *within the controlled synthetic
59-case corpus and the documented detection model this project covers* — they are not
a malware-detection rate and not a claim about real-world adversarial samples.

## N. Limitations

See `docs/EVALUATION.md` §25/26 and `docs/THREAT_MODEL.md` "Host assumptions" for the
full technical detail. In summary:

- Static structural analysis only — no dynamic execution/behavioral detection.
- No claim of malware-free-ness for ALLOW; no zero-day guarantee.
- Evaluation corpus is synthetic, controlled, and sized at 59 cases, deliberately built
  around DocGuard's own documented detection coverage — not an independent adversarial
  benchmark.
- Benchmarked on a single development host; latency figures are host-specific.
- No MFA/SSO — local operator authentication only, one role.
- Process-local rate limiting and abuse counters — the qualified topology is a single
  Uvicorn worker/node.
- SQLite, single-node target; no built-in multi-node clustering.
- TLS termination and reverse-proxy configuration are administrator responsibilities;
  DocGuard trusts Nginx to own that boundary.
- The systemd reference unit is a syntactically verified reference, not a fully
  installed/hardened deployment performed as part of this project.
- No external antivirus/cloud reputation integration (by design — see section H).
- CDR currently covers PDF only; Office/archive CDR is not implemented.
- File-format coverage is intentionally narrow (PDF, Office OOXML/classic OLE, ZIP) —
  not a general-purpose file-format security scanner.

## O. Future work

Reasonable extensions that are **not** implemented today:

- MFA/SSO for operator authentication.
- Multi-node deployment with a shared/distributed rate limiter.
- Optional external AV/reputation integration where confidentiality permits (e.g. an
  on-premises engine, not a cloud upload).
- A dynamic/behavioral sandbox tier as a second analysis stage.
- Broader document-format coverage (RAR/7z/TAR, deeper Office CDR, archive CDR).
- Stronger centralized observability/alerting beyond structured local logs.
- A larger, independently constructed evaluation corpus, ideally with external review.

---

## Jury Q&A

Thirty likely questions with concise, defensible answers.

**1. Why not just use antivirus?**
Traditional AV is signature/heuristic-based and often depends on cloud reputation
lookups that would leak confidential client documents. DocGuard is a gateway that
controls *whether a document reaches a user at all* and can layer with AV, not replace
it; it does not claim AV-equivalent detection coverage.

**2. Is ALLOW proof the file is safe?**
No. ALLOW means no risky characteristic covered by the configured detection model was
observed. It is explicitly not a benignity claim — this wording is fixed across all
documentation and the UI.

**3. What if the PDF parser has a vulnerability?**
That's exactly what Bubblewrap isolation is for: the parser runs in a disposable
sandbox with no network, no secrets, and dropped capabilities. A parser exploit
compromises that empty sandbox, not the trusted application or its data.

**4. Why Bubblewrap instead of Docker?**
Docker is an orchestration/packaging tool built on the same kernel namespace
primitives; it adds daemon/API attack surface DocGuard doesn't need. Bubblewrap is a
minimal, purpose-built unprivileged-sandboxing tool with a small, auditable surface,
well suited to "isolate one short-lived process per document."

**5. Why no VM sandbox?**
A full VM per document adds significant infrastructure and latency the target
deployment (a small office, one host) cannot support, and namespace isolation plus
dropped capabilities plus no network already contains the realistic worker-escape
threat model for this scope. A VM/dynamic-sandbox tier is listed as future work, not
rejected outright.

**6. Why static rather than dynamic analysis?**
Determinism, explainability, and infrastructure cost — see section G. Dynamic analysis
is acknowledged future work.

**7. Why no VirusTotal?**
Confidential business documents should not be automatically uploaded to a third party
— see section H.

**8. Why deterministic scoring instead of AI/ML?**
Auditability, no available labeled training data, reproducibility, explainability, and
a scope one developer can fully specify and test — see section I.

**9. What happens when analysis fails?**
The scan is marked non-release-eligible and quarantined; incomplete analysis is treated
as a containment signal, never silently promoted to ALLOW. Verified directly in Phase
11 (9/9 fail-secure cases).

**10. Can an operator release a BLOCK file?**
No. There is no capability, endpoint, or UI action that overrides a BLOCK decision in
this release.

**11. Can CDR make a BLOCK file safe?**
No. BLOCK sources are categorically excluded from CDR eligibility — verified directly
in Phase 11 (`PDF-RISK-010`).

**12. Does CDR modify the original verdict?**
No. The source scan's decision is immutable once persisted; CDR only ever creates a
separate derived scan. Verified by re-fetching the source scan after every CDR request
in Phase 11 and confirming it was unchanged in all 3 CDR cases.

**13. Where are private keys/secrets?**
TLS private keys belong to the Nginx reverse proxy, not DocGuard. DocGuard's own
secrets are the session/CSRF token digests (SHA-256 only, never raw) and Argon2id
password hashes in its private SQLite database; the worker sandbox never receives any
of them.

**14. Why SQLite?**
The qualified topology is a single-node, single-Uvicorn-worker deployment appropriate
for a small office; SQLite with WAL, `synchronous=FULL`, and foreign keys is a proven,
zero-administration fit for that scale. It is an explicit, documented scope limit, not
an oversight (see limitations).

**15. Is SQLite production-ready here?**
Yes, for the qualified single-node topology this project targets, with the documented
WAL/durability/integrity-check tooling. It is not qualified for multi-node deployment.

**16. Why single worker?**
Abuse-rate-limiting counters are process-local; multiple Uvicorn workers would let an
attacker bypass per-operator limits by hitting different processes. Scaling out would
require a shared limiter, which is explicit future work, not silently assumed.

**17. How do you prevent ZIP bombs?**
The archive analyzer never trusts declared sizes: actual per-member and aggregate
decompressed bytes are what's counted against fixed budgets, with entry/member/
nesting/materialization limits and the outer cgroup/rlimit/timeout as a hard backstop.
Exceeding any limit produces a bounded partial/malformed result and quarantine, not a
crash.

**18. How do you prevent archive traversal?**
The archive analyzer never calls `extract`/`extractall`; it only reads member content
into bounded memory. Member names with parent-directory components or rooted paths are
detected and reported as findings — they are never turned into filesystem paths.

**19. How do you prevent stored-file path attacks?**
Storage keys are server-generated random 128-bit identifiers; the original filename is
metadata only and never forms a path. Finalized objects are opened with `O_NOFOLLOW`
and their type/owner/mode/link-count/size/hash are checked on the open descriptor
before any bytes are served.

**20. How is authentication protected?**
Local operator accounts with Argon2id password hashing, opaque CSPRNG session tokens
(only SHA-256 digests stored), absolute and inactivity session expiry, rotation on
login, and bounded per-peer/per-username login throttling.

**21. What about CSRF?**
Every cookie-authenticated mutation requires a constant-time, session-bound CSRF token
plus an exact configured-Origin check; there is no permissive CORS layer.

**22. What do your 100% evaluation numbers actually mean?**
Within a 59-case controlled, synthetic corpus built around DocGuard's own documented
detection coverage, every pre-registered expectation was met exactly on a single real
Bubblewrap execution. It means the implementation matches its own specification on this
corpus — not a general malware-detection rate.

**23. Why is 59 cases enough/not enough?**
It's enough to exercise every documented detection category (PDF/Office/archive/file-
identity/YARA, benign and risky, plus fail-secure and CDR paths) with concrete,
reviewable ground truth. It is not enough, and not intended, to be a statistically
powered claim about real-world detection accuracy — that would need an independent,
much larger, adversarially constructed corpus.

**24. What are the largest limitations?**
No dynamic execution, a synthetic (not adversarial/real-world) evaluation corpus, single
development host benchmarking, and no MFA/SSO or multi-node deployment support. See
section N for the full list.

**25. What would you add with more time?**
A dynamic/behavioral sandbox tier and a larger, independently built evaluation corpus
would be the two highest-value additions — see section O.

**26. How does this relate to defense in depth?**
DocGuard is one layer (a document gateway before human access), not a complete
security program. It's designed to compose with endpoint AV, email filtering, and
normal account security rather than replace them.

**27. What happens after a server crash?**
Persisted lifecycle state (`STORED`/`ANALYZING`/`COMPLETED`/`QUARANTINED`) is
non-release by default; a stale `ANALYZING` row from a crash is caught and quarantined
by the bounded, dry-run-by-default reconciliation tool, which never fabricates an
ALLOW and never deletes business objects.

**28. Why does the worker have no network?**
To remove exfiltration and SSRF as viable outcomes of a parser compromise, and because
nothing in structural analysis legitimately needs to make an outbound connection —
external URIs and relationships are recorded as bounded text, never fetched.

**29. Why is the policy trusted instead of the worker?**
The worker is disposable and runs against attacker-controlled input by definition — it
cannot be allowed to decide its own outcome. It reports observations only; a separate,
versioned, fingerprinted policy registry that never touches document bytes owns the
score and decision.

**30. How do you know the sanitized PDF is actually sanitized?**
It isn't trusted because it came from the renderer — it is re-ingested as an
independent scan and run through the identical identification → structural analysis →
YARA → policy pipeline used for any upload. "Sanitized" is a property demonstrated by
that re-analysis reaching ALLOW, not an assumption about the rendering step.
