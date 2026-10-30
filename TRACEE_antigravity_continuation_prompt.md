# TRACEE CONTINUATION PROMPT — REMAINING WORK (for Google Antigravity)

> Give this entire file to the Antigravity agent with the TRACEE repository checked out, on branch `phase1-demo-critical`, with the worktree `.worktrees/phase1-demo-critical` active (that is where the 8 completed tasks live — verify this first, do not work from `master`).
> Baseline build: master commit `ddd2d96`, phase1 branch head `648c820` (17 commits ahead of master).
> Companion documents already in the repo: `docs/IMPROVEMENT_PLAN.md` (narrative plan) and `docs/superpowers/plans/2026-10-30-phase1-tracee.md` (the authoritative 18-task TDD spec — Tasks 1–8 are complete; you execute Tasks 9–18 exactly as written there, then the later phases).

---

## 0. HOW TO USE ANTIGRAVITY FOR THIS WORK

You are Antigravity, an agent-first IDE. Use your strengths deliberately; this project rewards verification over speed.

1. **Plan mode first.** For each task below, produce a short plan artifact before touching code. The repo's existing plan file already specifies files, tests and acceptance criteria per task — your plan should reference those task numbers, not reinvent them.
2. **One task = one commit.** Commit messages follow the existing convention on the branch (look at `git log master..phase1-demo-critical`: `feat(...)`, `fix(...)`, `test(...)` prefixes, workstream name in scope).
3. **Use the browser tool to verify UI work.** This repo has a strict "real behaviour, real screenshots" rule (Section 4.4 of the master prompt). After every UI task: start the server on loopback, drive the actual page, and save real screenshots into `docs/screenshots/` (`soffice`-style mockups and generated images are forbidden).
4. **Use artifacts for reports.** Write `docs/VERIFICATION_LOG.md` entries as you go: every "done" claim needs the exact command and its output. At the end of each phase, produce a verification artifact summarizing the phase.
5. **Terminal discipline.** Run `python -m pytest -q` (must end at 746 passed + your new tests, 0 failures) and `node --check ui/app.js` after every task. Never move on with a red suite.
6. **Walkthrough videos/screenshots as deliverables.** Antigravity can record walkthroughs; use one for the final demo path (upload → VALID → tamper → TAMPERED with failing layer) and save it under `docs/`.

---

## 1. VERIFIED CURRENT STATE (do not re-derive; spot-check only)

Already implemented and committed on `phase1-demo-critical` (Tasks 1–8 of the phase-1 plan):

- Task 1 — `src/tracee/demo.py`: demo vault marker + `tracee demo` CLI skeleton, `--reset` symlink guard.
- Task 2 — `verify.py`: per-layer tamper detail (`failed_layer`, `layer_details`) with backward-compatible construction; regression test in `tests/test_verify.py`.
- Task 3 — `POST /api/v1/verify-all` with summary counts; activity allowlist extended for 4 new event types; MISSING/INVALID counted correctly (tests in `tests/test_api.py`).
- Task 4 — `src/tracee/alerts.py`: append-only `alerts.jsonl`, raise/acknowledge, unit tests decoupled from ActivityLog.
- Task 5 — `tracee demo tamper`: safe tamper demo restricted to marked demo vaults, idempotent evidence-hash tamper.
- Task 6 — UI: real dashboard summary cards, chain visualizer, alert banner (silent-fetch-error and nested-live-region bugs fixed).
- Task 7 — `src/tracee/relationships.py` (861 lines): deterministic entity/edge extraction, co-observed-in-same-record only, `executed_by` requires explicit key, order-independence determinism test.
- Task 8 — `src/tracee/relationship_service.py`: storage mirroring `reconstruction_service.py` (symlink checks, exclusive lock, atomic replace, `content_sha256`, source-staleness check); API persistence per analysis.

**Not started (your work):** Task 9 (graph UI) through Task 18 (timing comparison), then Phases 2, 3 and 4.

The two UI placeholders (`ui/index.html` — "Relationships are not available" at the Timeline view, and "Not available through the current API" in Findings & Reports) are still present on the branch. Task 9 removes the first; Task 13 removes the second.

**Start by verifying this state:** checkout the worktree, run `python -m pytest -q` (expect 746 passed) and `node --check ui/app.js`, and confirm `git log --oneline master..phase1-demo-critical | wc -l` is 17. If any check fails, stop and report instead of "fixing forward" blindly.

---

## 2. REMAINING PHASE 1 WORK (demo-critical — execute Tasks 9–18)

Full task specifications, file lists, test requirements and acceptance criteria are in `docs/superpowers/plans/2026-10-30-phase1-tracee.md`. Summary and hard requirements:

### Task 9 — Timeline & Relationships graph UI
Inline SVG renderer (no external library, no CDN), hand-written deterministic layout, legend with shape+colour+label, node/edge counts, entity-type filters, time-range slider, search, pan/zoom, click → side panel with supporting observation IDs, source locators, parser and raw timestamps. Visible banner: "Edges mean co-observed in the same evidence record. They do not indicate causation or an attack path." Keyboard navigation for nodes and a text/table alternative of the same data. Remove the "Relationships are not available" notice when data exists; keep a clear empty state when the analysis has no entities. Node tests (`ui/*.test.js`) for layout determinism and filtering.

### Task 10 — Report builder core (`src/tracee/reporting.py`)
Pure, deterministic report document builder per master prompt W4: evidence inventory with fresh verification at generation time, verification history, timeline summary (unresolved time listed separately), relationship summary, reconstruction candidates with interpretation state and provenance, coverage/gap assessments (wired once Task 14 lands — build the section shape now), fixed "limitations and non-claims" section. Self-contained HTML (printable, HTML-escaped — hostile log content containing `<script>` must never render) and canonical deterministic JSON with isolated generation metadata.

### Task 11 — Report storage, export, manifest, API
Immutable `reports/` directory in the vault, manifest with SHA-256 of every file, report hash recorded in the activity log, export-as-copy, `GET` routes, "verify this report" recompute path. Tests: missing-evidence report, tampered-evidence report showing TAMPERED prominently, manifest verification.

### Task 12 — Review workflow (`review.py`)
Append-only review decisions (`reviewed-accepted-as-lead` / `reviewed-rejected` / `needs-more-evidence`) with note, principal category and time, stored separately from hypotheses. API routes + tests.

### Task 13 — Findings & Reports UI
Report list, generate dialog with scope selection and preview, download buttons, report hash display, verify-report button. Remove the "Not available through the current API" placeholder.

### Task 14 — Gap detectors (`src/tracee/gaps.py`)
Five detectors: sequence gap, silence interval, log-clear indicator, cross-source expectation, timestamp discontinuity. Reuse `coverage.py`'s `InterpretationState` vocabulary; interpretation states are `challenged` / `underdetermined` / `insufficient_input`, never "deleted". Each rule versioned with a plain-language false-positive description. Regression test proving missing data alone never creates a possible-removal claim. Benign look-alikes (quiet host, rotation boundary) must NOT raise a gap.

### Task 15 — Gap API + Coverage & Gaps UI panel
Per-source coverage timeline strip (covered / declared-uncovered / unknown), gap markers aligned to the timeline, per-gap card: what we observed, what we expected and why, alternative explanations, what evidence would settle it.

### Task 16 — Scenario fixtures + frozen `EXPECTED_RESULTS.md`
`scenarios/intrusion-and-log-tamper/` (auth.log with SSH failures then success, systemd journal export, JSON events with outbound connection, Windows events including a log-cleared event, one deliberate timestamp conflict, one timezone-unknown record, one declared logging-disabled gap) and `scenarios/negative-control/` (benign admin activity). **Freeze `EXPECTED_RESULTS.md` in a separate commit BEFORE running TRACEE on the data.** Any later change needs a recorded justification.

### Task 17 — Full `tracee demo` wiring
Demo creates an isolated marked temp vault, ingests the scenario, runs verify, analyses, relationships, gaps, reconstruction and a report, then starts the loopback server and prints the URL plus a numbered 5-minute walkthrough. Automated end-to-end test comparing against frozen `EXPECTED_RESULTS.md`; negative control must not produce a corroborated attack-like candidate. Demo runs offline, one command, from a clean checkout.

### Task 18 — Measured baseline comparison
Scripted, timed `grep`/`sort` baseline workflow vs TRACEE on the same data; medians over repeated runs; method and limits recorded. No extrapolation to real-world savings.

**Phase 1 exit criteria:** full suite green (746 + new tests), Node checks green, both UI placeholders gone, one-command demo runs from a clean temp vault, end-to-end test matches the frozen expected results, `docs/VERIFICATION_LOG.md` has an entry for every task, real screenshots saved. Commit `docs/VERIFICATION_LOG.md` update as the phase-close commit.

---

## 3. PHASE 2 — CREDIBILITY (start only after Phase 1 exit criteria are met)

- **W3 signed, anchored checkpoints** (per master prompt Section W3): Ed25519 via the optional `cryptography` extra (clear error when absent; core chain fully functional without it). `tracee keys generate` with restrictive permissions; public key + fingerprint in the vault; `tracee checkpoint export`; `tracee verify --anchor <file>` detecting tail truncation and full rewrite against an external anchor. Tests: valid anchor passes, truncation fails, full rewrite fails, bad signature fails, missing extra degrades cleanly. RFC 3161 documented as an extension point only — no network calls.
- **W5 identity, roles, cases** (Section W5): principals file with salted slow hash (`hashlib.scrypt` or `pbkdf2_hmac`), `hmac.compare_digest`, `tracee principals add|list|revoke|rotate`, tokens shown once. Legacy `TRACEE_API_TOKEN` maps to `legacy-admin` flagged as shared credential. Roles viewer/analyst/admin enforced server-side on every route with a table-driven permission test that FAILS the suite if a new route lacks a permission declaration. Login throttling with exponential backoff. Cases group evidence/analyses/reconstructions/reports/reviews without copying evidence; case selector in the UI header. Concurrency test with two principals.
- **W13 security hardening** (Section W13): `docs/THREAT_MODEL.md` (STRIDE, assets, trust boundaries, attacker models up to privileged vault-host attacker, residual risks). CSP without inline script, `X-Content-Type-Options`, `Referrer-Policy`, `Cache-Control: no-store` on API, Origin checks, request size limits, filename sanitization, content-type allow-list, path-traversal proof tests (`../`, absolute, symlink, Windows reserved, Unicode normalization). Escape/limit hostile log content everywhere. `pip-audit` + `bandit` output recorded. CI: pytest Linux (+Windows only if actually exercised), Node checks, ruff, type checks on new modules. Test that tokens never appear in logs/exceptions/URLs/reports.
- **W12 UI/UX polish** (Section W12): guided empty state, 5-step workflow strip, recent activity feed, toasts, search/filter/sort/CSV export on lists, loading skeletons, error+retry states, keyboard accessibility, WCAG AA in light and dark themes, `prefers-reduced-motion`, non-colour status cues, responsive to 1024px/768px, no layout thrash at 10,000 rows, static check failing on `TODO|Lorem|placeholder|coming soon` strings.

---

## 4. PHASE 3 — DEPTH AND PROOF

- **W9 parsers** in priority order: nginx/Apache combined access logs → Zeek `conn.log` (TSV+JSON) and Suricata `eve.json` (these feed `network_connection` edges into W1) → Sysmon via the windows_event path → AWS CloudTrail. Each: parser class in `registry.py`, ≥10 test cases including hostile inputs (very long lines, invalid UTF-8, control characters), documented supported fields and known limitations. `docs/PARSER_GUIDE.md` plugin contract. Do NOT claim memory-image or raw-pcap support anywhere.
- **W8 performance** (Section W8): `benchmarks/perf/` deterministic generators (100 MB, 1 GB, 1M and 10M events); measure ingest MB/s, peak RSS, parse/analysis events/s, timeline p50/p95, graph build, reconstruction and report times — ≥5 runs, hardware recorded. Stream line by line; server-side pagination with stable cursors; on-disk sorted timeline index if needed. 1 GB ingest must not load the file into memory. Publish `docs/PERFORMANCE.md` with measured values and single-process/local-FS limits stated plainly.
- **W11 benchmark credibility + comparison** (Section W11): freeze ground-truth labels in a dated commit with hashes recorded in results; structural diversity, clock-disagreement cases, broader negative controls, held-out set from unseen seeds; add Sigma-style single-event rule and time-window clustering baselines; run protocol ablations; report per-family precision/recall, unsupported-definitive-hypothesis rate, abstention appropriateness, and explicit failure cases. Label errors go through `docs/research/LABEL_ERRATA.md` with before/after results. `docs/COMPARISON.md`: factual table vs Timesketch, Plaso, Velociraptor, Autopsy, generic SIEM — every cell verified against current official documentation with the source cited, "not verified" where it cannot be verified; state where TRACEE is weaker; never call TRACEE "better".
- **W10 source-side collection** (Section W10): one-shot `tracee agent collect` computing SHA-256 at the source, signed manifest using W3 keys, upload via the existing authenticated API. Tests: manifest tampering fails, source-hash mismatch reported as such, replay rejected. Document that it is not an EDR. Ship only if Phases 1–3 core is green.

---

## 5. PHASE 4 — JUDGE READINESS

- `ReadMe.md`: accurate status, 3-command quickstart, real screenshot gallery, claims-versus-evidence table, "what TRACEE does not do" section.
- `docs/ARCHITECTURE.md` (Mermaid data-flow with trust boundaries), `docs/DEMO_SCRIPT.md` (5-min and 10-min scripts with fallbacks), `docs/JUDGE_QA.md` (hard questions and honest answers — include all ten listed in the master prompt W14).
- Deck: 7 slides matching the shipped product, real screenshots only, no "[Step N]" placeholders, forbidden wording absent, every number traceable to a repo file.
- Project documentation `.docx` updated to match; marked fields left for repository URL, team roles and demo link — do not invent them.
- `tools/check_claims.py` fails on forbidden feature names in README/deck text before they exist.
- `FINAL_REPORT.md`: per-problem status table (13 judge problems → workstream → evidence → fixed/partly/not), before/after rubric self-assessment, quality-gate results, open risks, assumptions, team-input list.

---

## 6. CONSTRAINTS THAT OVERRIDE EVERYTHING (from the master prompt — non-negotiable)

1. Integrity before analysis: never modify stored evidence, metadata, chain records or stored analyses; new outputs are new immutable records.
2. No overclaiming: output is an investigative lead; edges are co-observation, never causation; absence is never proof of deletion; hashing proves change after ingestion only. Caveats appear in UI, reports, README and deck.
3. Determinism: same input → byte-identical output including IDs; provenance on every derived object.
4. All existing tests stay green; test changes need written justification.
5. Loopback by default; no secrets in logs/URLs/browser storage.
6. Minimal dependencies: stdlib + FastAPI/uvicorn/python-multipart; optional extras in `pyproject.toml`; vanilla UI, no build step, no CDN, offline-capable.
7. No fabricated data: every number traces to a command with saved output; third-party statements verified against current official docs or omitted.
8. Backward compatible: CLI, API routes, on-disk layout, schema versions unchanged; new schema versions only; read-compatibility test.
9. Forbidden wording unless demonstrably true: "proves", "detects attacks", "attack-agnostic", "attack graph", "identifies the attacker", "tamper-proof", "court-admissible", "AI-powered", "real-time", "production-ready", "scalable to enterprise". Required: "candidate", "lead", "co-observed", "records show", "not independently corroborated", "synthetic benchmark", "exploratory".
10. Never import from `archive_future/`; mine it for ideas only. Never touch real vaults — demos and tests use fresh temporary vaults only.

---

## 7. WORKING RULES FOR THIS ENGAGEMENT

- **Order:** Phase 1 Tasks 9–18 → Phase 2 (W3 → W5 → W13 → W12) → Phase 3 (W9 items 1–2 → W9 items 3–4 → W8 → W11 → W10) → Phase 4. Do not reorder without recording why in the plan doc.
- **Stop rule:** if a task exceeds twice your estimated effort, abort it, mark it "not fixed, with reason" in the verification log, and continue. Never leave a half-built feature visible in the UI.
- **Per-task cycle:** plan artifact → implement with tests first where the plan file says TDD → full suite + Node check → commit → verification-log entry (+ browser check and screenshot for UI tasks).
- **Phase close:** re-run the demo from a clean temporary vault, update `docs/VERIFICATION_LOG.md`, produce a phase verification artifact, and summarize status honestly before starting the next phase.
- **Quality gates before the final report:** all ten gates of master prompt Section 9, including ≥90% line/branch coverage on new modules, the route-permission matrix, the frozen-expected-results match, and the placeholder/forbidden-string static check.
- If you are genuinely blocked (irreversible action, missing credential, contradictory spec), stop and report the blocker with the exact evidence. Otherwise decide conservatively, document the decision, and continue.
