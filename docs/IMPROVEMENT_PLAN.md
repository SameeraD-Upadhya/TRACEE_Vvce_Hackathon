# TRACEE Improvement Plan

Baseline (2026-10-30, Windows): `python -m pytest -q` → **745 passed, 1 skipped** (symlink-privilege test, Windows-only limitation). `node --check ui/app.js` → clean. CI (`.github/workflows/tests.yml`) runs pytest on a 3-OS matrix but has no lint, `bandit`, or `pip-audit` step.

Full task-by-task TDD plan for Phase 1 lives in `docs/superpowers/plans/2026-10-30-phase1-tracee.md`. This document is the narrative companion the master prompt (Section 4.1) asks for: current state, per-workstream design decisions, and risks. It will grow with each later phase.

## Current state (verified by reading the code, not assumed)

- **Integrity stack is real and tested:** `vault.py`/`chain.py`/`verify.py`/`verify_chain.py`/`verify_metadata.py` implement an unsigned, unanchored SHA-256 hash chain with a clean `VerificationState` enum (`VALID`/`TAMPERED`/`MISSING`/`INVALID`). `VerificationResult` currently returns only a free-text message, no structured failure layer — that's W2's gap.
- **Parsers are real but few:** `linux_auth`, `json_event`, `systemd_journal`, `windows_event`. No nginx/zeek/suricata/sysmon/cloudtrail parsers exist (W9, Phase 3).
- **Reconstruction is the most mature subsystem:** `reconstruction_service.py` already demonstrates the exact storage discipline (symlink-safe directories, exclusive file locks, canonical-JSON content hashing, create-or-return-existing, strict re-read validation) that W1/W4's new storage modules should copy rather than reinvent.
- **Judges' 13 complaints are all still verifiably true** as of this baseline: no relationship graph code outside `archive_future/` (which has broken imports and is reference-only), Findings & Reports and Timeline-graph are both literal placeholder text in `ui/index.html` (lines 180 and 183-185), no signed/anchored checkpoints, single shared `TRACEE_API_TOKEN` with no named identities, no performance numbers, no `scenarios/` demo, and the benchmark has only two self-authored baselines.
- **`pyproject.toml` lists a dependency named `httpx2`** in the `test` extra — unusual; verify it resolves before relying on it in any new test tooling.
- **Two stray `tracee` modules coexist:** `src/tracee.py` and the `src/tracee/` package. Flagged as a risk, not touched in Phase 1 (out of scope unless it actually collides with new work).

## Phase 1 workstreams and design decisions

Phase 1 covers W2 (tamper UX), W1 (relationship graph), W4 (reports), W7 (gap reasoning), W6 (end-to-end demo). **Execution order in the detailed plan deviates from the master prompt's listed order** because of real dependencies the prompt doesn't resolve: `tracee demo tamper` needs a demo-vault marker to exist first; the full `tracee demo` scenario needs relationships, reports, and gap detectors to exist before it can exercise them. The detailed plan therefore runs: demo-vault skeleton → W2 → W1 → W4 → W7 → full W6 wiring.

- **W2 (tamper UX):** Extend `VerificationResult`/`VerificationTamperError` with optional `failed_layer`/`layer_details` fields (backward compatible — existing 3-arg construction still works). Add `POST /api/v1/verify-all`, a new `alerts.py` module (append-only `alerts.jsonl`, mirrors `activity.py`'s lock pattern) for persistent, acknowledgeable TAMPERED/MISSING alerts, and `tracee demo tamper --vault <path>` which refuses to run on any vault lacking a demo marker file.
- **W1 (relationship graph):** New `relationships.py` (pure, deterministic entity/edge extraction from one analysis's observations — co-observed-in-the-same-record only, never cross-record inference) and `relationship_service.py` (storage, copying `reconstruction_service.py`'s safety pattern exactly). UI replaces the literal "Relationships are not available" notice with an inline-SVG graph (no external library, per the stdlib/no-CDN constraint), hand-written deterministic layout, legend, filters, and a text/table accessible fallback.
- **W4 (reports):** New `reporting.py` (pure report-document builder, HTML-escaped, deterministic apart from its own generation metadata) and `report_service.py` (immutable storage + manifest + verify). A review workflow (`review.py`) adds append-only accept/reject/needs-more-evidence decisions on reconstruction candidates. UI replaces the "Not available through the current API" placeholder.
- **W7 (gap reasoning):** New `gaps.py` with five detectors (sequence gap, silence interval, log-clear indicator, cross-source expectation, timestamp discontinuity), all reusing `coverage.py`'s existing `InterpretationState` vocabulary and its invariant that missing data alone never implies removal. New "Coverage & Gaps" UI panel.
- **W6 (demo):** Hand-authored `scenarios/intrusion-and-log-tamper/` and `scenarios/negative-control/` fixtures, with `EXPECTED_RESULTS.md` frozen and committed *before* the code is run against it. `tracee demo` CLI ingests, verifies, analyzes, builds relationships, runs gap detection and reconstruction, generates a report, and starts the loopback server with a printed walkthrough — using the existing single-shared-token model for now, since named-principal identities are W5 (Phase 2). This is a deliberate, documented scope decision per the master prompt's own "pick the conservative, honest option" instruction (Section 4.6), because the master prompt's W6 text otherwise assumes W5 principals that don't exist yet in Phase 1.

## Cross-cutting risks (tracked in the detailed plan's Review Focus)

1. Backward compatibility of `VerificationResult` when adding fields.
2. Symlink/path-traversal safety of four new vault subdirectories (`relationships/`, `reports/`, `reviews/`, `alerts.jsonl`).
3. HTML injection in generated reports from hostile log content.
4. Concurrent build-or-get races on relationship/report storage.
5. Non-overclaiming wording regressions in new UI/report copy (Section 8's forbidden-word list).

## Deferred to later phases (not forgotten, just not in scope yet)

- W3 signed/anchored checkpoints, W5 identities/roles/cases, W13 security hardening, W12 full UI/UX+a11y polish → Phase 2.
- W9 new parsers, W8 performance benchmarks, W11 benchmark credibility/comparison, W10 collection agent → Phase 3.
- W14 docs/deck/judge readiness, final `FINAL_REPORT.md` → Phase 4.
