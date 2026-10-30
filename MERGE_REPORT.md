# TRACEE — Combined Source (All Branches Merged)

**Combined on:** 2026-10-30
**Source:** 9 zip archives merged into this single tree
**Verification:** 746 / 746 tests pass (`pytest tests/`), package imports clean

---

## What was merged

| Archive | Role | Files | Contribution to this combined tree |
|---|---|---|---|
| `TRACEzip.zip` | Main source code (user-designated) | 97 | Base — byte-identical to `TRACEE-main.zip` (same MD5) |
| `TRACEE-main.zip` | Main branch snapshot | 97 | Base (identical to TRACEzip) |
| `TRACEE-0.1-foundation.zip` | Version branch (2026-10-07) | 52 | Fully contained in newer versions — nothing new |
| `TRACEE-0.2-packaging.zip` | Version branch (2026-10-09) | 58 | Fully contained in newer versions — nothing new |
| `TRACEE-0.2-services.zip` | Version branch (2026-10-09) | 57 | Fully contained in newer versions — nothing new |
| `TRACEE-0.3-frontend.zip` | Version branch (2026-10-09) | 58 | Fully contained in newer versions — nothing new |
| `TRACEE-research-uncertainty-aware-reconstruction.zip` | Research branch (2026-10-10) | 73 | Older snapshot; work already absorbed into main + consolidation |
| `TRACEE-research-benchmark-generator.zip` | Research branch (2026-10-17) | 97 | Older snapshot; work already absorbed into consolidation |
| `TRACEE-consolidation-research-integration-2026-10-18.zip` | Latest integration branch | 129 | **Winning content for all conflicts** (newest, strict superset) |

**Result: 129 files** — every file from every archive is present, each at its newest version.

## How conflicts were resolved

1. `TRACEzip.zip` and `TRACEE-main.zip` are byte-identical (MD5 `633bf1b872868f173a7adfa2edfd1c9f`) — confirmed the same main source.
2. Every file path in every branch was checksum-compared against the consolidation branch:
   - **0 files** from any branch are missing from the consolidation branch.
   - For the files that exist in older branches with different content, the differences were
     reviewed line-by-line: older versions contain only superseded code (e.g. schema version
     `"1.0"` → `"1.1"`, cosmetic `# ---` comment separators, older doc headers) or *lack* tests
     that the consolidation version includes (e.g. `test_corroborated_means_rule_support_passed_not_independent_sources`).
   - Therefore the consolidation branch (`2026-10-18`) holds the newest version of every file
     and was used as the winning content, with main as the declared base.
3. New content unique to the consolidation branch (now part of this tree):
   - `.github/workflows/tests.yml` (CI)
   - `docs/`: API_OPERATIONS, QUICKSTART, README-integration, evidence-analysis,
     evidence-reconstruction, hackathon-demo-runbook, systemd-journal-collector, windows-event-collector
   - `src/parsers/`: systemd_journal.py, windows_event.py
   - `src/tracee/`: activity.py, analysis.py, api.py, journal_collector.py, locking.py,
     reconstruction_rules.py, reconstruction_service.py, windows_event_collector.py
   - `tests/`: 9 new test modules
   - `ui/`: index.html, app.js, reconstruction-presentation.js, styles.css

## Verification performed

- `python -c "import tracee, parsers"` — OK
- `python -m pytest tests/` — **746 passed**, 0 failed (5.4 s)
- Structural check: no missing paths vs. any source archive
