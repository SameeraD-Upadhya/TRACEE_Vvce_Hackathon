# TRACEE Synthetic Multi-Source Security Telemetry Corpus

**Version:** 1.0.0  
**Total:** 750,000 synthetic event records  
**Sources:** 10 CSV datasets  
**Generation seed:** `20261030`  
**Time window represented:** 2026-10-23 through 2026-10-30 UTC

> **Data provenance warning:** Every row in this package is generated synthetic data. It was not collected from real Windows/Linux endpoints, real organizations, real users, or real network traffic. Hostnames, users, addresses, domains, messages, and activity are fictional. The IP addresses use documentation/test ranges and domains use `.example`/`.test` namespaces. The package is appropriate for parser, replay, demonstration, and controlled evaluation—not for claims about real-world prevalence or live endpoint detection.

## Contents

```text
TRACEE_Synthetic_Security_Dataset_v1/
├── dataset_manifest.json
├── scenario_profiles.json
├── validation_report.json
├── COMPATIBILITY_REPORT.md
├── REPLAY_GUIDE.md
├── SHA256SUMS.txt
├── NOTICE.txt
├── README.md
├── DATA_DICTIONARY.md
├── data/
│   ├── linux_auth.csv
│   ├── systemd_journal.csv
│   ├── windows_security.csv
│   ├── windows_sysmon.csv
│   ├── process_activity.csv
│   ├── network_flow.csv
│   ├── dns.csv
│   ├── filesystem.csv
│   ├── service_persistence.csv
│   └── web_application.csv
├── ground_truth/
│   └── ground_truth_positive_only.csv
├── schemas/
│   └── common_record_schema.json
├── samples/
│   ├── replay_smoke_test/       # 25 sample rows per source
│   └── compatibility_test/     # 1,000 adapter/parser-tested rows per source
└── tools/
    ├── generate_dataset.py
    └── tracee_csv_adapter.py
```

The ground-truth file is deliberately separate from evidence CSVs. It contains only non-benign records (`SUSPICIOUS` or `MALICIOUS`); a source row absent from that file is `BENIGN` by the generation policy. It includes the scenario profile, technique/tactic annotations and rationale. Do not ingest ground truth as evidence or expose it to detection logic. Keep it in an evaluation-only location. The eight cross-source profiles are catalogued in `scenario_profiles.json`.

## Dataset allocation

| CSV | Records | Existing TRACEE parser | Adapter output |
|---|---:|---|---|
| `linux_auth.csv` | 90,000 | `linux_auth` | auth-log text `.log` |
| `systemd_journal.csv` | 75,000 | `systemd_journal` | systemd journal JSONL |
| `windows_security.csv` | 95,000 | `windows_event` | TRACEE Windows Event JSONL envelope |
| `windows_sysmon.csv` | 100,000 | `windows_event` | TRACEE Windows Event JSONL envelope |
| `process_activity.csv` | 70,000 | `json_event` | JSON event JSONL |
| `network_flow.csv` | 75,000 | `json_event` | JSON event JSONL |
| `dns.csv` | 55,000 | `json_event` | JSON event JSONL |
| `filesystem.csv` | 60,000 | `json_event` | JSON event JSONL |
| `service_persistence.csv` | 55,000 | `json_event` | JSON event JSONL |
| `web_application.csv` | 75,000 | `json_event` | JSON event JSONL |
| **Total** | **750,000** | **4 parser IDs** | **4 output formats** |

The `windows_security.csv` and `windows_sysmon.csv` are structured synthetic event records—not native EVTX files. The adapter constructs TRACEE's existing versioned JSONL envelope with a well-formed Windows Event XML payload. `network_flow.csv` contains flow metadata only; it does not contain PCAP packets or payloads.

## Quick start

Python 3.10+ is recommended. The generator and adapter use only the Python standard library.

### 1. Validate the downloaded corpus

From this directory:

```powershell
python .\tools\tracee_csv_adapter.py validate
```

This verifies source file hashes, headers, row counts, record ID uniqueness, synthetic markers, timestamps, and the separate ground-truth checksum.

### 2. Prepare a randomized replay sample

This selects up to 5,000 rows per source, shuffles records reproducibly, and emits batches of up to 5,000 lines. The batches from the different source families are then interleaved into a seeded replay queue in formats accepted by the existing TRACEE parsers:

```powershell
python .\tools\tracee_csv_adapter.py prepare `
  --seed 42 `
  --records-per-source 5000 `
  --batch-size 5000 `
  --output replay_runs
```

To test against the actual parser package in your TRACEE checkout:

```powershell
python .\tools\tracee_csv_adapter.py prepare `
  --seed 42 `
  --records-per-source 1000 `
  --batch-size 1000 `
  --output samples `
  --tracee-root "C:/path/to/TRACEE"
```

`--tracee-root` must point to the project root containing `src/parsers/`. The command records a `compatibility_report.json` in the replay run directory.

### 3. Prepare the complete corpus for replay

Use `--records-per-source 0` to include every record. This can generate many evidence batches; start with the 5,000-per-source smoke run first.

```powershell
python .\tools\tracee_csv_adapter.py prepare `
  --seed 20261030 `
  --records-per-source 0 `
  --batch-size 5000 `
  --output replay_runs
```

Changing the seed changes the selected rows and replay order. Reusing a seed and the same corpus version reproduces the same selected records and order. Original `event_timestamp` values are retained; the consuming simulation must separately record replay time and vault ingestion time. The prepared run manifest includes the source CSV hash, replay-order record-ID digest, parser ID and batch hash for each batch.

### 4. Upload prepared batches into an already-running TRACEE API (optional)

The current repository has `POST /api/v1/evidence`, which accepts one multipart file named `file`. The endpoint requires `TRACEE_API_TOKEN` and `TRACEE_UPLOAD_TOKEN` to be the same secret (at least 32 characters). Start the API with those settings, then:

```powershell
$env:TRACEE_API_TOKEN = "<same-32+-character-token-configured-on-server>"
python .\tools\tracee_csv_adapter.py upload `
  --run-dir "replay_runs/REPLAY-42-YYYYMMDDTHHMMSSZ" `
  --api-url http://127.0.0.1:8000 `
  --analyze `
  --delay-min-ms 100 `
  --delay-max-ms 500
```

Or provide `--api-token`. By default the adapter uploads only; add `--analyze` to call the existing analyze endpoint after each successful acquisition, using that batch's parser ID. The adapter writes `upload_report.json`; review it and the TRACEE API response rather than assuming all files were accepted. Duplicate evidence is expected to be rejected by the current vault because it rejects identical SHA-256 objects. This optional uploader follows the current API contract but was not tested against a live configured server in this environment.

## Verified compatibility smoke test

The included `samples/compatibility_test/` run contains 1,000 randomly selected records from each of the ten sources (10,000 total). It was tested against the parser registry in the uploaded TRACEE repository. Every prepared batch passed both `can_parse()` and `parse_line()` for all records. The same ten batches were ingested into a temporary isolated filesystem vault, each evidence object verified as `VALID`, all 10,000 events analyzed with the mapped parser, and the full 10-record custody chain verified. The detailed results are in `samples/compatibility_test/` and `COMPATIBILITY_REPORT.md`.

This is an offline integration smoke test against the uploaded Python code, not a live test of the running FastAPI server or browser UI.

## Parser compatibility contract

- `linux_auth`: adapter outputs lines matching the existing regex: `YYYY-MM-DD HH:MM:SS EVENT user=VALUE ip=VALUE`. This parser extracts timestamp, event type, user, and IP only. Other original columns remain available in the CSV source, but are not extracted by this legacy parser.
- `systemd_journal`: adapter outputs one JSON object per line with systemd markers (`__CURSOR`, `__REALTIME_TIMESTAMP`, `_BOOT_ID`) plus allowlisted fields. The current parser normalizes each record to `journal_entry`; it does not independently classify security events.
- `windows_event`: adapter emits the existing `windows_event_log` schema version `1.0`, including valid XML, matching envelope/System fields, record IDs and UTC timestamps.
- `json_event`: adapter emits one JSON object per line with `timestamp`, `event_type`, and all source CSV columns under `attributes`.

The generated replay formats preserve the original CSV records as the source-of-truth dataset. Do not replace or discard the CSV corpus after conversion. The adapter uses the standard library only; no `pandas`, `numpy`, or external package install is required.

## Replay safety and provenance

- This is offline dataset replay; it does not run attacks, execute command lines, contact external hosts, or collect endpoint telemetry.
- Event records contain descriptive process/command-line strings only. They are evidence-like data, not executable instructions.
- Do not describe replayed historical records as live endpoint events. UI labels should say `Synthetic dataset replay` and show original event time, replay time, and ingestion time separately.
- Ground-truth labels are for evaluation only. The analysis/detection path must not read them.
- A replay seed, dataset version, source ID and selected record IDs should be retained in the simulation manifest.
- The existing vault's duplicate-SHA behavior means uploading the exact same prepared batch again will return a duplicate error. Use a new sampled batch or handle the duplicate as an already-acquired object; do not modify source evidence to evade deduplication.

## Regenerating the corpus

```bash
python tools/generate_dataset.py --output . --seed 20261030 --scenarios 1500
python tools/tracee_csv_adapter.py validate
```

The generator is deterministic for a fixed Python implementation, seed and scenario count. It rewrites the CSVs and manifest. Re-run it only when you intend to replace the current corpus.

## Current project-side work still required

The data and adapter are provided, and the output formats are mapped to the parser registry in the uploaded TRACEE checkout. The repository still needs the following application integration for a polished, one-click simulation workflow:

1. **UI parser option:** `src/parsers/registry.py` contains `windows_event`, but `ui/index.html` currently exposes only `linux_auth`, `json_event`, and `systemd_journal`. Add the Windows Event parser option or use the existing parser ID from the simulation metadata where analysis is launched.
2. **Replay controls and progress:** add a Simulation Lab screen/control flow for start, pause, resume, stop, selected sources, seed, records per source and batch size. The supplied adapter is a command-line preparation/upload tool, not yet a background API replay service.
3. **Batch ingest orchestration:** call the existing `POST /api/v1/evidence` endpoint for each prepared batch. The adapter's optional uploader does this sequentially, but the frontend does not yet manage the run or show a live event stream.
4. **Automatic analysis:** after successful acquisition, use each batch's `parser_id` from `replay_manifest.json` to call the existing analyze endpoint. The current upload API only stores evidence and does not automatically analyze it.
5. **Run persistence and UI status:** persist replay session state, selected record IDs, progress, upload results and errors. A UI refresh should retrieve run state rather than reset counters.
6. **Windows semantics:** these are normalized synthetic Windows event envelopes, not genuine EVTX exports. If native EVTX import is later required, add a tested EVTX acquisition/export adapter separately.
7. **Parser field depth:** the current Linux authentication parser extracts only four fields; the current systemd parser normalizes the message and allowlisted journal fields; the current Windows parser produces a generic `windows_event` event and retains XML in an attribute rather than extracting every event-specific field. Additional event-specific normalization/correlation is future work.
8. **Integrity fixtures:** intentionally invalid, tampered, or missing-artifact examples are not mixed into the 750,000 valid synthetic telemetry rows. Keep those as separate vault QA fixtures so ordinary replay batches remain parser-valid.

## Research/evaluation caveat

The corpus is designed for software demonstration and controlled test coverage. It is not an independently collected dataset, and its synthetic ground truth does not establish detection performance on real enterprise telemetry. For external research claims, evaluate separately on original public datasets with source attribution and documented licensing.
