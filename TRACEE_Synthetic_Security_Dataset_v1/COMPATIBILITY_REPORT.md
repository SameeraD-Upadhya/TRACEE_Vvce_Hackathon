# TRACEE Dataset Compatibility & Integration Report

**Result: PASS for the generated 10,000-record smoke run**  
**Target code:** uploaded `TRACEE (2)(3).zip` extracted to the working checkout  
**Test type:** offline code-level integration; no live API server or browser session

## Dataset validation

| Check | Result |
|---|---:|
| Total source records | 750,000 |
| CSV source files | 10 |
| Scenario profiles | 8 |
| Correlated scenarios | 1,500 |
| Positive ground-truth rows | 9,377 |
| `SUSPICIOUS` labels | 5,813 |
| `MALICIOUS` labels | 3,564 |
| Source checksums | PASS |
| CSV schema and counts | PASS |
| Global record ID uniqueness | PASS |
| Synthetic provenance marker | PASS |
| UTC timestamp validation | PASS |
| Ground-truth references and checksum | PASS |
| Scenario profile catalog checksum | PASS |

The positive label rate is approximately 1.25% of all records. This is an intentionally imbalanced synthetic corpus; the rate is a design property of this generated corpus and must not be interpreted as an estimate of real security-event prevalence.

## Parser registry compatibility

The uploaded project parser registry exposes four parser IDs:

| Dataset source | Parser ID | Output produced by adapter | All sample records parsed |
|---|---|---|---:|
| Linux authentication | `linux_auth` | Legacy auth-log line format | 1,000 / 1,000 |
| systemd journal | `systemd_journal` | Journal JSONL with journal marker fields | 1,000 / 1,000 |
| Windows Security | `windows_event` | TRACEE v1.0 Windows Event JSONL envelope | 1,000 / 1,000 |
| Windows Sysmon | `windows_event` | TRACEE v1.0 Windows Event JSONL envelope | 1,000 / 1,000 |
| Process activity | `json_event` | Generic JSON event JSONL | 1,000 / 1,000 |
| Network flow | `json_event` | Generic JSON event JSONL | 1,000 / 1,000 |
| DNS | `json_event` | Generic JSON event JSONL | 1,000 / 1,000 |
| Filesystem | `json_event` | Generic JSON event JSONL | 1,000 / 1,000 |
| Service/persistence | `json_event` | Generic JSON event JSONL | 1,000 / 1,000 |
| Web/application | `json_event` | Generic JSON event JSONL | 1,000 / 1,000 |
| **Total** | **4 parser IDs** | **10 source batches** | **10,000 / 10,000** |

For each batch, the test called the parser's `can_parse()` against its sample prefix and called `parse_line()` against every line in the batch. No line was rejected by the selected parser in this 10,000-record smoke test.

## Evidence vault and analysis integration

The 10 generated replay batches were passed into the uploaded repository's actual Python `TraceeService` and `EvidenceAnalysisService`, using a disposable temporary vault outside the source tree.

| Check | Result |
|---|---:|
| Evidence objects ingested | 10 / 10 |
| Evidence IDs created | 10 |
| Evidence objects verified | 10 / 10 (`VALID`) |
| Analysis runs completed | 10 / 10 |
| Normalized events returned | 10,000 / 10,000 |
| Persistent custody chain records | 10 / 10 |
| Full chain verification | PASS |

The temporary vault was removed after the test. No user project files or configured vault were modified.

Machine-readable outputs:

- `validation_report.json`
- `samples/compatibility_test/REPLAY-*/compatibility_report.json`
- `samples/compatibility_test/REPLAY-*/vault_ingestion_smoke_report.json`

## Known limitations / project-side integration required

1. The screenshot's UI parser selector lists three parsers. The uploaded code registry contains `windows_event` as a fourth parser, but `ui/index.html` does not expose that option. Add the option before selecting Windows Security/Sysmon evidence for analysis in the browser UI.
2. CSV -> parser-compatible batch conversion is implemented in `tools/tracee_csv_adapter.py`. The prepared batches can be ingested through the current `POST /api/v1/evidence` API. A UI-driven replay session controller (start, pause, resume, stop, progress, retry, run persistence) is not implemented in this data package.
3. Uploading evidence and analyzing evidence are separate API operations in the current project. The optional adapter uploader performs upload only. The app still needs to trigger the analyze endpoint using the `parser_id` attached to each batch in `replay_manifest.json`.
4. The Windows parser validates the event envelope and XML but normalizes each row to generic `windows_event`; it does not fully extract all `EventData` fields into typed normalized observations. The original event XML and CSV remain available, but richer field extraction/correlation requires parser enhancement.
5. The Linux authentication parser extracts timestamp, event type, username and IP only. Several extra fields remain in the original CSV but do not appear in parser output.
6. `systemd_journal` maps all records to `journal_entry`; it preserves only its allowlisted journal attributes. TRACEE still needs event classification and cross-source correlation logic to turn these records into investigation findings.
7. This corpus is generated synthetic data, not native Windows EVTX, genuine Linux log exports, PCAP traffic, or telemetry captured from endpoints. It is suitable for replay/parser testing and UI demonstrations only.
8. The API uploader was not exercised against a live configured server in this environment. Its request format follows the current endpoint contract; actual network/auth configuration must be checked in the running app.

## Conclusion

This dataset is parser-compatible and has been successfully ingested, verified and analyzed through the uploaded TRACEE Python services at a 10,000-record smoke-test scale. It is therefore directly usable as the input corpus for a replay workflow after the adapter prepares parser-ready batches. A one-click frontend simulation feature still requires the UI/API orchestration listed above.
