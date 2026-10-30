# Evidence Analysis API

The analysis API parses bytes already stored in a configured TRACEE vault. It
requires an explicit parser and verifies the source evidence before and after
parsing. Results are stored as immutable JSON files under
`analyses/{evidence_id}/`; the original
object, metadata record, and evidence chain are not used for derived results.

## Supported parsers

Parser identifiers match the existing parser registry:

- `linux_auth`: `YYYY-MM-DD HH:MM:SS EVENT user=VALUE ip=VALUE`. The legacy
  parser extracts only the timestamp, event type, user, and IP fields. Its
  timestamp has no timezone, so its normalized UTC extent remains unknown.
- `json_event`: one JSON object per line with `timestamp` and `event_type`.
  The existing parser preserves the `attributes` object and promotes its
  recognized top-level fields (`user`, `ip`, `source_ip`, `destination_ip`,
  `domain`, `hostname`, `process`, and `file`). Other top-level fields are
  ignored by that parser. Timestamp offsets are normalized to UTC; naive
  timestamps retain their raw value and have no normalized UTC extent.
- `systemd_journal`: one JSON object per line from an existing
  `journalctl --output=json` export. Journal-specific fields such as
  `__CURSOR`, `__REALTIME_TIMESTAMP`, `__MONOTONIC_TIMESTAMP`, and `_BOOT_ID`
  identify records; unrelated JSON objects are rejected. The normalized event
  type is always `journal_entry` and does not classify the entry as a security
  event. Only an explicit allowlist is promoted to attributes: message,
  priority, unit and syslog identifier, process IDs/identity, host and boot
  context, cursor, monotonic timestamp, and the original realtime timestamp
  value. Long values are bounded and marked as truncated. A byte-array
  `MESSAGE` remains an explicitly tagged byte array; unsupported JSON types
  are represented by their type and are not converted to misleading text.
  `__REALTIME_TIMESTAMP` is interpreted as nonnegative microseconds since the
  Unix epoch. Integer and ASCII numeric-string forms are converted with exact
  UTC arithmetic and emitted as ISO-8601 with a trailing `Z`. Missing,
  malformed, negative, or out-of-range values have no normalized timestamp.
  This parser consumes only the already acquired evidence bytes. It does not
  run `journalctl`, collect new data, checkpoint cursors, deduplicate records,
  recover from interruptions, or schedule collection.
- `windows_event`: one JSON object per line using the versioned
  `windows_event_log` envelope (`schema_version` `1.0`) below. This is a cross-platform parser for
  static evidence; it does not access Windows APIs or query event channels.
  The rendered event XML is retained as a string and is the preserved source
  representation. The parser checks its duplicated system fields against the
  envelope, rejects DTD/entity declarations, and rejects malformed XML,
  unknown versions, conflicting fields, and envelopes over 16 KiB (including
  event XML over 12 KiB). Rejected lines use the existing bounded
  `unsupported_record` diagnostic. Unknown XML fields remain in the original
  XML string. A source timestamp is preserved verbatim; UTC normalization is
  accepted only when the timestamp itself includes a timezone. Normalized
  timestamps use the analysis model's microsecond resolution; any greater
  source precision remains available in the raw timestamp and XML. Missing,
  unparseable, or timezone-free timestamps do not receive a guessed UTC time.
  Windows records produce the generic `windows_event` normalized event type;
  this parser adds no incident or reconstruction interpretation.

The envelope has a fixed set of fields and explicit `null` values for
unavailable source fields. JSON strings are UTF-8, so XML markup and Unicode
content are JSON-escaped on disk and decoded back to the original XML string
before validation. `event_id` is a non-negative integer; `record_id` is a
non-negative integer or `null`. Optional strings distinguish `null` (not
recorded) from an empty source string. The `timestamp.normalized_utc` value is
the canonical microsecond UTC representation derived from the raw timestamp,
or `null` when it cannot be justified.

```json
{"schema_version":"1.0","source_type":"windows_event_log","host":"WS-01","channel":"System","provider":{"name":"Service Control Manager","guid":null},"event_id":7036,"record_id":1234,"timestamp":{"raw":"2026-10-18T10:30:40.1234567Z","normalized_utc":"2026-10-18T10:30:40.123456Z"},"event_xml":"<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\"><System><Provider Name=\"Service Control Manager\"/><EventID>7036</EventID><EventRecordID>1234</EventRecordID><TimeCreated SystemTime=\"2026-10-18T10:30:40.1234567Z\"/><Channel>System</Channel><Computer>WS-01</Computer></System><EventData><Data Name=\"param1\">Example service</Data></EventData></Event>"}
```

The envelope duplicates host, channel, provider, event ID, record ID, and raw
timestamp from the XML `System` section. In rendered Windows event XML,
`EventRecordID` is a child element. If a separately supplied native record ID
and XML value disagree, serialization rejects the record instead of selecting
one. Provider name/GUID, host, channel, record ID, and timestamp may be `null`
only when the matching source field is absent and no independent native record
ID is available; event ID and the XML `System`/`EventID` are required. The XML
is bounded before parsing and DTD/entity declarations are rejected; general
external entity resolution is not enabled. No source fields are added to the
shared evidence metadata schema.

The parser registry does not supply parser versions; stored records report the
TRACEE adapter version (`1.0`), not a version asserted by the legacy parser.
Blank lines are counted. Malformed, invalid UTF-8, oversized, and unsupported
records are counted and receive a bounded list (first 100) of line-number and
diagnostic-code pairs. Raw source lines and parser exception text are not
copied into diagnostics. Records with absent or invalid timestamps can still be
preserved as partial observations when the selected parser recognizes them.

Default analysis limits are 64 MiB per source, 16 KiB per line, 20,000 normalized
events, and 16 MiB per stored result. `TRACEE_MAX_ANALYSIS_BYTES` may lower or
raise the input limit up to a hard 256 MiB ceiling. The
`TRACEE_MAX_ANALYSIS_RESULT_BYTES` setting may raise the result limit up to a
hard 64 MiB ceiling. A request that exceeds a limit fails without persisting a
partial result. Evidence must pass the existing full
verification before parsing and again afterward; the hash of the exact bytes
read during parsing must match the verified metadata hash.

## Endpoints

### `POST /api/v1/evidence/{evidence_id}/analyze`

Request JSON (exactly one field):

```json
{"parser":"systemd_journal"}
```

Returns HTTP 201 and an analysis summary with these fields:

| Field | Type | Meaning |
| --- | --- | --- |
| `analysis_id` | string | Unique `TRACE-AN-` identifier. |
| `evidence_id` | string | Validated source evidence identifier. |
| `source_sha256` | string | SHA-256 digest of source bytes read and verified. |
| `parser` | string | Selected parser ID: `linux_auth`, `json_event`, `systemd_journal`, or `windows_event`. |
| `parser_version` | string | TRACEE adapter version (`1.0`). |
| `created_at` | string | UTC RFC 3339 timestamp. |
| `event_count` | integer | Number of normalized records. |
| `diagnostics` | object | `lines_total`, `parsed_records`, `partial_records`, `blank_lines`, `malformed_lines`, and bounded `issues` array (`line_number`, `code`). |

The `source_sha256` binds the immutable result to the evidence bytes. Repeated
requests create distinct analysis IDs and do not overwrite earlier results.
The API records start, completion, and failure activity events using the
existing local actor classification. That classification is not a named
investigator identity. If completion auditing fails after persistence, the
response reports that the result was stored and that the audit was not
recorded.

### `GET /api/v1/evidence/{evidence_id}/analyses`

Returns `{ "evidence_id": "...", "analyses": [<summary>, ...], "pagination": {"offset": 0, "limit": 25, "total_analyses": 0} }`.
`offset` defaults to 0 and is bounded to 1,000,000; `limit` defaults to 25
and is bounded to 1–100. Each result is checked against the currently verified
source. Malformed records fail the request rather than being silently omitted.

### `GET /api/v1/evidence/{evidence_id}/analyses/{analysis_id}`

Returns the summary plus one page of normalized events, their matching source
observations, and pagination metadata. `offset` defaults to 0 and is bounded
to 1,000,000. `limit` defaults to 25 and is bounded to 1–50. Each event links
to its observation by `source_observation_ids`; observations contain the
evidence ID, parser, line locator, raw timestamp semantics, parse status, and
extracted attributes. No timeline, relationship, finding, or causality claims
are generated by this parsing API.

Errors use `{ "error": { "code": "...", "message": "..." } }`. Relevant
codes include `invalid_evidence_id`, `evidence_not_found`,
`integrity_verification_failed`, `unsupported_parser`, `parser_mismatch`,
`analysis_limit_exceeded`, `source_changed`, `analysis_invalid`,
`stale_analysis`, and `analysis_storage_failed`. Verification failures also
include the actual state under `verification.state`.
