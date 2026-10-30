# Evidence-backed candidate reconstruction

TRACEE exposes deterministic candidate reconstruction over a previously persisted, integrity-checked analysis. This workflow does not edit source evidence, metadata, chain records, or analysis records. Each invocation produces a separate immutable JSON run under `reconstructions/<evidence-id>/`.

## Built-in rules

The registry currently has two versioned rules: `same-user-event-linux_auth@1.0.0` and `same-user-event-json_event@1.0.0`. Each rule only accepts its matching parser output and groups observations within one analysis when the extracted `user` and linked normalized event's `event_type` match and their known temporal extents fall within the requested candidate window. The event type is projected into a temporary observation value for the reconstruction engine; persisted analyses are never rewritten. A collision with the reserved projection field is rejected.

At least two observations are required for a candidate to be corroborated by the evaluator. Singleton clusters may still appear, but remain `insufficient_input`. Unknown timestamps are not assigned inferred times and cannot be grouped. Equal usernames do not establish a common person, account controller, host, or cross-evidence identity. Temporal proximity does not establish causality or prove that an incident occurred. No cross-evidence correlation is performed.

## API

- `GET /api/v1/reconstruction/rules` returns the actual built-in registry, including versions, parser support, required attributes, documented assumptions, and limitations.
- `POST /api/v1/evidence/{evidence_id}/analyses/{analysis_id}/reconstruct` accepts `{"candidate_window_seconds": 300}`. The property may be omitted (default 300); it must be a JSON integer from 0 through 86400. Booleans, floats, strings, negative values, and larger values are rejected. Successful persisted runs return `201` with provenance, selected rule versions, configuration, counts, and status.
- `GET /api/v1/evidence/{evidence_id}/reconstructions?offset=0&limit=25` returns validated summaries, with limit at most 50.
- `GET /api/v1/evidence/{evidence_id}/reconstructions/{reconstruction_id}` returns a run and separately paged `hypotheses` and `skipped_inputs`, each with offset and limit parameters (limit at most 50).

Run records are validated for schema, digest, identifiers, count consistency, and source provenance when read. The source analysis is reloaded through `EvidenceAnalysisService` and its source evidence is verified against the current vault state. Changed or unverifiable source evidence is not presented as current. `TRACEE_MAX_RECONSTRUCTION_RESULT_BYTES` can lower the default 16 MiB serialization limit; values above the hard 64 MiB ceiling are rejected. `TRACEE_MAX_RECONSTRUCTION_PAGE_SIZE` sets the maximum page size (default 50; hard maximum 50), and `TRACEE_DEFAULT_RECONSTRUCTION_PAGE_SIZE` sets the default (25, bounded by the configured maximum). Content digests detect accidental or unauthorized modifications only when the record's digest is not also recomputed; they are not a keyed authenticity mechanism.

Reconstruction start, completion, and failure are appended through the existing validated activity log. Its current schema can record the evidence ID, source SHA-256 on successful completion, actor classification, outcome, timestamp, and chain hashes. It has no fields for analysis IDs, reconstruction IDs, or rule references, so those are preserved in the result record rather than fabricated into activity fields. Authenticated API reconstruction operations record the actor category `local_api_token`; this identifies the credential path, not a named investigator.
