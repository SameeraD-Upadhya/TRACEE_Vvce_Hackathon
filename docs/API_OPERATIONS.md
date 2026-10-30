# TRACEE Local API Operations

The API is intended for local development and binds Uvicorn to `127.0.0.1`.
From the repository root, it can be launched natively with
`python -m uvicorn tracee.api:app --app-dir src --host 127.0.0.1 --port 8000`
on Windows, Linux, or macOS. Configure `TRACEE_API_VAULT_DIR` in the local
shell before starting it. Every `/api/v1` route requires a shared bearer
credential. `/health` is public and returns only service identity/status;
interactive docs and the OpenAPI schema are disabled unless explicitly enabled.
This API is not production-ready and has no individual identity authentication,
per-user authorization, HTTPS deployment, or hardened network boundary.

## Configuration

Set `TRACEE_API_VAULT_DIR` to an already initialized vault. Upload does not
initialize or select a vault. The configured vault must already contain the
`objects/`, `records/`, `chain/`, and `.staging/` directories, the
`chain/chain.jsonl` file, and the `.vault.lock` file.

Set `TRACEE_API_TOKEN` to a high-entropy secret of at least 32 characters before
starting the API. All `/api/v1` endpoints require `Authorization: Bearer <token>`;
missing or invalid credentials fail closed. The server compares tokens in
constant time and does not log or persist them. The browser UI prompts for this
credential and keeps it only in page memory; closing or locking the page clears
the session. Never put the credential in a URL, frontend source, or browser
storage.

Uploads additionally retain their existing authorization and validation
checks. Configure `TRACEE_UPLOAD_TOKEN` to the exact same secret as
`TRACEE_API_TOKEN`; upload is disabled or misconfigured otherwise. This setting
is a compatibility gate for the upload route, not a second credential or a
bypass for API authentication. Upload size and same-origin checks still apply.
The shared credential records only an actor category and does not identify an
individual investigator.

For a disposable local credential in PowerShell, generate 32 random bytes and
assign the same value to both variables without displaying it:

```powershell
$tokenBytes = New-Object byte[] 32
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$rng.GetBytes($tokenBytes)
$env:TRACEE_API_TOKEN = [Convert]::ToBase64String($tokenBytes)
$env:TRACEE_UPLOAD_TOKEN = $env:TRACEE_API_TOKEN
$tokenBytes = $null
$rng.Dispose()
```

The API reads these environment variables at request time. Restart the process
after changing configuration and clear the variables from the shell when the
local session ends.

`/docs`, `/redoc`, and `/openapi.json` are disabled by default. Set
`TRACEE_API_DOCS_ENABLED=1` before app startup to enable them for local
development; leave it unset in deployments where the documentation surface is
not intended to be public. `/health` remains public in either mode.
Missing API configuration returns `503 api_auth_not_configured`; a too-short
configured value returns `503 api_auth_misconfigured`; missing or invalid
request credentials return `401 unauthorized`. These errors contain neither
the configured nor supplied credential.

`TRACEE_MAX_UPLOAD_BYTES` optionally sets the maximum file size as a positive
integer. The default is 104857600 bytes (100 MiB). Requests with a declared
content length substantially beyond the configured size are rejected before
multipart parsing; the extracted file stream is independently checked against
the exact configured file-size limit.

Uploads with an `Origin` header are accepted only when the origin matches the
API request's scheme and authority. Requests without an `Origin` header, such
as local command-line clients, are allowed when their bearer token is valid.
CORS is not enabled.

## Routes

All routes under `/api/v1` require the API bearer credential, including reads,
analysis, reconstruction, and activity history. This includes
`GET /api/v1/evidence`, `GET /api/v1/evidence/{evidence_id}`,
`GET /api/v1/evidence/{evidence_id}/verify`, analysis creation/list/detail,
timeline, reconstruction rules/create/list/detail, and activity history.

### `POST /api/v1/evidence`

Requires a bearer token and one `multipart/form-data` field named `file`.
Additional fields and multiple files are rejected. Uploaded bytes are copied
without transformation to a temporary file, then passed to
`TraceeService.ingest()`; the temporary file is cleaned up after processing.
Client filenames are reduced to a safe basename and are never used as vault
paths.

On a persisted, audited acquisition, returns HTTP `201` with:

| Field | Meaning |
|---|---|
| `evidence_id` | Actual identifier assigned by ingestion. |
| `metadata` | Actual persisted `EvidenceMetadata` fields: `schema_version`, `evidence_id`, `original_filename`, `size_bytes`, `sha256`, `ingested_at`, and `media_type`. |
| `chain_sequence` | Actual sequence from the persisted `ChainRecord`. |

A duplicate content upload returns `409 duplicate_evidence`. Other errors use
the error envelope `{"error":{"code":"...","message":"..."}}` and may
include an `operation` and `audit` object when the operation completed but its
required audit record did not. In that case, `operation.completed` describes
the evidence operation and `audit.recorded` is false; a stored object is never
reported as an ordinary successful audited acquisition if its completion event
could not be appended.

Upload error codes include `upload_disabled`, `upload_token_misconfigured`,
`unauthorized`, `invalid_origin`, `upload_configuration_invalid`,
`vault_not_configured`, `vault_unavailable`, `upload_too_large`,
`invalid_content_length`, `unsupported_media_type`, `invalid_multipart`,
`missing_file`, `unexpected_form_field`, `invalid_upload`, `invalid_filename`,
`empty_file`, `duplicate_evidence`, `ingestion_failed`, `storage_failure`,
`activity_log_invalid`, `activity_log_unavailable`, `activity_audit_failed`,
and `internal_error`. Error messages are sanitized and do not include local
paths, exception text, or secrets.

### `GET /api/v1/activity?limit=N`

Returns `{"activity":[...],"limit":N}` with validated entries newest first.
`limit` defaults to 50 and must be between 1 and 200. A valid vault without an
activity file returns an empty list and does not create audit files. Invalid or
unavailable activity data returns a sanitized `activity_log_invalid` or
`activity_log_unavailable` error. Reading this endpoint does not itself append
an activity event.

Each entry has these fields:

| Field | Type / meaning |
|---|---|
| `schema_version` | String schema version. |
| `event_id` | Unique UUID string. |
| `timestamp` | UTC ISO-8601 timestamp ending in `Z`. |
| `event_type` | Evidence view and verification, acquisition, analysis, or reconstruction started/completed/failed event types defined by the activity schema. |
| `actor` | `local_api_token` for authenticated API reads and operations, `local_upload_token` for API uploads, or `local_cli` for explicit local CLI acquisitions. These are actor categories, not named identities. |
| `outcome` | `success`, an actual verification state, `accepted`, or a stable acquisition failure code. |
| `evidence_id` | Valid TRACEE evidence ID when known, otherwise null. |
| `filename` | Safe filename basename when relevant, otherwise null. |
| `size_bytes` | Actual copied or persisted file size when available, otherwise null. |
| `sha256` | Actual persisted evidence digest when available, otherwise null. |
| `previous_hash` | `GENESIS` for the first record, then the preceding entry's record hash. |
| `record_hash` | SHA-256 over canonical JSON of the entry fields excluding `record_hash`. |

## Activity-integrity limits

The activity log is stored at `audit/activity.jsonl` within the vault. Appends
validate all prior entries, use canonical JSON, hash-link each record, and use
restrictive permissions where supported. Appends are serialized across threads
and processes on the same filesystem using the platform's exclusive file lock;
the hidden `audit/.activity.lock` file is lock coordination state, not an event.
Malformed or changed history fails closed. This detects many edits and
reorderings, but a privileged filesystem operator can rewrite the entire log
and recompute its hashes. The log is tamper-evident locally, not immutable or
externally anchored.

## Platform behavior

The active vault locking layer uses POSIX `flock` on Linux/macOS and Windows
byte-range locking on Windows. Lock failures stop the storage operation. On
POSIX, private files use restrictive mode bits. Python's Windows permission
API cannot set private NTFS ACLs, so files and directories inherit the access
control list of their parent; administrators should ensure the vault and temp
directory have appropriate ACLs. Stored evidence is also marked read-only on
Windows, which is a filesystem attribute rather than an access-control or
immutability guarantee. Cross-platform support is implemented, but each OS
still requires native test execution before being described as verified.

Metadata retrieval and verification require the shared API bearer credential,
like every other `/api/v1` route. Their activity entries use the
`local_api_token` actor category. This category records the credential path;
it does not identify a named investigator. Upload uses the
`local_upload_token` actor category, which likewise is not an individual
identity. A shared credential can serve as an additional access barrier for a
single-operator private deployment, but it does not provide individual
authentication or authorization. Public or multi-operator deployment requires
a separate identity and authorization design, secure transport, hardened
network boundary, evidence-storage access controls, and tested
backup/recovery procedures.
