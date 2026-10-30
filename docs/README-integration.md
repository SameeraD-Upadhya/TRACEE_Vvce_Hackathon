# TRACEE

TRACEE (Threat Reconstruction & Cyber Evidence Engine) is a local-first
digital-forensics application for acquiring evidence files, preserving their
integrity and provenance, analyzing supported event records, and presenting
rule-based reconstruction candidates for investigator review.

TRACEE is an active development project. It is not a production-ready public
service, and its reconstruction output does not establish that an attack or
incident occurred, prove causation, or establish independent corroboration.

## Current capabilities

- **Evidence acquisition and integrity:** ingest files into a filesystem vault,
  persist metadata and a hash-linked evidence chain, and verify evidence,
  metadata, and chain state through the existing service and CLI.
- **Event parsers:** `linux_auth`, `json_event`, `systemd_journal`, and
  `windows_event`. Parsers process evidence already in the vault; they do not
  acquire operating-system events by themselves.
- **Opt-in collectors:** the Linux systemd journal collector explicitly reads
  bounded `journalctl` JSON batches and maintains checkpoints when the operator
  starts it. The Windows collector is an explicit, one-shot acquisition from
  one local `Application` or `System` channel, with optional provider and event
  ID filters. It has no continuous polling or durable bookmark support.
- **Event analysis:** analyze verified evidence with an explicitly selected
  parser. Results retain source-observation provenance and are stored separately
  from the original evidence and evidence chain.
- **Reconstruction candidates:** apply versioned, built-in rules to stored
  analysis and preserve assumptions, limitations, unresolved conditions, and
  source provenance. Candidates are investigative leads, not incident findings
  or causal conclusions.
- **Timeline and local dashboard:** view normalized event time and source
  provenance through the local browser UI. The UI also supports evidence
  inventory, upload, integrity verification, analysis, reconstruction review,
  and activity history. Relationship data and findings/report generation are
  not currently exposed as completed capabilities.

## Install and run locally

Python 3.10 or newer is required. From a fresh checkout, install the project
and test dependencies, initialize a new vault, configure a high-entropy API
credential, and start the server on loopback. Follow
[the fresh-checkout quickstart](docs/QUICKSTART.md) for platform-specific
commands. For the repeatable Windows synthetic-evidence walkthrough, see the
[hackathon demo runbook](docs/hackathon-demo-runbook.md).

The UI is served by the API from the checkout's top-level `ui/` directory.
Keep that directory alongside the source tree when running the app. The
current packaging configuration does not declare the UI as wheel package
data, so a wheel-only installation should not be assumed to include the
dashboard.

From the repository root, create and activate a virtual environment, then
install the project and test dependencies:

```sh
python -m venv .venv
# Activate .venv for your shell, then:
python -m pip install -e ".[test]"
```

Initialize a new vault with `FilesystemVaultStore.initialize()` and start the
API using the steps in [the quickstart](docs/QUICKSTART.md). The API does not
create or initialize a vault automatically.

Run the Python test suite from the repository root with:

```sh
python -m pytest -q
```

The UI has no separate frontend build step. Optional source checks are:

```sh
node --check ui/app.js
node --test tests/test_reconstruction_presentation.test.js
```

Windows Event Log acquisition uses the optional `windows` dependency extra;
the systemd journal collector requires Linux and an accessible `journalctl`.
See the [Windows collector guide](docs/windows-event-collector.md) and
[systemd journal guide](docs/systemd-journal-collector.md) for their limits.

## Security and deployment boundaries

The development server binds to `127.0.0.1`. Do not bind it to `0.0.0.0`,
forward its port, or expose it directly to a public or shared network.
`/health` is public and reports service liveness only. Every `/api/v1` route
requires the shared bearer credential configured as `TRACEE_API_TOKEN`; browser
requests receive it from the operator and keep it in page memory. Upload also
requires `TRACEE_UPLOAD_TOKEN` to equal that API token. The shared token is not
named-user authentication, role-based authorization, or a production security
boundary. Locking the UI clears its page-held token but does not revoke the
server credential.

A private, single-operator deployment may put the loopback-bound API behind a
private-network-only gateway with explicit access policy and durable,
restricted vault storage. That deployment topology and its recovery procedures
still need operational validation. Do not assume a private GitHub repository
makes a deployed application private. Public deployment is out of scope and
requires a separate security design, including individual identity,
authorization, secure transport, storage isolation, and tested backup and
recovery.

The filesystem vault contains source evidence and derived records. Keep the
whole vault on durable storage, restrict access to it, and back it up and test
restoration. Evidence and activity integrity checks are useful tamper
indicators; they do not make a privileged operator unable to rewrite local
data or provide external immutable anchoring.

For API configuration, routes, error behavior, and operational limitations,
see [API Operations](docs/API_OPERATIONS.md).
