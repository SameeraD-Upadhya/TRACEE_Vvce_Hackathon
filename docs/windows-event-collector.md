# One-shot Windows Event Log acquisition

TRACEE provides an explicitly invoked, one-shot command for acquiring a
bounded batch from one **local** Windows Event Log channel. It supports only
`Application` and `System`. It does not query `Security`, remote systems, or
the machine journal automatically; it does not install a service, poll, save
bookmarks, or resume collection.

## Install and run

On Windows, install the optional integration with:

```powershell
python -m pip install -e ".[windows]"
```

From the repository root, explicitly run one channel query:

```powershell
tracee collect-windows-events --vault D:\Cases\demo-vault --channel Application
```

Use `--channel System` to select the other supported channel. The default
query retrieves at most the newest 100 records; options can reduce or raise
the count up to 1,000. `--max-record-bytes` defaults to 16,384 bytes per
serialized JSON record (excluding its line terminator), and the serialized
batch limit defaults to 1 MiB. Both sizes are configurable, with hard maxima
of 16 KiB per record and 16 MiB per batch. The parser also enforces its
12 KiB rendered-XML ceiling and 16 KiB envelope ceiling. A limit violation
rejects the whole selected batch; it never truncates records or ingests only a
prefix.

Optional `--provider "Microsoft-Windows-Sample"` and `--event-id 1000`
filters can be used together or separately. TRACEE validates these values and
builds the Event Log XPath query internally; the CLI does not accept query
text. Provider matching uses the exact source `Provider/@Name`, and event IDs
must be integers from 0 through 65,535. Provider names are limited to 256
characters; empty names, names with leading or trailing whitespace, apostrophes,
or control characters are rejected so they cannot alter the generated query.
The native query filters events before applying the record-count bound.
TRACEE also checks rendered provider and event ID values before serialization.
If nothing matches, the command reports `no_matching_events` and creates no
evidence.

The pywin32 `Evt*` event handle used here exposes rendered XML but no separate
record-ID property. The collector therefore takes the record ID from the
rendered `System/EventRecordID` element. If that element and any independent
adapter-provided ID are both absent, the envelope keeps `record_id: null`; it
never infers an ID from event order or timestamps.

The native query requests records newest-first and takes no more than the
configured count. TRACEE validates and serializes the selected records in
deterministic chronological order, using normalized source timestamps,
record IDs, then source XML as tie-breakers. Records with missing or invalid
timezone-qualified timestamps, inconsistent source fields, malformed XML, or
an event channel different from the selected channel fail the acquisition.
Unavailable host/provider values and record IDs remain explicit `null` values;
TRACEE does not invent them.

The temporary JSONL file is closed before ingestion and removed in a `finally`
cleanup path. The resulting evidence uses the existing ingestion, hashing,
vault staging, metadata, evidence-chain, and verification pipeline. CLI output
reports the selected channel, record count, serialized bytes, evidence ID,
SHA-256, and actual verification state; it does not print event XML or event
contents. The activity log uses the `local_cli` actor category. It does not
identify an individual operator.

## Limits and operational notes

- Installing the `windows` extra supplies `pywin32`; normal cross-platform
  installs do not require or import it until the Windows command is run.
- The caller needs permission to read the selected local channel. The command
  reports access denial and does not substitute a different channel.
- If no events are returned, the command reports that no evidence was
  created. If evidence ingestion or verification fails, the command does not
  report successful acquisition.
- This phase has no durable checkpoint or bookmark. It does not guarantee
  exactly-once acquisition across repeated invocations. An identical batch
  is rejected by the existing duplicate-evidence check.
- Automated tests use synthetic event XML and a fake API adapter. They do not
  query real machine logs. The command has not been smoke-tested against a
  live Windows channel as part of this implementation.
