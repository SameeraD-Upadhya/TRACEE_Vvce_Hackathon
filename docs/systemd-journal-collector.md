# Local systemd journal collector

TRACEE's journal collector is an opt-in local CLI operation. It is not started by the API, installed as an operating-system service, or enabled at boot. It reads a bounded JSON export from `journalctl`; the original journald storage files are not copied or acquired.

## Prerequisites and access

Run the collector on Linux with `journalctl` installed and readable by the operator. Use the least privilege that can read the journal. Some systems expose only the invoking user's journal; system-wide access may require membership in an appropriate journal-reading group or a privileged invocation. Do not change journald policy just to make collection work.

Journal entries can contain sensitive data. Restrict access to both the evidence vault and the collector state directory. On POSIX systems TRACEE creates state with owner-only directory and file permissions. Windows is not a supported execution platform for this Linux journal collector.

## Safe first run

The default initial position is `tail`. The first cycle records the cursor of the current last journal entry and does not ingest the pre-existing history. If the journal is empty, TRACEE persists a UTC wall-clock watermark at microsecond precision and uses journalctl's inclusive `--since` filter only until the first batch is safely analyzed and committed. This avoids an unbounded no-cursor history query; after that batch, checkpoints are cursor-based again. Repeated bootstrap queries can include the watermark boundary, but entries are staged and committed in journal order before switching to a cursor.

The bootstrap watermark requires a stable system clock. If the current UTC time is earlier than the saved watermark, collection fails closed and does not advance a cursor. If the process is interrupted after the watermark is persisted but before the initial tail probe establishes whether the journal was empty, restart also fails closed because the original tail boundary cannot be inferred safely. Preserve the state and investigate before deliberate recovery. A clock rollback that occurs and is corrected entirely between polls cannot be detected by this watermark scheme; on systems where that is a material risk, establish reliable time synchronization before enabling collection. State is never silently reset if it is missing, malformed, incompatible with the configured vault, or inconsistent with a staged batch.

State must be stored outside and separate from the evidence vault. Do not delete or hand-edit the state directory to recover a failed collection. Preserve it and investigate the reported safe error first. The staged JSONL batch is the exact `journalctl --output=json` byte stream and is used to recover interrupted operations.

## Controlled and continuous collection

One bounded cycle, defaulting to current-tail initialization:

```sh
tracee collect-journal --vault /var/lib/tracee/vault --state-dir /var/lib/tracee/journal-state --once
```

To deliberately collect retained journal history from its beginning:

```sh
tracee collect-journal --vault /var/lib/tracee/vault --state-dir /var/lib/tracee/journal-state --initial-position beginning --once
```

To run continuously after explicitly starting the command:

```sh
tracee collect-journal --vault /var/lib/tracee/vault --state-dir /var/lib/tracee/journal-state --interval-seconds 5 --batch-size 100 --max-batch-bytes 4194304
```

Use the same vault, state directory, and initial-position mode on restart. `--once` processes at most one bounded batch; the first tail invocation is an initialization cycle. In continuous mode, SIGTERM requests a stop after the current bounded cycle finishes; Ctrl+C retains its existing stop behavior. Pending staged work remains checkpointed for restart.

## Checkpoints and recovery

The versioned checkpoint records the selected initial mode, vault identity, committed cursor, and (during empty-journal bootstrap) the UTC watermark and bootstrap phase. It also records (when work is pending) the cursor before that batch, first and last cursors, exact batch digest and size, evidence ID, analysis ID, and processing phase. Captures use `journalctl --after-cursor` or the temporary bootstrap `--since` filter and chronological output, then stop after the earliest batch count or byte limit; `--lines=N` is not used for routine reads because it selects the most recent entries and can skip intervening entries. A later batch resumes after the last committed `__CURSOR` value. Older checkpoint schemas are rejected and are never silently reinterpreted.

Before cursor commit, TRACEE stages and flushes the byte-exact JSONL batch, ingests it through `TraceeService`, and analyzes the acquired object with `systemd_journal`. If acquisition may have completed before the evidence ID checkpoint was written, restart retries ingestion; a duplicate is resolved only by finding exactly one byte-matching evidence object that passes the existing integrity verifier. If analysis may have completed before its checkpoint, validated stored analyses are searched and reused. Unresolved or corrupt state fails closed without moving the cursor. The process lock prevents concurrent collectors using the same state directory.

## Limits and failure reporting

Defaults bound each batch to 100 records, 4 MiB total, 1 MiB per record, and a 15-second `journalctl` timeout. Batch count/bytes, record bytes, timeout, and polling interval are configurable within bounded ranges. Existing analysis input/result limits also apply. Invalid JSON, missing `__CURSOR`, oversize records, journal read/permission failures, integrity failures, and state/checkpoint problems stop the cycle with an actionable sanitized CLI message. Raw journal messages and subprocess stderr are not printed.

The acquired evidence is a JSON export produced by `journalctl`, not a bit-for-bit copy of native journal storage. `journalctl` output is subject to the fields and serialization behavior of the installed systemd version and to the operator's journal visibility. This collector does not provide a systemd-managed service, automatic boot/login startup, or guaranteed collection when the operator is not running it.
