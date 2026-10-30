"""
TRACEE Command-Line Interface

Provides the V0.2 command-line interface over the TRACEE
application service layer.

The CLI is intentionally thin. It is responsible for:

    - argument parsing
    - command dispatch
    - human-readable output
    - process exit codes

It does not implement evidence storage, hashing, chain construction,
or verification logic.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Sequence

from .errors import (
    ExitCode,
    TraceeError,
    exit_code_for,
)
from .services import TraceeService
from .journal_collector import CollectorError, JournalCollector
from .verify import VerificationState
from .verify_chain import ChainVerificationError
from .verify_metadata import MetadataVerificationError
from .windows_event_collector import (
    DEFAULT_MAX_BATCH_BYTES as WINDOWS_DEFAULT_MAX_BATCH_BYTES,
    DEFAULT_MAX_RECORDS as WINDOWS_DEFAULT_MAX_RECORDS,
    DEFAULT_MAX_RECORD_BYTES as WINDOWS_DEFAULT_MAX_RECORD_BYTES,
    MAX_BATCH_BYTES as WINDOWS_MAX_BATCH_BYTES,
    MAX_RECORDS as WINDOWS_MAX_RECORDS,
    MAX_RECORD_BYTES as WINDOWS_MAX_RECORD_BYTES,
    SUPPORTED_CHANNELS as WINDOWS_SUPPORTED_CHANNELS,
    WindowsCollectorError,
    WindowsEventLogCollector,
)


CLI_VERSION = "0.2.0"


def build_parser() -> argparse.ArgumentParser:
    """Build and return the TRACEE command-line parser."""

    parser = argparse.ArgumentParser(
        prog="tracee",
        description=(
            "TRACEE Threat Reconstruction & Cyber Evidence Engine"
        ),
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"TRACEE CLI {CLI_VERSION}",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    ingest_parser = subparsers.add_parser(
        "ingest",
        help="Ingest evidence into a TRACEE vault.",
    )

    ingest_parser.add_argument(
        "--vault",
        required=True,
        type=Path,
        help="Path to the TRACEE evidence vault.",
    )

    ingest_parser.add_argument(
        "source",
        type=Path,
        help="Path to the evidence source file.",
    )

    verify_parser = subparsers.add_parser(
        "verify",
        help="Verify one evidence object completely.",
    )

    verify_parser.add_argument(
        "--vault",
        required=True,
        type=Path,
        help="Path to the TRACEE evidence vault.",
    )

    verify_parser.add_argument(
        "evidence_id",
        help="TRACEE evidence ID to verify.",
    )

    verify_chain_parser = subparsers.add_parser(
        "verify-chain",
        help="Verify the complete persisted evidence chain.",
    )

    verify_chain_parser.add_argument(
        "--vault",
        required=True,
        type=Path,
        help="Path to the TRACEE evidence vault.",
    )

    verify_metadata_parser = subparsers.add_parser(
        "verify-metadata",
        help="Verify one evidence metadata record.",
    )

    verify_metadata_parser.add_argument(
        "--vault",
        required=True,
        type=Path,
        help="Path to the TRACEE evidence vault.",
    )

    verify_metadata_parser.add_argument(
        "evidence_id",
        help="TRACEE evidence ID to verify.",
    )

    metadata_parser = subparsers.add_parser(
        "metadata",
        help="Read one persisted metadata record.",
    )

    metadata_parser.add_argument(
        "--vault",
        required=True,
        type=Path,
        help="Path to the TRACEE evidence vault.",
    )

    journal_parser = subparsers.add_parser(
        "collect-journal",
        help="Explicitly collect local systemd journal entries as evidence.",
        description=(
            "Acquire bounded journalctl JSON batches into a TRACEE vault. "
            "This command runs only when explicitly started by an operator."
        ),
    )
    journal_parser.add_argument(
        "--vault", required=True, type=Path,
        help="Path to the TRACEE evidence vault.",
    )
    journal_parser.add_argument(
        "--state-dir", required=True, type=Path,
        help="Persistent collector checkpoint directory outside the vault.",
    )
    journal_parser.add_argument(
        "--interval-seconds", type=float, default=5.0,
        help="Polling interval from 0.1 to 3600 seconds (default: 5).",
    )
    journal_parser.add_argument(
        "--batch-size", type=int, default=100,
        help="Maximum records per batch, from 1 to 10000 (default: 100).",
    )
    journal_parser.add_argument(
        "--max-batch-bytes", type=int, default=4 * 1024 * 1024,
        help="Maximum serialized bytes per batch (default: 4194304).",
    )
    journal_parser.add_argument(
        "--max-record-bytes", type=int, default=1024 * 1024,
        help="Maximum serialized bytes per record (default: 1048576).",
    )
    journal_parser.add_argument(
        "--subprocess-timeout", type=float, default=15.0,
        help="journalctl timeout from 0.1 to 300 seconds (default: 15).",
    )
    journal_parser.add_argument(
        "--once", action="store_true",
        help="Run at most one bounded collection cycle and exit.",
    )
    journal_parser.add_argument(
        "--initial-position", choices=("tail", "beginning"), default="tail",
        help="Start at current tail (safe default) or collect retained history.",
    )

    windows_parser = subparsers.add_parser(
        "collect-windows-events",
        help="Explicitly acquire a bounded batch from a local Windows event channel.",
        description=(
            "Acquire the newest bounded records from one local Application or System "
            "channel, serialize them in chronological order, and ingest them as evidence."
        ),
    )
    windows_parser.add_argument(
        "--vault", required=True, type=Path,
        help="Path to the TRACEE evidence vault.",
    )
    windows_parser.add_argument(
        "--channel", required=True, choices=WINDOWS_SUPPORTED_CHANNELS,
        help="Local Windows Event Log channel to query.",
    )
    windows_parser.add_argument(
        "--provider",
        help="Optional exact Windows event provider name filter.",
    )
    windows_parser.add_argument(
        "--event-id", type=int,
        help="Optional exact Windows event ID filter (0-65535).",
    )
    windows_parser.add_argument(
        "--max-records", type=int, default=WINDOWS_DEFAULT_MAX_RECORDS,
        help=f"Maximum newest records to retrieve (1-{WINDOWS_MAX_RECORDS}; default {WINDOWS_DEFAULT_MAX_RECORDS}).",
    )
    windows_parser.add_argument(
        "--max-record-bytes", type=int, default=WINDOWS_DEFAULT_MAX_RECORD_BYTES,
        help=f"Maximum UTF-8 JSON bytes per record, excluding line terminator (1-{WINDOWS_MAX_RECORD_BYTES}; default {WINDOWS_DEFAULT_MAX_RECORD_BYTES}).",
    )
    windows_parser.add_argument(
        "--max-batch-bytes", type=int, default=WINDOWS_DEFAULT_MAX_BATCH_BYTES,
        help=f"Maximum total UTF-8 JSONL bytes including line terminators (1-{WINDOWS_MAX_BATCH_BYTES}; default {WINDOWS_DEFAULT_MAX_BATCH_BYTES}).",
    )

    metadata_parser.add_argument(
        "evidence_id",
        help="TRACEE evidence ID to read.",
    )

    return parser


def _verification_exit_code(
    state: VerificationState,
) -> int:
    """Convert a verification state into a stable process exit code."""

    if state is VerificationState.VALID:
        return int(ExitCode.SUCCESS)

    if state is VerificationState.TAMPERED:
        return int(ExitCode.EVIDENCE_TAMPERED)

    if state is VerificationState.MISSING:
        return int(ExitCode.EVIDENCE_MISSING)

    return int(ExitCode.VERIFICATION_FAILURE)


def _run_ingest(
    service: TraceeService,
    source: Path,
) -> int:
    """Execute the ingest command."""

    metadata, record = service.ingest(source)

    print("[PASS] Evidence ingestion completed")
    print(f"Evidence ID: {metadata.evidence_id}")
    print(f"Source: {metadata.original_filename}")
    print(f"Size: {metadata.size_bytes} bytes")
    print(f"SHA-256: {metadata.sha256}")
    print(f"Chain sequence: {record.sequence}")

    return int(ExitCode.SUCCESS)


def _run_verify(
    service: TraceeService,
    evidence_id: str,
) -> int:
    """Execute the complete evidence verification command."""

    result = service.verify(evidence_id)

    if result.state is VerificationState.VALID:
        print(
            f"[PASS] Evidence verified: "
            f"{result.evidence_id}"
        )
    else:
        print(
            f"[ERROR] Evidence verification failed: "
            f"{result.evidence_id}"
        )

    print(f"State: {result.state.value}")
    print(f"Message: {result.message}")

    return _verification_exit_code(
        result.state
    )


def _run_verify_chain(
    service: TraceeService,
) -> int:
    """Execute the complete chain verification command."""

    records = service.verify_chain()

    print(
        "[PASS] Evidence chain verified "
        f"({len(records)} record(s))"
    )

    return int(ExitCode.SUCCESS)


def _run_verify_metadata(
    service: TraceeService,
    evidence_id: str,
) -> int:
    """Execute metadata verification."""

    metadata = service.verify_metadata(
        evidence_id
    )

    print(
        f"[PASS] Metadata verified: "
        f"{metadata.evidence_id}"
    )

    print(
        f"SHA-256: {metadata.sha256}"
    )

    print(
        "Metadata hash matches chain"
    )

    return int(ExitCode.SUCCESS)


def _run_metadata(
    service: TraceeService,
    evidence_id: str,
) -> int:
    """Read and print one persisted metadata record."""

    metadata = service.get_metadata(
        evidence_id
    )

    print("[PASS] Metadata record loaded")
    print(f"Evidence ID: {metadata['evidence_id']}")
    print(
        f"Original filename: "
        f"{metadata['original_filename']}"
    )
    print(
        f"Size: {metadata['size_bytes']} bytes"
    )
    print(f"SHA-256: {metadata['sha256']}")
    print(
        f"Ingested at: "
        f"{metadata['ingested_at']}"
    )
    print(
        f"Media type: "
        f"{metadata['media_type']}"
    )
    print(
        f"Schema version: "
        f"{metadata['schema_version']}"
    )

    return int(ExitCode.SUCCESS)


def run_command(
    args: argparse.Namespace,
) -> int:
    """Dispatch a parsed command."""

    if args.command == "collect-journal":
        try:
            collector = JournalCollector(
                args.vault,
                args.state_dir,
                interval_seconds=args.interval_seconds,
                batch_size=args.batch_size,
                max_batch_bytes=args.max_batch_bytes,
                max_record_bytes=args.max_record_bytes,
                subprocess_timeout=args.subprocess_timeout,
                initial_position=args.initial_position,
            )
            if args.once:
                collected = collector.run_once()
                print("[PASS] Journal collector cycle completed" if collected else "[INFO] No journal batch was collected")
                return int(ExitCode.SUCCESS)
            collector.run_forever()
            return int(ExitCode.SUCCESS)
        except CollectorError as exc:
            print(f"[ERROR] {exc.message}")
            return int(ExitCode.VERIFICATION_FAILURE)
        except KeyboardInterrupt:
            print("[INFO] Collection interrupted; checkpointed work remains recoverable.")
            return 130

    if args.command == "collect-windows-events":
        try:
            result = WindowsEventLogCollector(
                args.vault,
                max_records=args.max_records,
                max_record_bytes=args.max_record_bytes,
                max_batch_bytes=args.max_batch_bytes,
                provider_name=args.provider,
                event_id=args.event_id,
            ).collect(args.channel)
        except WindowsCollectorError as exc:
            print(f"[ERROR] {exc.message}")
            return int(ExitCode.VERIFICATION_FAILURE)
        print("[PASS] Windows event acquisition completed and evidence verified")
        print(f"Channel: {result.channel}")
        print(f"Records: {result.record_count}")
        print(f"Serialized bytes: {result.serialized_bytes}")
        print(f"Evidence ID: {result.evidence_id}")
        print(f"SHA-256: {result.sha256}")
        print(f"Verification: {result.verification_state}")
        print(f"Verification message: {result.verification_message}")
        return int(ExitCode.SUCCESS)

    if args.command == "ingest":
        service = TraceeService(
            args.vault
        )

        return _run_ingest(
            service,
            args.source,
        )

    service = TraceeService(
        args.vault
    )

    if args.command == "verify":
        return _run_verify(
            service,
            args.evidence_id,
        )

    if args.command == "verify-chain":
        return _run_verify_chain(
            service
        )

    if args.command == "verify-metadata":
        return _run_verify_metadata(
            service,
            args.evidence_id,
        )

    if args.command == "metadata":
        return _run_metadata(
            service,
            args.evidence_id,
        )

    raise TraceeError(
        f"Unsupported command: {args.command}",
        exit_code=ExitCode.INVALID_INPUT,
    )


def main(
    argv: Sequence[str] | None = None,
) -> int:
    """Run the TRACEE command-line interface."""

    parser = build_parser()

    try:
        args = parser.parse_args(argv)

        return run_command(args)

    except ChainVerificationError as exc:
        print(
            f"[ERROR] Chain verification failed: {exc}"
        )
        return int(
            ExitCode.VERIFICATION_FAILURE
        )

    except MetadataVerificationError as exc:
        print(
            f"[ERROR] Metadata verification failed: "
            f"{exc}"
        )
        return int(
            ExitCode.VERIFICATION_FAILURE
        )

    except TraceeError as exc:
        print(
            f"[ERROR] {exc}"
        )
        return exit_code_for(exc)


if __name__ == "__main__":
    raise SystemExit(main())
