"""
TRACEE Persistent Evidence-Chain Verification

Reads a persisted TRACEE chain from disk and verifies:

1. JSON structure
2. Chain record schema
3. Individual record hashes
4. Sequence continuity
5. Previous-record hash links
6. GENESIS linkage for the first record
7. Evidence-ID uniqueness

This module is read-only. It never modifies the chain.
"""

from __future__ import annotations

import json
from pathlib import Path

from .chain import verify_chain_link
from .models import ChainRecord


class ChainVerificationError(RuntimeError):
    """Raised when the persisted evidence chain is invalid."""


def load_chain(chain_path: str | Path) -> list[ChainRecord]:
    """
    Load and structurally validate every record in a chain file.
    """

    path = Path(chain_path)

    if not path.is_file():
        raise ChainVerificationError(
            f"Chain file does not exist: {path}"
        )

    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ChainVerificationError(
            f"Unable to read chain file: {path}"
        ) from exc

    records: list[ChainRecord] = []

    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            raise ChainVerificationError(
                f"Blank chain record at line {line_number}"
            )

        try:
            data = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ChainVerificationError(
                f"Invalid JSON at chain line {line_number}"
            ) from exc

        if not isinstance(data, dict):
            raise ChainVerificationError(
                f"Chain line {line_number} is not a JSON object"
            )

        try:
            record = ChainRecord(
                schema_version=data["schema_version"],
                sequence=data["sequence"],
                evidence_id=data["evidence_id"],
                timestamp=data["timestamp"],
                metadata_sha256=data["metadata_sha256"],
                previous_record_hash=data["previous_record_hash"],
                record_hash=data["record_hash"],
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ChainVerificationError(
                f"Invalid chain record at line {line_number}: {exc}"
            ) from exc

        records.append(record)

    if not records:
        raise ChainVerificationError(
            "Chain file contains no records"
        )

    return records


def verify_persistent_chain(
    chain_path: str | Path,
) -> list[ChainRecord]:
    """
    Verify the complete persisted TRACEE evidence chain.

    Returns the verified records.

    Raises ChainVerificationError on any integrity failure.
    """

    records = load_chain(chain_path)

    previous: ChainRecord | None = None
    seen_evidence_ids: set[str] = set()

    for index, current in enumerate(records, start=1):
        if current.sequence != index:
            raise ChainVerificationError(
                "Sequence discontinuity detected: "
                f"expected {index}, got {current.sequence}"
            )

        if current.evidence_id in seen_evidence_ids:
            raise ChainVerificationError(
                f"Duplicate evidence ID detected: "
                f"{current.evidence_id}"
            )

        seen_evidence_ids.add(current.evidence_id)

        if not verify_chain_link(previous, current):
            raise ChainVerificationError(
                "Chain integrity failure at sequence "
                f"{current.sequence} "
                f"({current.evidence_id})"
            )

        previous = current

    return records


def verify_chain_file(chain_path: str | Path) -> bool:
    """
    Return True only when the complete persisted chain is valid.
    """

    verify_persistent_chain(chain_path)
    return True


def main() -> int:
    """
    Command-line entry point.

    Usage:

        python3 -m src.tracee.verify_chain /path/to/chain.jsonl
    """

    import argparse

    parser = argparse.ArgumentParser(
        description="Verify a TRACEE evidence chain."
    )

    parser.add_argument(
        "chain",
        type=Path,
        help="Path to chain.jsonl",
    )

    args = parser.parse_args()

    try:
        records = verify_persistent_chain(args.chain)

    except ChainVerificationError as exc:
        print(f"[ERROR] Chain verification failed: {exc}")
        return 1

    print(
        "[PASS] Evidence chain verified "
        f"({len(records)} record(s))"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
