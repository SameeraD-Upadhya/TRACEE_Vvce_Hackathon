"""
TRACEE Unified Verification Engine

Performs read-only verification of:
    1. Evidence file integrity
    2. Evidence metadata integrity
    3. Metadata-to-chain binding
    4. Complete evidence-chain integrity

Verification states:
    VALID
    TAMPERED
    MISSING
    INVALID

This module does not modify evidence, metadata, or chain records.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Optional

from .canonical import canonicalize
from .chain import calculate_record_hash, verify_chain_link
from .hashing import sha256_bytes, sha256_file
from .ids import is_valid_evidence_id
from .models import ChainRecord, EvidenceMetadata


class VerificationState(str, Enum):
    """Final state returned by the verification engine."""

    VALID = "VALID"
    TAMPERED = "TAMPERED"
    MISSING = "MISSING"
    INVALID = "INVALID"


@dataclass(frozen=True)
class VerificationResult:
    """Structured result of one evidence verification operation."""

    state: VerificationState
    evidence_id: str
    message: str

    def is_valid(self) -> bool:
        """Return True only when verification succeeded completely."""

        return self.state is VerificationState.VALID


class VerificationTamperError(Exception):
    """Raised when integrity verification detects tampering."""


class VerificationEngine:
    """
    Read-only verification engine for one TRACEE evidence object.

    Verification relationship:

        evidence
            |
            v
        metadata
            |
            v
        chain record
            |
            v
        previous chain record
    """

    def __init__(
        self,
        metadata_path: Path,
        evidence_path: Path,
        chain_path: Path,
    ) -> None:
        self.metadata_path = metadata_path
        self.evidence_path = evidence_path
        self.chain_path = chain_path

    def verify(self) -> VerificationResult:
        """Perform complete verification."""

        try:
            metadata = self._load_metadata()
            evidence_id = metadata.evidence_id

            if not is_valid_evidence_id(evidence_id):
                return VerificationResult(
                    VerificationState.INVALID,
                    evidence_id,
                    "Invalid evidence ID in metadata.",
                )

            if not self.evidence_path.exists():
                return VerificationResult(
                    VerificationState.MISSING,
                    evidence_id,
                    "Evidence file is missing.",
                )

            if not self.chain_path.exists():
                return VerificationResult(
                    VerificationState.MISSING,
                    evidence_id,
                    "Chain file is missing.",
                )

            self._verify_evidence(metadata)

            records = self._load_chain_records()

            chain_record = self._find_chain_record(
                records,
                evidence_id,
            )

            if chain_record is None:
                return VerificationResult(
                    VerificationState.INVALID,
                    evidence_id,
                    "No matching chain record exists.",
                )

            self._verify_metadata_binding(
                metadata,
                chain_record,
            )

            self._verify_complete_chain(records)

            return VerificationResult(
                VerificationState.VALID,
                evidence_id,
                "Evidence, metadata, and chain verification successful.",
            )

        except VerificationTamperError as exc:
            return VerificationResult(
                VerificationState.TAMPERED,
                self._safe_evidence_id(),
                str(exc),
            )

        except FileNotFoundError as exc:
            return VerificationResult(
                VerificationState.MISSING,
                self._safe_evidence_id(),
                f"Required file is missing: {exc}",
            )

        except (ValueError, TypeError, json.JSONDecodeError) as exc:
            return VerificationResult(
                VerificationState.INVALID,
                self._safe_evidence_id(),
                str(exc),
            )

    def _load_metadata(self) -> EvidenceMetadata:
        """Load and validate the metadata JSON record."""

        if not self.metadata_path.exists():
            raise FileNotFoundError(self.metadata_path)

        try:
            with self.metadata_path.open(
                "r",
                encoding="utf-8",
            ) as handle:
                data = json.load(handle)

        except json.JSONDecodeError as exc:
            raise ValueError(
                f"Metadata JSON is invalid: {exc}"
            ) from exc

        if not isinstance(data, dict):
            raise ValueError(
                "Metadata must contain a JSON object."
            )

        try:
            return EvidenceMetadata(**data)

        except TypeError as exc:
            raise ValueError(
                f"Metadata structure is invalid: {exc}"
            ) from exc

    def _load_chain_records(self) -> list[ChainRecord]:
        """
        Load all chain records from the JSONL chain file.

        The chain file is treated as read-only.
        """

        records: list[ChainRecord] = []

        with self.chain_path.open(
            "r",
            encoding="utf-8",
        ) as handle:

            for line_number, line in enumerate(
                handle,
                start=1,
            ):
                line = line.strip()

                if not line:
                    continue

                try:
                    data = json.loads(line)

                except json.JSONDecodeError as exc:
                    raise ValueError(
                        f"Invalid JSON in chain at line "
                        f"{line_number}: {exc}"
                    ) from exc

                if not isinstance(data, dict):
                    raise ValueError(
                        f"Chain line {line_number} must contain "
                        f"a JSON object."
                    )

                try:
                    record = ChainRecord(**data)

                except TypeError as exc:
                    raise ValueError(
                        f"Invalid chain record at line "
                        f"{line_number}: {exc}"
                    ) from exc

                records.append(record)

        if not records:
            raise ValueError(
                "Chain file contains no records."
            )

        return records

    def _verify_evidence(
        self,
        metadata: EvidenceMetadata,
    ) -> None:
        """Verify evidence size and SHA-256 digest."""

        actual_size = self.evidence_path.stat().st_size

        if actual_size != metadata.size_bytes:
            raise VerificationTamperError(
                "Evidence size does not match metadata."
            )

        actual_hash = sha256_file(
            self.evidence_path
        )

        if actual_hash != metadata.sha256:
            raise VerificationTamperError(
                "Evidence SHA-256 does not match metadata."
            )

    def _find_chain_record(
        self,
        records: list[ChainRecord],
        evidence_id: str,
    ) -> Optional[ChainRecord]:
        """Find the unique chain record belonging to an evidence object."""

        matches = [
            record
            for record in records
            if record.evidence_id == evidence_id
        ]

        if len(matches) == 0:
            return None

        if len(matches) > 1:
            raise ValueError(
                f"Multiple chain records found for {evidence_id}."
            )

        return matches[0]

    def _verify_metadata_binding(
        self,
        metadata: EvidenceMetadata,
        chain_record: ChainRecord,
    ) -> None:
        """Verify that the chain record binds the metadata correctly."""

        metadata_hash = sha256_bytes(
            canonicalize(
                metadata.to_dict()
            )
        )

        if metadata_hash != chain_record.metadata_sha256:
            raise VerificationTamperError(
                "Metadata SHA-256 does not match chain record."
            )

    def _verify_complete_chain(
        self,
        records: list[ChainRecord],
    ) -> None:
        """
        Verify the complete chain.

        The first record must reference GENESIS.

        Every subsequent record must:
            1. Have the expected sequence number.
            2. Have a valid record hash.
            3. Point to the previous record's hash.
        """

        ordered = sorted(
            records,
            key=lambda record: record.sequence,
        )

        for index, record in enumerate(
            ordered
        ):
            expected_sequence = index + 1

            if record.sequence != expected_sequence:
                raise VerificationTamperError(
                    "Chain sequence is invalid."
                )

            expected_record_hash = calculate_record_hash(
                schema_version=record.schema_version,
                sequence=record.sequence,
                evidence_id=record.evidence_id,
                timestamp=record.timestamp,
                metadata_sha256=record.metadata_sha256,
                previous_record_hash=record.previous_record_hash,
            )

            if record.record_hash != expected_record_hash:
                raise VerificationTamperError(
                    f"Chain record hash verification failed at "
                    f"sequence {record.sequence}."
                )

            if index == 0:
                if record.previous_record_hash != "GENESIS":
                    raise VerificationTamperError(
                        "First chain record does not reference GENESIS."
                    )

                continue

            previous_record = ordered[index - 1]

            # verify_chain_link expects:
            #     previous_record, current_record
            if not verify_chain_link(
                previous_record,
                record,
            ):
                raise VerificationTamperError(
                    f"Chain link verification failed at "
                    f"sequence {record.sequence}."
                )

    def _safe_evidence_id(self) -> str:
        """
        Attempt to retrieve the evidence ID for an error result.

        If the metadata is unavailable or malformed, return UNKNOWN.
        """

        try:
            if not self.metadata_path.exists():
                return "UNKNOWN"

            with self.metadata_path.open(
                "r",
                encoding="utf-8",
            ) as handle:
                data = json.load(handle)

            evidence_id = data.get(
                "evidence_id"
            )

            if isinstance(
                evidence_id,
                str,
            ):
                return evidence_id

        except Exception:
            pass

        return "UNKNOWN"


def verify_evidence(
    metadata_path: str | Path,
    evidence_path: str | Path,
    chain_path: str | Path,
) -> VerificationResult:
    """
    Verify one TRACEE evidence object.

    This is the public API for callers that do not need
    to instantiate VerificationEngine directly.
    """

    engine = VerificationEngine(
        metadata_path=Path(metadata_path),
        evidence_path=Path(evidence_path),
        chain_path=Path(chain_path),
    )

    return engine.verify()


def main() -> int:
    """CLI entry point."""

    parser = argparse.ArgumentParser(
        description="Verify a TRACEE evidence object."
    )

    parser.add_argument(
        "--metadata",
        required=True,
        type=Path,
        help="Path to the evidence metadata JSON file.",
    )

    parser.add_argument(
        "--evidence",
        required=True,
        type=Path,
        help="Path to the stored evidence file.",
    )

    parser.add_argument(
        "--chain",
        required=True,
        type=Path,
        help="Path to the evidence chain JSONL file.",
    )

    args = parser.parse_args()

    result = verify_evidence(
        metadata_path=args.metadata,
        evidence_path=args.evidence,
        chain_path=args.chain,
    )

    print(
        f"[{result.state.value}] "
        f"{result.evidence_id}: "
        f"{result.message}"
    )

    return (
        0
        if result.state is VerificationState.VALID
        else 1
    )


if __name__ == "__main__":
    raise SystemExit(main())
