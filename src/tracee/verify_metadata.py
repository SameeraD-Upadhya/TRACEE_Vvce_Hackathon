"""
TRACEE Metadata Integrity Verification

Verifies that:

1. Metadata JSON is structurally valid.
2. Evidence ID is valid.
3. Metadata SHA-256 matches the actual evidence file.
4. Canonical metadata bytes produce the expected metadata hash.
5. The corresponding chain record contains the same metadata hash.

This module is read-only.
It never modifies evidence, metadata, or chain records.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .canonical import canonicalize
from .hashing import sha256_bytes, sha256_file
from .ids import is_valid_evidence_id
from .models import EvidenceMetadata


class MetadataVerificationError(RuntimeError):
    """Raised when evidence metadata integrity verification fails."""


def load_metadata(path: str | Path) -> EvidenceMetadata:
    """Load and validate a metadata JSON file."""

    metadata_path = Path(path)

    if not metadata_path.is_file():
        raise MetadataVerificationError(
            f"Metadata file does not exist: {metadata_path}"
        )

    try:
        data = json.loads(
            metadata_path.read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError) as exc:
        raise MetadataVerificationError(
            f"Unable to read metadata JSON: {metadata_path}"
        ) from exc

    if not isinstance(data, dict):
        raise MetadataVerificationError(
            "Metadata root must be a JSON object"
        )

    try:
        return EvidenceMetadata(
            schema_version=data["schema_version"],
            evidence_id=data["evidence_id"],
            original_filename=data["original_filename"],
            size_bytes=data["size_bytes"],
            sha256=data["sha256"],
            ingested_at=data["ingested_at"],
            media_type=data["media_type"],
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise MetadataVerificationError(
            f"Invalid metadata structure: {exc}"
        ) from exc


def load_chain_metadata_hash(
    chain_path: str | Path,
    evidence_id: str,
) -> str:
    """Find the metadata hash belonging to an evidence ID."""

    path = Path(chain_path)

    if not path.is_file():
        raise MetadataVerificationError(
            f"Chain file does not exist: {path}"
        )

    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise MetadataVerificationError(
            f"Unable to read chain file: {path}"
        ) from exc

    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue

        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise MetadataVerificationError(
                f"Invalid chain JSON at line {line_number}"
            ) from exc

        if not isinstance(record, dict):
            raise MetadataVerificationError(
                f"Chain record at line {line_number} is not an object"
            )

        if record.get("evidence_id") == evidence_id:
            metadata_hash = record.get("metadata_sha256")

            if not isinstance(metadata_hash, str):
                raise MetadataVerificationError(
                    f"Missing metadata_sha256 for {evidence_id}"
                )

            return metadata_hash

    raise MetadataVerificationError(
        f"No chain record found for evidence ID: {evidence_id}"
    )


def verify_metadata(
    metadata_path: str | Path,
    evidence_path: str | Path,
    chain_path: str | Path,
) -> EvidenceMetadata:
    """
    Verify metadata against the evidence file and chain record.
    """

    metadata = load_metadata(metadata_path)

    if not is_valid_evidence_id(metadata.evidence_id):
        raise MetadataVerificationError(
            f"Invalid evidence ID: {metadata.evidence_id}"
        )

    evidence = Path(evidence_path)

    if not evidence.is_file():
        raise MetadataVerificationError(
            f"Evidence file does not exist: {evidence}"
        )

    # 1. Verify evidence size

    actual_size = evidence.stat().st_size

    if actual_size != metadata.size_bytes:
        raise MetadataVerificationError(
            "Evidence size mismatch: "
            f"metadata={metadata.size_bytes}, "
            f"actual={actual_size}"
        )

    # 2. Verify evidence SHA-256

    actual_evidence_hash = sha256_file(evidence)

    if actual_evidence_hash != metadata.sha256:
        raise MetadataVerificationError(
            "Evidence SHA-256 mismatch: "
            f"metadata={metadata.sha256}, "
            f"actual={actual_evidence_hash}"
        )

    # 3. Calculate canonical metadata hash

    metadata_dict = {
        "schema_version": metadata.schema_version,
        "evidence_id": metadata.evidence_id,
        "original_filename": metadata.original_filename,
        "size_bytes": metadata.size_bytes,
        "sha256": metadata.sha256,
        "ingested_at": metadata.ingested_at,
        "media_type": metadata.media_type,
    }

    canonical_metadata = canonicalize(metadata_dict)

    calculated_metadata_hash = sha256_bytes(
        canonical_metadata
    )

    # 4. Compare metadata hash against chain

    expected_metadata_hash = load_chain_metadata_hash(
        chain_path,
        metadata.evidence_id,
    )

    if calculated_metadata_hash != expected_metadata_hash:
        raise MetadataVerificationError(
            "Metadata SHA-256 mismatch with chain: "
            f"calculated={calculated_metadata_hash}, "
            f"chain={expected_metadata_hash}"
        )

    return metadata


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify TRACEE evidence metadata integrity."
    )

    parser.add_argument(
        "--metadata",
        required=True,
        type=Path,
        help="Evidence metadata JSON file",
    )

    parser.add_argument(
        "--evidence",
        required=True,
        type=Path,
        help="Original evidence file",
    )

    parser.add_argument(
        "--chain",
        required=True,
        type=Path,
        help="TRACEE evidence chain JSONL",
    )

    args = parser.parse_args()

    try:
        metadata = verify_metadata(
            metadata_path=args.metadata,
            evidence_path=args.evidence,
            chain_path=args.chain,
        )

    except MetadataVerificationError as exc:
        print(f"[ERROR] Metadata verification failed: {exc}")
        return 1

    print(
        "[PASS] Metadata verified "
        f"({metadata.evidence_id})"
    )

    print(
        f"[PASS] Evidence SHA-256 verified: "
        f"{metadata.sha256}"
    )

    print(
        "[PASS] Metadata hash matches chain"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
