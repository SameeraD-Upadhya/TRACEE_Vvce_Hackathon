"""
TRACEE Evidence Chain

Provides deterministic construction and verification of append-only
evidence-chain records.

This module does not perform filesystem storage or ingestion.
"""

from __future__ import annotations

from typing import Any, Dict

from .canonical import canonicalize
from .errors import ChainError
from .hashing import sha256_bytes, validate_sha256
from .models import CHAIN_SCHEMA_VERSION, ChainRecord


def calculate_record_hash(
    *,
    schema_version: str,
    sequence: int,
    evidence_id: str,
    timestamp: str,
    metadata_sha256: str,
    previous_record_hash: str,
) -> str:
    """
    Calculate the deterministic SHA-256 hash of a chain record.

    record_hash is calculated only from the canonical representation
    of the chain fields that precede it.
    """

    if not schema_version:
        raise ChainError(
            "schema_version must not be empty"
        )

    if (
        not isinstance(sequence, int)
        or isinstance(sequence, bool)
    ):
        raise ChainError(
            "sequence must be an integer"
        )

    if sequence <= 0:
        raise ChainError(
            "sequence must be greater than zero"
        )

    if not evidence_id:
        raise ChainError(
            "evidence_id must not be empty"
        )

    if not timestamp:
        raise ChainError(
            "timestamp must not be empty"
        )

    if not validate_sha256(metadata_sha256):
        raise ChainError(
            "metadata_sha256 must be a valid SHA-256 digest"
        )

    if (
        previous_record_hash != "GENESIS"
        and not validate_sha256(previous_record_hash)
    ):
        raise ChainError(
            "previous_record_hash must be GENESIS "
            "or a valid SHA-256 digest"
        )

    hashable_record: Dict[str, Any] = {
        "schema_version": schema_version,
        "sequence": sequence,
        "evidence_id": evidence_id,
        "timestamp": timestamp,
        "metadata_sha256": metadata_sha256,
        "previous_record_hash": previous_record_hash,
    }

    canonical_bytes = canonicalize(
        hashable_record
    )

    return sha256_bytes(canonical_bytes)


def create_chain_record(
    *,
    sequence: int,
    evidence_id: str,
    timestamp: str,
    metadata_sha256: str,
    previous_record_hash: str = "GENESIS",
    schema_version: str = CHAIN_SCHEMA_VERSION,
) -> ChainRecord:
    """
    Create a new deterministic TRACEE chain record.
    """

    record_hash = calculate_record_hash(
        schema_version=schema_version,
        sequence=sequence,
        evidence_id=evidence_id,
        timestamp=timestamp,
        metadata_sha256=metadata_sha256,
        previous_record_hash=previous_record_hash,
    )

    return ChainRecord(
        schema_version=schema_version,
        sequence=sequence,
        evidence_id=evidence_id,
        timestamp=timestamp,
        metadata_sha256=metadata_sha256,
        previous_record_hash=previous_record_hash,
        record_hash=record_hash,
    )


def verify_chain_record(
    record: ChainRecord,
) -> bool:
    """
    Verify that record_hash matches the deterministic
    contents of the record.
    """

    try:
        expected_hash = calculate_record_hash(
            schema_version=record.schema_version,
            sequence=record.sequence,
            evidence_id=record.evidence_id,
            timestamp=record.timestamp,
            metadata_sha256=record.metadata_sha256,
            previous_record_hash=record.previous_record_hash,
        )
    except ChainError:
        return False

    return expected_hash == record.record_hash


def verify_chain_link(
    previous_record: ChainRecord | None,
    current_record: ChainRecord,
) -> bool:
    """
    Verify the relationship between two consecutive chain records.

    The first record must point to GENESIS.

    Every subsequent record must point to the previous
    record's hash and have the next sequence number.
    """

    if not verify_chain_record(
        current_record
    ):
        return False

    if previous_record is None:
        return (
            current_record.previous_record_hash
            == "GENESIS"
            and current_record.sequence == 1
        )

    if not verify_chain_record(
        previous_record
    ):
        return False

    if (
        current_record.sequence
        != previous_record.sequence + 1
    ):
        return False

    if (
        current_record.previous_record_hash
        != previous_record.record_hash
    ):
        return False

    return True


def append_record(
    records: list[ChainRecord],
    *,
    evidence_id: str,
    timestamp: str,
    metadata_sha256: str,
) -> ChainRecord:
    """
    Build the next chain record from an existing
    in-memory chain.

    This function does not write to disk.
    """

    if records:
        previous = records[-1]

        if not verify_chain_record(
            previous
        ):
            raise ChainError(
                "Cannot append to an invalid existing chain"
            )

        sequence = previous.sequence + 1
        previous_hash = previous.record_hash

    else:
        sequence = 1
        previous_hash = "GENESIS"

    record = create_chain_record(
        sequence=sequence,
        evidence_id=evidence_id,
        timestamp=timestamp,
        metadata_sha256=metadata_sha256,
        previous_record_hash=previous_hash,
    )

    if not verify_chain_link(
        records[-1] if records else None,
        record,
    ):
        raise ChainError(
            "New chain record failed link verification"
        )

    records.append(record)

    return record


def verify_chain(
    records: list[ChainRecord],
) -> bool:
    """
    Verify an entire in-memory chain.

    Returns False if any record, sequence number,
    or hash link is invalid.
    """

    previous: ChainRecord | None = None

    for record in records:
        if not verify_chain_link(
            previous,
            record,
        ):
            return False

        previous = record

    return True
