"""
TRACEE Evidence Chain Tests

Tests deterministic construction, validation, linking, appending,
and verification of the V0.1 evidence chain.

These tests operate entirely in memory and do not modify the
repository vault or runtime evidence directories.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from src.tracee.chain import (
    append_record,
    calculate_record_hash,
    create_chain_record,
    verify_chain,
    verify_chain_link,
    verify_chain_record,
)
from src.tracee.errors import ChainError


VALID_DIGEST = "a" * 64
SECOND_DIGEST = "b" * 64
THIRD_DIGEST = "c" * 64

EVIDENCE_ID_1 = "TRACE-EV-000001"
EVIDENCE_ID_2 = "TRACE-EV-000002"
EVIDENCE_ID_3 = "TRACE-EV-000003"

TIMESTAMP_1 = "2026-10-05T10:00:00+00:00"
TIMESTAMP_2 = "2026-10-05T10:01:00+00:00"
TIMESTAMP_3 = "2026-10-05T10:02:00+00:00"


def test_calculate_record_hash_is_deterministic() -> None:
    """Identical inputs must produce the same record hash."""

    first = calculate_record_hash(
        schema_version="1.0",
        sequence=1,
        evidence_id=EVIDENCE_ID_1,
        timestamp=TIMESTAMP_1,
        metadata_sha256=VALID_DIGEST,
        previous_record_hash="GENESIS",
    )

    second = calculate_record_hash(
        schema_version="1.0",
        sequence=1,
        evidence_id=EVIDENCE_ID_1,
        timestamp=TIMESTAMP_1,
        metadata_sha256=VALID_DIGEST,
        previous_record_hash="GENESIS",
    )

    assert first == second
    assert len(first) == 64


def test_calculate_record_hash_changes_with_metadata() -> None:
    """Changing metadata must change the record hash."""

    first = calculate_record_hash(
        schema_version="1.0",
        sequence=1,
        evidence_id=EVIDENCE_ID_1,
        timestamp=TIMESTAMP_1,
        metadata_sha256=VALID_DIGEST,
        previous_record_hash="GENESIS",
    )

    second = calculate_record_hash(
        schema_version="1.0",
        sequence=1,
        evidence_id=EVIDENCE_ID_1,
        timestamp=TIMESTAMP_1,
        metadata_sha256=SECOND_DIGEST,
        previous_record_hash="GENESIS",
    )

    assert first != second


def test_calculate_record_hash_changes_with_timestamp() -> None:
    """Changing timestamp must change the record hash."""

    first = calculate_record_hash(
        schema_version="1.0",
        sequence=1,
        evidence_id=EVIDENCE_ID_1,
        timestamp=TIMESTAMP_1,
        metadata_sha256=VALID_DIGEST,
        previous_record_hash="GENESIS",
    )

    second = calculate_record_hash(
        schema_version="1.0",
        sequence=1,
        evidence_id=EVIDENCE_ID_1,
        timestamp=TIMESTAMP_2,
        metadata_sha256=VALID_DIGEST,
        previous_record_hash="GENESIS",
    )

    assert first != second


def test_calculate_record_hash_changes_with_previous_hash() -> None:
    """Changing previous_record_hash must change the record hash."""

    first = calculate_record_hash(
        schema_version="1.0",
        sequence=2,
        evidence_id=EVIDENCE_ID_2,
        timestamp=TIMESTAMP_2,
        metadata_sha256=VALID_DIGEST,
        previous_record_hash=SECOND_DIGEST,
    )

    second = calculate_record_hash(
        schema_version="1.0",
        sequence=2,
        evidence_id=EVIDENCE_ID_2,
        timestamp=TIMESTAMP_2,
        metadata_sha256=VALID_DIGEST,
        previous_record_hash=THIRD_DIGEST,
    )

    assert first != second


def test_create_chain_record_creates_genesis_record() -> None:
    """The first record must use sequence one and GENESIS."""

    record = create_chain_record(
        sequence=1,
        evidence_id=EVIDENCE_ID_1,
        timestamp=TIMESTAMP_1,
        metadata_sha256=VALID_DIGEST,
    )

    assert record.sequence == 1
    assert record.evidence_id == EVIDENCE_ID_1
    assert record.previous_record_hash == "GENESIS"
    assert verify_chain_record(record) is True


def test_create_chain_record_accepts_previous_hash() -> None:
    """A subsequent record must retain its supplied previous hash."""

    record = create_chain_record(
        sequence=2,
        evidence_id=EVIDENCE_ID_2,
        timestamp=TIMESTAMP_2,
        metadata_sha256=SECOND_DIGEST,
        previous_record_hash=VALID_DIGEST,
    )

    assert record.sequence == 2
    assert record.previous_record_hash == VALID_DIGEST
    assert verify_chain_record(record) is True


def test_verify_chain_record_accepts_valid_record() -> None:
    """A valid record must pass deterministic hash verification."""

    record = create_chain_record(
        sequence=1,
        evidence_id=EVIDENCE_ID_1,
        timestamp=TIMESTAMP_1,
        metadata_sha256=VALID_DIGEST,
    )

    assert verify_chain_record(record) is True


def test_verify_chain_record_rejects_tampered_record_hash() -> None:
    """Changing record_hash without recalculation must fail."""

    record = create_chain_record(
        sequence=1,
        evidence_id=EVIDENCE_ID_1,
        timestamp=TIMESTAMP_1,
        metadata_sha256=VALID_DIGEST,
    )

    tampered = replace(
        record,
        record_hash=SECOND_DIGEST,
    )

    assert verify_chain_record(tampered) is False


def test_verify_chain_record_rejects_modified_sequence() -> None:
    """Changing sequence without recalculating the hash must fail."""

    record = create_chain_record(
        sequence=1,
        evidence_id=EVIDENCE_ID_1,
        timestamp=TIMESTAMP_1,
        metadata_sha256=VALID_DIGEST,
    )

    tampered = replace(
        record,
        sequence=2,
    )

    assert verify_chain_record(tampered) is False


def test_verify_chain_record_rejects_modified_evidence_id() -> None:
    """Changing evidence_id without recalculation must fail."""

    record = create_chain_record(
        sequence=1,
        evidence_id=EVIDENCE_ID_1,
        timestamp=TIMESTAMP_1,
        metadata_sha256=VALID_DIGEST,
    )

    tampered = replace(
        record,
        evidence_id=EVIDENCE_ID_2,
    )

    assert verify_chain_record(tampered) is False


def test_verify_chain_record_rejects_modified_metadata_hash() -> None:
    """Changing metadata_sha256 without recalculation must fail."""

    record = create_chain_record(
        sequence=1,
        evidence_id=EVIDENCE_ID_1,
        timestamp=TIMESTAMP_1,
        metadata_sha256=VALID_DIGEST,
    )

    tampered = replace(
        record,
        metadata_sha256=SECOND_DIGEST,
    )

    assert verify_chain_record(tampered) is False


def test_verify_chain_link_accepts_genesis() -> None:
    """A valid first record must satisfy the genesis rules."""

    record = create_chain_record(
        sequence=1,
        evidence_id=EVIDENCE_ID_1,
        timestamp=TIMESTAMP_1,
        metadata_sha256=VALID_DIGEST,
    )

    assert verify_chain_link(None, record) is True


def test_verify_chain_link_rejects_wrong_genesis_sequence() -> None:
    """The first record must always have sequence one."""

    record = create_chain_record(
        sequence=2,
        evidence_id=EVIDENCE_ID_1,
        timestamp=TIMESTAMP_1,
        metadata_sha256=VALID_DIGEST,
        previous_record_hash=VALID_DIGEST,
    )

    assert verify_chain_link(None, record) is False


def test_verify_chain_link_accepts_consecutive_records() -> None:
    """Correctly linked consecutive records must verify."""

    first = create_chain_record(
        sequence=1,
        evidence_id=EVIDENCE_ID_1,
        timestamp=TIMESTAMP_1,
        metadata_sha256=VALID_DIGEST,
    )

    second = create_chain_record(
        sequence=2,
        evidence_id=EVIDENCE_ID_2,
        timestamp=TIMESTAMP_2,
        metadata_sha256=SECOND_DIGEST,
        previous_record_hash=first.record_hash,
    )

    assert verify_chain_link(first, second) is True


def test_verify_chain_link_rejects_wrong_sequence() -> None:
    """The current sequence must be previous sequence plus one."""

    first = create_chain_record(
        sequence=1,
        evidence_id=EVIDENCE_ID_1,
        timestamp=TIMESTAMP_1,
        metadata_sha256=VALID_DIGEST,
    )

    second = create_chain_record(
        sequence=3,
        evidence_id=EVIDENCE_ID_2,
        timestamp=TIMESTAMP_2,
        metadata_sha256=SECOND_DIGEST,
        previous_record_hash=first.record_hash,
    )

    assert verify_chain_link(first, second) is False


def test_verify_chain_link_rejects_wrong_previous_hash() -> None:
    """A record referencing the wrong predecessor must fail."""

    first = create_chain_record(
        sequence=1,
        evidence_id=EVIDENCE_ID_1,
        timestamp=TIMESTAMP_1,
        metadata_sha256=VALID_DIGEST,
    )

    second = create_chain_record(
        sequence=2,
        evidence_id=EVIDENCE_ID_2,
        timestamp=TIMESTAMP_2,
        metadata_sha256=SECOND_DIGEST,
        previous_record_hash=THIRD_DIGEST,
    )

    assert verify_chain_link(first, second) is False


def test_verify_chain_rejects_tampered_record() -> None:
    """One tampered record must invalidate the complete chain."""

    first = create_chain_record(
        sequence=1,
        evidence_id=EVIDENCE_ID_1,
        timestamp=TIMESTAMP_1,
        metadata_sha256=VALID_DIGEST,
    )

    second = create_chain_record(
        sequence=2,
        evidence_id=EVIDENCE_ID_2,
        timestamp=TIMESTAMP_2,
        metadata_sha256=SECOND_DIGEST,
        previous_record_hash=first.record_hash,
    )

    tampered_second = replace(
        second,
        record_hash=THIRD_DIGEST,
    )

    assert verify_chain(
        [first, tampered_second],
    ) is False


def test_verify_chain_accepts_valid_chain() -> None:
    """A correctly linked multi-record chain must verify."""

    first = create_chain_record(
        sequence=1,
        evidence_id=EVIDENCE_ID_1,
        timestamp=TIMESTAMP_1,
        metadata_sha256=VALID_DIGEST,
    )

    second = create_chain_record(
        sequence=2,
        evidence_id=EVIDENCE_ID_2,
        timestamp=TIMESTAMP_2,
        metadata_sha256=SECOND_DIGEST,
        previous_record_hash=first.record_hash,
    )

    third = create_chain_record(
        sequence=3,
        evidence_id=EVIDENCE_ID_3,
        timestamp=TIMESTAMP_3,
        metadata_sha256=THIRD_DIGEST,
        previous_record_hash=second.record_hash,
    )

    assert verify_chain(
        [first, second, third],
    ) is True


def test_verify_chain_accepts_empty_chain() -> None:
    """An empty in-memory chain contains no invalid records."""

    assert verify_chain([]) is True


def test_append_record_creates_first_record() -> None:
    """Appending to an empty list creates the genesis record."""

    records = []

    record = append_record(
        records,
        evidence_id=EVIDENCE_ID_1,
        timestamp=TIMESTAMP_1,
        metadata_sha256=VALID_DIGEST,
    )

    assert len(records) == 1
    assert records[0] == record
    assert record.sequence == 1
    assert record.previous_record_hash == "GENESIS"
    assert verify_chain(records) is True


def test_append_record_creates_linked_records() -> None:
    """Appending records maintains sequence and hash linkage."""

    records = []

    first = append_record(
        records,
        evidence_id=EVIDENCE_ID_1,
        timestamp=TIMESTAMP_1,
        metadata_sha256=VALID_DIGEST,
    )

    second = append_record(
        records,
        evidence_id=EVIDENCE_ID_2,
        timestamp=TIMESTAMP_2,
        metadata_sha256=SECOND_DIGEST,
    )

    assert first.sequence == 1
    assert second.sequence == 2
    assert second.previous_record_hash == first.record_hash
    assert verify_chain(records) is True


def test_append_record_rejects_invalid_existing_chain() -> None:
    """Appending to an invalid existing chain must fail."""

    first = create_chain_record(
        sequence=1,
        evidence_id=EVIDENCE_ID_1,
        timestamp=TIMESTAMP_1,
        metadata_sha256=VALID_DIGEST,
    )

    tampered = replace(
        first,
        record_hash=SECOND_DIGEST,
    )

    records = [tampered]

    with pytest.raises(ChainError):
        append_record(
            records,
            evidence_id=EVIDENCE_ID_2,
            timestamp=TIMESTAMP_2,
            metadata_sha256=SECOND_DIGEST,
        )


def test_calculate_record_hash_rejects_non_integer_sequence() -> None:
    """Sequence must be an integer and bool must not be accepted."""

    with pytest.raises(ChainError):
        calculate_record_hash(
            schema_version="1.0",
            sequence="1",  # type: ignore[arg-type]
            evidence_id=EVIDENCE_ID_1,
            timestamp=TIMESTAMP_1,
            metadata_sha256=VALID_DIGEST,
            previous_record_hash="GENESIS",
        )

    with pytest.raises(ChainError):
        calculate_record_hash(
            schema_version="1.0",
            sequence=True,  # type: ignore[arg-type]
            evidence_id=EVIDENCE_ID_1,
            timestamp=TIMESTAMP_1,
            metadata_sha256=VALID_DIGEST,
            previous_record_hash="GENESIS",
        )


def test_calculate_record_hash_rejects_non_positive_sequence() -> None:
    """Sequence zero and negative values must be rejected."""

    with pytest.raises(ChainError):
        calculate_record_hash(
            schema_version="1.0",
            sequence=0,
            evidence_id=EVIDENCE_ID_1,
            timestamp=TIMESTAMP_1,
            metadata_sha256=VALID_DIGEST,
            previous_record_hash="GENESIS",
        )

    with pytest.raises(ChainError):
        calculate_record_hash(
            schema_version="1.0",
            sequence=-1,
            evidence_id=EVIDENCE_ID_1,
            timestamp=TIMESTAMP_1,
            metadata_sha256=VALID_DIGEST,
            previous_record_hash="GENESIS",
        )


def test_calculate_record_hash_rejects_invalid_metadata_digest() -> None:
    """Metadata digest must be a valid SHA-256 digest."""

    with pytest.raises(ChainError):
        calculate_record_hash(
            schema_version="1.0",
            sequence=1,
            evidence_id=EVIDENCE_ID_1,
            timestamp=TIMESTAMP_1,
            metadata_sha256="invalid",
            previous_record_hash="GENESIS",
        )


def test_calculate_record_hash_rejects_invalid_previous_hash() -> None:
    """Previous hash must be GENESIS or a valid SHA-256 digest."""

    with pytest.raises(ChainError):
        calculate_record_hash(
            schema_version="1.0",
            sequence=2,
            evidence_id=EVIDENCE_ID_2,
            timestamp=TIMESTAMP_2,
            metadata_sha256=VALID_DIGEST,
            previous_record_hash="invalid",
        )
