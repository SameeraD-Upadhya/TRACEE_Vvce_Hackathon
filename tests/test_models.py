"""
TRACEE Data Model Tests

Tests the structured evidence metadata and chain-record contracts
used by the V0.1 integrity foundation.
"""

from __future__ import annotations

import pytest

from src.tracee.models import (
    CHAIN_SCHEMA_VERSION,
    EVIDENCE_SCHEMA_VERSION,
    ChainRecord,
    EvidenceMetadata,
    ModelValidationError,
)


VALID_EVIDENCE_ID = "TRACE-EV-000001"
VALID_SHA256 = "a" * 64
VALID_TIMESTAMP = "2026-10-03T10:00:00Z"


def test_evidence_schema_version() -> None:
    """The evidence schema version must remain defined."""

    assert EVIDENCE_SCHEMA_VERSION == "1.0"


def test_chain_schema_version() -> None:
    """The chain schema version must remain defined."""

    assert CHAIN_SCHEMA_VERSION == "1.0"


def test_valid_evidence_metadata() -> None:
    """A complete valid metadata record must be accepted."""

    metadata = EvidenceMetadata(
        schema_version=EVIDENCE_SCHEMA_VERSION,
        evidence_id=VALID_EVIDENCE_ID,
        original_filename="evidence.log",
        size_bytes=128,
        sha256=VALID_SHA256,
        ingested_at=VALID_TIMESTAMP,
        media_type="text/plain",
    )

    assert metadata.evidence_id == VALID_EVIDENCE_ID
    assert metadata.size_bytes == 128
    assert metadata.sha256 == VALID_SHA256
    assert metadata.media_type == "text/plain"


def test_evidence_metadata_to_dict() -> None:
    """Metadata must serialize to the expected dictionary structure."""

    metadata = EvidenceMetadata(
        schema_version="1.0",
        evidence_id=VALID_EVIDENCE_ID,
        original_filename="evidence.log",
        size_bytes=10,
        sha256=VALID_SHA256,
        ingested_at=VALID_TIMESTAMP,
        media_type="text/plain",
    )

    result = metadata.to_dict()

    assert result == {
        "schema_version": "1.0",
        "evidence_id": VALID_EVIDENCE_ID,
        "original_filename": "evidence.log",
        "size_bytes": 10,
        "sha256": VALID_SHA256,
        "ingested_at": VALID_TIMESTAMP,
        "media_type": "text/plain",
    }


@pytest.mark.parametrize(
    "field",
    [
        "schema_version",
        "original_filename",
        "ingested_at",
        "media_type",
    ],
)
def test_evidence_metadata_rejects_empty_required_strings(
    field: str,
) -> None:
    """Required string fields must not be empty."""

    values = {
        "schema_version": "1.0",
        "evidence_id": VALID_EVIDENCE_ID,
        "original_filename": "evidence.log",
        "size_bytes": 10,
        "sha256": VALID_SHA256,
        "ingested_at": VALID_TIMESTAMP,
        "media_type": "text/plain",
    }

    values[field] = ""

    with pytest.raises(ModelValidationError):
        EvidenceMetadata(**values)


@pytest.mark.parametrize(
    "size_bytes",
    [
        -1,
        -100,
        True,
        False,
    ],
)
def test_evidence_metadata_rejects_invalid_size(
    size_bytes: object,
) -> None:
    """Evidence size must be a non-negative integer."""

    with pytest.raises(ModelValidationError):
        EvidenceMetadata(
            schema_version="1.0",
            evidence_id=VALID_EVIDENCE_ID,
            original_filename="evidence.log",
            size_bytes=size_bytes,
            sha256=VALID_SHA256,
            ingested_at=VALID_TIMESTAMP,
            media_type="text/plain",
        )


@pytest.mark.parametrize(
    "evidence_id",
    [
        "",
        "TRACE-EV-000000",
        "TRACE-EV-ABCDEF",
        "invalid",
    ],
)
def test_evidence_metadata_rejects_invalid_evidence_id(
    evidence_id: str,
) -> None:
    """Metadata must contain a valid TRACEE evidence ID."""

    with pytest.raises(ModelValidationError):
        EvidenceMetadata(
            schema_version="1.0",
            evidence_id=evidence_id,
            original_filename="evidence.log",
            size_bytes=10,
            sha256=VALID_SHA256,
            ingested_at=VALID_TIMESTAMP,
            media_type="text/plain",
        )


@pytest.mark.parametrize(
    "sha256",
    [
        "",
        "abc",
        "A" * 64,
        "g" * 64,
        "0" * 63,
        "0" * 65,
    ],
)
def test_evidence_metadata_rejects_invalid_sha256(
    sha256: str,
) -> None:
    """Metadata must contain a valid lowercase SHA-256 digest."""

    with pytest.raises(ModelValidationError):
        EvidenceMetadata(
            schema_version="1.0",
            evidence_id=VALID_EVIDENCE_ID,
            original_filename="evidence.log",
            size_bytes=10,
            sha256=sha256,
            ingested_at=VALID_TIMESTAMP,
            media_type="text/plain",
        )


def test_valid_genesis_chain_record() -> None:
    """A valid genesis chain record must be accepted."""

    record = ChainRecord(
        schema_version=CHAIN_SCHEMA_VERSION,
        sequence=1,
        evidence_id=VALID_EVIDENCE_ID,
        timestamp=VALID_TIMESTAMP,
        metadata_sha256=VALID_SHA256,
        previous_record_hash="GENESIS",
        record_hash=VALID_SHA256,
    )

    assert record.sequence == 1
    assert record.previous_record_hash == "GENESIS"
    assert record.record_hash == VALID_SHA256


def test_valid_linked_chain_record() -> None:
    """A non-genesis chain record must accept a valid previous hash."""

    record = ChainRecord(
        schema_version=CHAIN_SCHEMA_VERSION,
        sequence=2,
        evidence_id="TRACE-EV-000002",
        timestamp=VALID_TIMESTAMP,
        metadata_sha256=VALID_SHA256,
        previous_record_hash="b" * 64,
        record_hash=VALID_SHA256,
    )

    assert record.sequence == 2
    assert record.previous_record_hash == "b" * 64


def test_chain_record_to_dict() -> None:
    """Chain records must serialize all fields."""

    record = ChainRecord(
        schema_version="1.0",
        sequence=1,
        evidence_id=VALID_EVIDENCE_ID,
        timestamp=VALID_TIMESTAMP,
        metadata_sha256=VALID_SHA256,
        previous_record_hash="GENESIS",
        record_hash=VALID_SHA256,
    )

    result = record.to_dict()

    assert result == {
        "schema_version": "1.0",
        "sequence": 1,
        "evidence_id": VALID_EVIDENCE_ID,
        "timestamp": VALID_TIMESTAMP,
        "metadata_sha256": VALID_SHA256,
        "previous_record_hash": "GENESIS",
        "record_hash": VALID_SHA256,
    }


def test_chain_record_hashable_dict_excludes_record_hash() -> None:
    """record_hash must never be included in its own hash input."""

    record = ChainRecord(
        schema_version="1.0",
        sequence=1,
        evidence_id=VALID_EVIDENCE_ID,
        timestamp=VALID_TIMESTAMP,
        metadata_sha256=VALID_SHA256,
        previous_record_hash="GENESIS",
        record_hash=VALID_SHA256,
    )

    result = record.hashable_dict()

    assert "record_hash" not in result
    assert result == {
        "schema_version": "1.0",
        "sequence": 1,
        "evidence_id": VALID_EVIDENCE_ID,
        "timestamp": VALID_TIMESTAMP,
        "metadata_sha256": VALID_SHA256,
        "previous_record_hash": "GENESIS",
    }


@pytest.mark.parametrize(
    "sequence",
    [
        0,
        -1,
        True,
        False,
    ],
)
def test_chain_record_rejects_invalid_sequence(
    sequence: object,
) -> None:
    """Chain sequence numbers must be positive integers."""

    with pytest.raises(ModelValidationError):
        ChainRecord(
            schema_version="1.0",
            sequence=sequence,
            evidence_id=VALID_EVIDENCE_ID,
            timestamp=VALID_TIMESTAMP,
            metadata_sha256=VALID_SHA256,
            previous_record_hash="GENESIS",
            record_hash=VALID_SHA256,
        )


@pytest.mark.parametrize(
    "previous_record_hash",
    [
        "",
        "abc",
        "A" * 64,
        "g" * 64,
    ],
)
def test_chain_record_rejects_invalid_previous_hash(
    previous_record_hash: str,
) -> None:
    """Previous-record hash must be GENESIS or a valid SHA-256 digest."""

    with pytest.raises(ModelValidationError):
        ChainRecord(
            schema_version="1.0",
            sequence=1,
            evidence_id=VALID_EVIDENCE_ID,
            timestamp=VALID_TIMESTAMP,
            metadata_sha256=VALID_SHA256,
            previous_record_hash=previous_record_hash,
            record_hash=VALID_SHA256,
        )


def test_chain_record_rejects_invalid_record_hash() -> None:
    """record_hash must be a valid SHA-256 digest."""

    with pytest.raises(ModelValidationError):
        ChainRecord(
            schema_version="1.0",
            sequence=1,
            evidence_id=VALID_EVIDENCE_ID,
            timestamp=VALID_TIMESTAMP,
            metadata_sha256=VALID_SHA256,
            previous_record_hash="GENESIS",
            record_hash="invalid",
        )
