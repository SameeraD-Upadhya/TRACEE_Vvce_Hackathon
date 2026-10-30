"""
TRACEE Evidence Ingestion Tests

Tests the V0.1 evidence-ingestion pipeline against an isolated
temporary vault.

These tests verify:
    - source validation
    - evidence hashing
    - metadata creation
    - evidence ID assignment
    - vault storage
    - metadata persistence
    - chain creation
    - duplicate detection
    - multi-evidence sequencing
    - tamper detection
    - fail-closed behavior when the existing chain is corrupted
    - staging cleanup
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tracee.chain import verify_chain
from tracee.errors import (
    ChainError,
    DuplicateEvidenceError,
    IngestionError,
)
from tracee.hashing import sha256_file
from tracee.ingest import detect_media_type, ingest_file, metadata_sha256
from tracee.models import ChainRecord


def load_chain(vault_root: Path) -> list[ChainRecord]:
    """Load persisted chain records from the test vault."""

    chain_path = vault_root / "chain" / "chain.jsonl"

    records: list[ChainRecord] = []

    with chain_path.open(
        "r",
        encoding="utf-8",
    ) as stream:
        for line in stream:
            data = json.loads(line)

            records.append(
                ChainRecord(
                    schema_version=data["schema_version"],
                    sequence=data["sequence"],
                    evidence_id=data["evidence_id"],
                    timestamp=data["timestamp"],
                    metadata_sha256=data["metadata_sha256"],
                    previous_record_hash=data[
                        "previous_record_hash"
                    ],
                    record_hash=data["record_hash"],
                )
            )

    return records


def test_detect_media_type_uses_deterministic_builtin_mapping() -> None:
    """Host MIME databases must not change persisted evidence metadata."""

    assert detect_media_type(Path("evidence.log")) == "application/octet-stream"
    assert detect_media_type(Path("evidence.txt")) == "text/plain"
    assert detect_media_type(Path("evidence.tracee-unknown")) == "application/octet-stream"


def test_ingest_file_creates_evidence_metadata_and_chain(
    evidence_file: Path,
    vault_root: Path,
) -> None:
    """A valid source file should be fully ingested."""

    metadata, record = ingest_file(
        evidence_file,
        vault_root,
    )

    assert metadata.evidence_id == "TRACE-EV-000001"
    assert metadata.original_filename == evidence_file.name
    assert metadata.size_bytes == evidence_file.stat().st_size
    assert metadata.sha256 == sha256_file(evidence_file)
    assert metadata.media_type == "application/octet-stream"
    assert metadata.ingested_at.endswith("Z")

    assert record.sequence == 1
    assert record.evidence_id == "TRACE-EV-000001"
    assert record.previous_record_hash == "GENESIS"

    evidence_path = (
        vault_root
        / "objects"
        / "TRACE-EV-000001"
        / "evidence.bin"
    )

    metadata_path = (
        vault_root
        / "records"
        / "TRACE-EV-000001.json"
    )

    chain_path = (
        vault_root
        / "chain"
        / "chain.jsonl"
    )

    assert evidence_path.is_file()
    assert metadata_path.is_file()
    assert chain_path.is_file()

    assert evidence_path.read_bytes() == evidence_file.read_bytes()


def test_ingest_metadata_record_matches_returned_metadata(
    evidence_file: Path,
    vault_root: Path,
) -> None:
    """Persisted metadata should match the metadata returned by ingestion."""

    metadata, _ = ingest_file(
        evidence_file,
        vault_root,
    )

    metadata_path = (
        vault_root
        / "records"
        / f"{metadata.evidence_id}.json"
    )

    persisted = json.loads(
        metadata_path.read_text(
            encoding="utf-8"
        )
    )

    assert persisted == metadata.to_dict()


def test_ingest_chain_record_is_persisted(
    evidence_file: Path,
    vault_root: Path,
) -> None:
    """The generated chain record should be persisted exactly."""

    _, returned_record = ingest_file(
        evidence_file,
        vault_root,
    )

    records = load_chain(vault_root)

    assert len(records) == 1
    assert records[0] == returned_record
    assert verify_chain(records)


def test_ingest_creates_valid_first_chain_link(
    evidence_file: Path,
    vault_root: Path,
) -> None:
    """The first evidence item must point to GENESIS."""

    _, record = ingest_file(
        evidence_file,
        vault_root,
    )

    assert record.sequence == 1
    assert record.previous_record_hash == "GENESIS"


def test_ingest_assigns_incrementing_evidence_ids(
    evidence_file: Path,
    second_evidence_file: Path,
    vault_root: Path,
) -> None:
    """Distinct evidence files should receive sequential IDs."""

    first_metadata, first_record = ingest_file(
        evidence_file,
        vault_root,
    )

    second_metadata, second_record = ingest_file(
        second_evidence_file,
        vault_root,
    )

    assert first_metadata.evidence_id == "TRACE-EV-000001"
    assert second_metadata.evidence_id == "TRACE-EV-000002"

    assert first_record.sequence == 1
    assert second_record.sequence == 2

    assert (
        second_record.previous_record_hash
        == first_record.record_hash
    )

    records = load_chain(vault_root)

    assert len(records) == 2
    assert verify_chain(records)


def test_ingest_stores_distinct_evidence_objects(
    evidence_file: Path,
    second_evidence_file: Path,
    vault_root: Path,
) -> None:
    """Each ingested source should have its own stored object."""

    first_metadata, _ = ingest_file(
        evidence_file,
        vault_root,
    )

    second_metadata, _ = ingest_file(
        second_evidence_file,
        vault_root,
    )

    first_path = (
        vault_root
        / "objects"
        / first_metadata.evidence_id
        / "evidence.bin"
    )

    second_path = (
        vault_root
        / "objects"
        / second_metadata.evidence_id
        / "evidence.bin"
    )

    assert first_path.is_file()
    assert second_path.is_file()

    assert first_path.read_bytes() == evidence_file.read_bytes()
    assert second_path.read_bytes() == second_evidence_file.read_bytes()

    assert first_path.read_bytes() != second_path.read_bytes()


def test_ingest_rejects_duplicate_evidence(
    evidence_file: Path,
    vault_root: Path,
) -> None:
    """The same evidence bytes must not be ingested twice."""

    first_metadata, _ = ingest_file(
        evidence_file,
        vault_root,
    )

    with pytest.raises(DuplicateEvidenceError) as exc_info:
        ingest_file(
            evidence_file,
            vault_root,
        )

    assert first_metadata.evidence_id == "TRACE-EV-000001"
    assert "TRACE-EV-000001" in str(exc_info.value)

    records = load_chain(vault_root)

    assert len(records) == 1
    assert records[0].evidence_id == "TRACE-EV-000001"
    assert verify_chain(records)


def test_ingest_duplicate_does_not_create_second_object(
    evidence_file: Path,
    vault_root: Path,
) -> None:
    """Duplicate ingestion must not create another vault object."""

    ingest_file(
        evidence_file,
        vault_root,
    )

    with pytest.raises(DuplicateEvidenceError):
        ingest_file(
            evidence_file,
            vault_root,
        )

    object_dirs = [
        path
        for path in (vault_root / "objects").iterdir()
        if path.is_dir()
    ]

    assert object_dirs == [
        vault_root
        / "objects"
        / "TRACE-EV-000001"
    ]


def test_ingest_missing_source_fails(
    vault_root: Path,
    test_root: Path,
) -> None:
    """A missing source file must fail before ingestion."""

    missing_file = test_root / "does-not-exist.log"

    with pytest.raises(IngestionError):
        ingest_file(
            missing_file,
            vault_root,
        )

    assert not vault_root.exists()


def test_ingest_chain_failure_is_fail_closed(
    evidence_file: Path,
    second_evidence_file: Path,
    vault_root: Path,
) -> None:
    """
    Ingestion must refuse to continue when the existing
    evidence chain has been corrupted.
    """

    ingest_file(
        evidence_file,
        vault_root,
    )

    chain_path = (
        vault_root
        / "chain"
        / "chain.jsonl"
    )

    chain_data = json.loads(
        chain_path.read_text(
            encoding="utf-8"
        ).strip()
    )

    chain_data["record_hash"] = "0" * 64

    chain_path.write_text(
        json.dumps(
            chain_data,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ChainError):
        ingest_file(
            second_evidence_file,
            vault_root,
        )


def test_ingest_tampering_changes_evidence_hash(
    evidence_file: Path,
    vault_root: Path,
    test_root: Path,
) -> None:
    """
    A modified copy of stored evidence must have a different
    SHA-256 digest from the original evidence metadata.

    The vault intentionally protects the stored object from
    ordinary writes, so this test does not weaken those permissions.
    """

    metadata, _ = ingest_file(
        evidence_file,
        vault_root,
    )

    evidence_path = (
        vault_root
        / "objects"
        / metadata.evidence_id
        / "evidence.bin"
    )

    tampered_copy = (
        test_root
        / "tampered-evidence.bin"
    )

    tampered_copy.write_bytes(
        evidence_path.read_bytes()
        + b"tampered"
    )

    assert sha256_file(evidence_path) == metadata.sha256
    assert sha256_file(tampered_copy) != metadata.sha256


def test_ingest_leaves_no_staging_directory_after_success(
    evidence_file: Path,
    vault_root: Path,
) -> None:
    """Successful ingestion should not leave staged evidence behind."""

    ingest_file(
        evidence_file,
        vault_root,
    )

    staging_path = vault_root / ".staging"

    if not staging_path.exists():
        return

    assert list(staging_path.iterdir()) == []


def test_ingest_multiple_files_preserves_chain_order(
    evidence_file: Path,
    second_evidence_file: Path,
    vault_root: Path,
) -> None:
    """Multiple evidence objects must preserve chain ordering."""

    first_metadata, first_record = ingest_file(
        evidence_file,
        vault_root,
    )

    second_metadata, second_record = ingest_file(
        second_evidence_file,
        vault_root,
    )

    records = load_chain(vault_root)

    assert [record.sequence for record in records] == [1, 2]

    assert [
        record.evidence_id
        for record in records
    ] == [
        first_metadata.evidence_id,
        second_metadata.evidence_id,
    ]

    assert records[0] == first_record
    assert records[1] == second_record

    assert verify_chain(records)


def test_ingest_preserves_original_filename(
    evidence_file: Path,
    vault_root: Path,
) -> None:
    """Metadata should preserve the original source filename."""

    metadata, _ = ingest_file(
        evidence_file,
        vault_root,
    )

    assert metadata.original_filename == evidence_file.name


def test_ingest_records_correct_evidence_size(
    evidence_file: Path,
    vault_root: Path,
) -> None:
    """Metadata size must match the source file size."""

    metadata, _ = ingest_file(
        evidence_file,
        vault_root,
    )

    assert metadata.size_bytes == evidence_file.stat().st_size


def test_ingest_chain_metadata_hash_matches_metadata(
    evidence_file: Path,
    vault_root: Path,
) -> None:
    """The chain record must bind to the persisted metadata."""

    metadata, record = ingest_file(
        evidence_file,
        vault_root,
    )

    assert record.metadata_sha256 == metadata_sha256(metadata)


def test_ingest_vault_contains_expected_first_evidence(
    evidence_file: Path,
    vault_root: Path,
) -> None:
    """A first successful ingestion should create the expected structure."""

    ingest_file(
        evidence_file,
        vault_root,
    )

    expected_evidence = (
        vault_root
        / "objects"
        / "TRACE-EV-000001"
        / "evidence.bin"
    )

    expected_metadata = (
        vault_root
        / "records"
        / "TRACE-EV-000001.json"
    )

    expected_chain = (
        vault_root
        / "chain"
        / "chain.jsonl"
    )

    assert expected_evidence.is_file()
    assert expected_metadata.is_file()
    assert expected_chain.is_file()


def test_ingest_same_content_different_filename_is_duplicate(
    evidence_file: Path,
    test_root: Path,
    vault_root: Path,
) -> None:
    """
    Duplicate detection is content-based rather than filename-based.
    """

    second_path = test_root / "renamed-evidence.log"

    second_path.write_bytes(
        evidence_file.read_bytes()
    )

    ingest_file(
        evidence_file,
        vault_root,
    )

    with pytest.raises(DuplicateEvidenceError):
        ingest_file(
            second_path,
            vault_root,
        )
