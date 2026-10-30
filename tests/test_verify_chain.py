"""
TRACEE Persistent Evidence-Chain Verification Tests

Tests the V0.1 persisted chain verification layer.

These tests verify:
    - valid chain loading
    - valid persistent chain verification
    - missing chain files
    - empty chain files
    - blank records
    - malformed JSON
    - non-object JSON records
    - invalid ChainRecord data
    - sequence discontinuity
    - duplicate evidence IDs
    - record-hash tampering
    - previous-record link tampering
    - verify_chain_file success behavior
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tracee.chain import calculate_record_hash
from tracee.ingest import ingest_file
from tracee.verify_chain import (
    ChainVerificationError,
    load_chain,
    verify_chain_file,
    verify_persistent_chain,
)


def chain_path(vault_root: Path) -> Path:
    """Return the persisted chain path for a test vault."""

    return vault_root / "chain" / "chain.jsonl"


def read_chain_json(vault_root: Path) -> list[dict]:
    """Read persisted chain records as dictionaries."""

    path = chain_path(vault_root)

    return [
        json.loads(line)
        for line in path.read_text(
            encoding="utf-8"
        ).splitlines()
        if line.strip()
    ]


def write_chain_json(
    vault_root: Path,
    records: list[dict],
) -> None:
    """Write chain dictionaries using the normal JSONL structure."""

    chain_path(vault_root).write_text(
        "".join(
            json.dumps(
                record,
                sort_keys=True,
                ensure_ascii=False,
                separators=(",", ":"),
            )
            + "\n"
            for record in records
        ),
        encoding="utf-8",
    )


def test_load_chain_returns_valid_records(
    evidence_file: Path,
    vault_root: Path,
) -> None:
    """A valid persisted chain should load into ChainRecord objects."""

    _, returned_record = ingest_file(
        evidence_file,
        vault_root,
    )

    records = load_chain(
        chain_path(vault_root)
    )

    assert len(records) == 1
    assert records[0] == returned_record


def test_verify_persistent_chain_accepts_valid_chain(
    evidence_file: Path,
    second_evidence_file: Path,
    vault_root: Path,
) -> None:
    """A valid multi-record chain must pass verification."""

    ingest_file(
        evidence_file,
        vault_root,
    )

    ingest_file(
        second_evidence_file,
        vault_root,
    )

    records = verify_persistent_chain(
        chain_path(vault_root)
    )

    assert len(records) == 2
    assert records[0].sequence == 1
    assert records[1].sequence == 2
    assert (
        records[0].previous_record_hash
        == "GENESIS"
    )
    assert (
        records[1].previous_record_hash
        == records[0].record_hash
    )


def test_verify_chain_file_returns_true_for_valid_chain(
    evidence_file: Path,
    vault_root: Path,
) -> None:
    """verify_chain_file must return True for a valid chain."""

    ingest_file(
        evidence_file,
        vault_root,
    )

    assert verify_chain_file(
        chain_path(vault_root)
    ) is True


def test_load_chain_rejects_missing_file(
    vault_root: Path,
) -> None:
    """A missing chain file must fail verification."""

    missing_path = vault_root / "chain" / "chain.jsonl"

    with pytest.raises(ChainVerificationError) as exc_info:
        load_chain(missing_path)

    assert "does not exist" in str(exc_info.value)


def test_load_chain_rejects_empty_file(
    vault_root: Path,
) -> None:
    """An empty chain file must be rejected."""

    path = vault_root / "chain" / "chain.jsonl"
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )
    path.touch()

    with pytest.raises(ChainVerificationError) as exc_info:
        load_chain(path)

    assert "contains no records" in str(exc_info.value)


def test_load_chain_rejects_blank_record(
    vault_root: Path,
) -> None:
    """Blank chain lines are invalid."""

    path = vault_root / "chain" / "chain.jsonl"
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )
    path.write_text(
        "\n",
        encoding="utf-8",
    )

    with pytest.raises(ChainVerificationError) as exc_info:
        load_chain(path)

    assert "Blank chain record" in str(exc_info.value)


def test_load_chain_rejects_invalid_json(
    vault_root: Path,
) -> None:
    """Malformed JSON must be rejected."""

    path = vault_root / "chain" / "chain.jsonl"
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )
    path.write_text(
        "{invalid-json\n",
        encoding="utf-8",
    )

    with pytest.raises(ChainVerificationError) as exc_info:
        load_chain(path)

    assert "Invalid JSON" in str(exc_info.value)


def test_load_chain_rejects_non_object_json(
    vault_root: Path,
) -> None:
    """A JSON value other than an object must be rejected."""

    path = vault_root / "chain" / "chain.jsonl"
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )
    path.write_text(
        json.dumps(["not", "a", "record"]) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ChainVerificationError) as exc_info:
        load_chain(path)

    assert "is not a JSON object" in str(exc_info.value)


def test_load_chain_rejects_invalid_record_schema(
    evidence_file: Path,
    vault_root: Path,
) -> None:
    """A structurally invalid ChainRecord must be rejected."""

    ingest_file(
        evidence_file,
        vault_root,
    )

    records = read_chain_json(vault_root)

    del records[0]["metadata_sha256"]

    write_chain_json(
        vault_root,
        records,
    )

    with pytest.raises(ChainVerificationError) as exc_info:
        load_chain(chain_path(vault_root))

    assert "Invalid chain record" in str(exc_info.value)


def test_verify_persistent_chain_rejects_sequence_discontinuity(
    evidence_file: Path,
    vault_root: Path,
) -> None:
    """The first record must have sequence number 1."""

    ingest_file(
        evidence_file,
        vault_root,
    )

    records = read_chain_json(vault_root)
    records[0]["sequence"] = 2

    write_chain_json(
        vault_root,
        records,
    )

    with pytest.raises(ChainVerificationError) as exc_info:
        verify_persistent_chain(
            chain_path(vault_root)
        )

    assert "Sequence discontinuity detected" in str(
        exc_info.value
    )


def test_verify_persistent_chain_rejects_duplicate_evidence_id(
    evidence_file: Path,
    second_evidence_file: Path,
    vault_root: Path,
) -> None:
    """
    Evidence IDs must be unique even when the chain records
    themselves are otherwise structurally valid.
    """

    ingest_file(
        evidence_file,
        vault_root,
    )

    ingest_file(
        second_evidence_file,
        vault_root,
    )

    records = read_chain_json(vault_root)

    records[1]["evidence_id"] = records[0]["evidence_id"]

    write_chain_json(
        vault_root,
        records,
    )

    with pytest.raises(ChainVerificationError) as exc_info:
        verify_persistent_chain(
            chain_path(vault_root)
        )

    assert "Duplicate evidence ID detected" in str(
        exc_info.value
    )


def test_verify_persistent_chain_rejects_record_hash_tampering(
    evidence_file: Path,
    vault_root: Path,
) -> None:
    """Changing record_hash must invalidate the chain."""

    ingest_file(
        evidence_file,
        vault_root,
    )

    records = read_chain_json(vault_root)

    records[0]["record_hash"] = "0" * 64

    write_chain_json(
        vault_root,
        records,
    )

    with pytest.raises(ChainVerificationError) as exc_info:
        verify_persistent_chain(
            chain_path(vault_root)
        )

    assert "Chain integrity failure" in str(
        exc_info.value
    )


def test_verify_persistent_chain_rejects_broken_previous_link(
    evidence_file: Path,
    second_evidence_file: Path,
    vault_root: Path,
) -> None:
    """
    A record whose own hash is valid but whose previous-record
    reference is wrong must fail link verification.
    """

    ingest_file(
        evidence_file,
        vault_root,
    )

    ingest_file(
        second_evidence_file,
        vault_root,
    )

    records = read_chain_json(vault_root)

    records[1]["previous_record_hash"] = "1" * 64

    records[1]["record_hash"] = calculate_record_hash(
        schema_version=records[1]["schema_version"],
        sequence=records[1]["sequence"],
        evidence_id=records[1]["evidence_id"],
        timestamp=records[1]["timestamp"],
        metadata_sha256=records[1]["metadata_sha256"],
        previous_record_hash=records[1][
            "previous_record_hash"
        ],
    )

    write_chain_json(
        vault_root,
        records,
    )

    with pytest.raises(ChainVerificationError) as exc_info:
        verify_persistent_chain(
            chain_path(vault_root)
        )

    assert "Chain integrity failure" in str(
        exc_info.value
    )


def test_verify_persistent_chain_rejects_genesis_tampering(
    evidence_file: Path,
    vault_root: Path,
) -> None:
    """The first record must always point to GENESIS."""

    ingest_file(
        evidence_file,
        vault_root,
    )

    records = read_chain_json(vault_root)

    records[0]["previous_record_hash"] = "1" * 64

    records[0]["record_hash"] = calculate_record_hash(
        schema_version=records[0]["schema_version"],
        sequence=records[0]["sequence"],
        evidence_id=records[0]["evidence_id"],
        timestamp=records[0]["timestamp"],
        metadata_sha256=records[0]["metadata_sha256"],
        previous_record_hash=records[0][
            "previous_record_hash"
        ],
    )

    write_chain_json(
        vault_root,
        records,
    )

    with pytest.raises(ChainVerificationError) as exc_info:
        verify_persistent_chain(
            chain_path(vault_root)
        )

    assert "Chain integrity failure" in str(
        exc_info.value
    )


def test_verify_persistent_chain_is_read_only(
    evidence_file: Path,
    vault_root: Path,
) -> None:
    """Verification must not modify the persisted chain."""

    ingest_file(
        evidence_file,
        vault_root,
    )

    path = chain_path(vault_root)
    before = path.read_bytes()

    verify_persistent_chain(path)

    after = path.read_bytes()

    assert after == before


def test_verify_persistent_chain_returns_records_in_stored_order(
    evidence_file: Path,
    second_evidence_file: Path,
    vault_root: Path,
) -> None:
    """Verified records should preserve chain order."""

    ingest_file(
        evidence_file,
        vault_root,
    )

    ingest_file(
        second_evidence_file,
        vault_root,
    )

    records = verify_persistent_chain(
        chain_path(vault_root)
    )

    assert [
        record.sequence
        for record in records
    ] == [1, 2]

    assert [
        record.evidence_id
        for record in records
    ] == [
        "TRACE-EV-000001",
        "TRACE-EV-000002",
    ]
