"""
TRACEE Unified Verification Tests

Tests the V0.1 unified verification engine.

These tests verify:
    - valid complete verification
    - VerificationResult behavior
    - missing metadata
    - missing evidence
    - missing chain
    - evidence-size tampering
    - evidence-hash tampering
    - metadata-to-chain tampering
    - missing chain record
    - invalid metadata
    - malformed chain JSON
    - empty chain
    - duplicate chain records
    - record-hash tampering
    - broken chain links
    - read-only behavior
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tracee.chain import calculate_record_hash
from tracee.ingest import ingest_file
from tracee.verify import (
    VerificationEngine,
    VerificationState,
)


def metadata_path(
    vault_root: Path,
    evidence_id: str,
) -> Path:
    """Return the metadata path for an evidence object."""

    return (
        vault_root
        / "records"
        / f"{evidence_id}.json"
    )


def evidence_path(
    vault_root: Path,
    evidence_id: str,
) -> Path:
    """Return the stored evidence path."""

    return (
        vault_root
        / "objects"
        / evidence_id
        / "evidence.bin"
    )


def chain_path(vault_root: Path) -> Path:
    """Return the persisted chain path."""

    return vault_root / "chain" / "chain.jsonl"


def build_engine(
    vault_root: Path,
    evidence_id: str,
) -> VerificationEngine:
    """Construct a VerificationEngine for one evidence object."""

    return VerificationEngine(
        metadata_path=metadata_path(
            vault_root,
            evidence_id,
        ),
        evidence_path=evidence_path(
            vault_root,
            evidence_id,
        ),
        chain_path=chain_path(vault_root),
    )


def read_chain_records(
    vault_root: Path,
) -> list[dict]:
    """Read chain JSONL into dictionaries."""

    return [
        json.loads(line)
        for line in chain_path(vault_root)
        .read_text(
            encoding="utf-8"
        )
        .splitlines()
        if line.strip()
    ]


def write_chain_records(
    path: Path,
    records: list[dict],
) -> None:
    """Write chain dictionaries as JSONL."""

    path.write_text(
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


def test_valid_evidence_returns_valid_state(
    evidence_file: Path,
    vault_root: Path,
) -> None:
    """A complete untampered evidence object must verify as VALID."""

    metadata, _ = ingest_file(
        evidence_file,
        vault_root,
    )

    result = build_engine(
        vault_root,
        metadata.evidence_id,
    ).verify()

    assert result.state is VerificationState.VALID
    assert result.evidence_id == metadata.evidence_id
    assert result.is_valid() is True


def test_verification_result_is_invalid_for_non_valid_state() -> None:
    """Only VALID results may report is_valid() as True."""

    from tracee.verify import VerificationResult

    result = VerificationResult(
        state=VerificationState.TAMPERED,
        evidence_id="TRACE-EV-000001",
        message="Integrity failure.",
    )

    assert result.is_valid() is False


def test_missing_metadata_returns_missing_state(
    evidence_file: Path,
    vault_root: Path,
) -> None:
    """Missing metadata must produce a MISSING result."""

    metadata, _ = ingest_file(
        evidence_file,
        vault_root,
    )

    metadata_file = metadata_path(
        vault_root,
        metadata.evidence_id,
    )

    metadata_file.unlink()

    result = build_engine(
        vault_root,
        metadata.evidence_id,
    ).verify()

    assert result.state is VerificationState.MISSING


def test_missing_evidence_returns_missing_state(
    evidence_file: Path,
    vault_root: Path,
) -> None:
    """Missing evidence must produce a MISSING result."""

    metadata, _ = ingest_file(
        evidence_file,
        vault_root,
    )

    stored_evidence = evidence_path(
        vault_root,
        metadata.evidence_id,
    )

    stored_evidence.chmod(0o600)
    stored_evidence.unlink()

    result = build_engine(
        vault_root,
        metadata.evidence_id,
    ).verify()

    assert result.state is VerificationState.MISSING


def test_missing_chain_returns_missing_state(
    evidence_file: Path,
    vault_root: Path,
) -> None:
    """Missing chain must produce a MISSING result."""

    metadata, _ = ingest_file(
        evidence_file,
        vault_root,
    )

    chain_file = chain_path(vault_root)

    chain_file.unlink()

    result = build_engine(
        vault_root,
        metadata.evidence_id,
    ).verify()

    assert result.state is VerificationState.MISSING


def test_evidence_size_tampering_returns_tampered(
    evidence_file: Path,
    vault_root: Path,
    test_root: Path,
) -> None:
    """Evidence size modification must return TAMPERED."""

    metadata, _ = ingest_file(
        evidence_file,
        vault_root,
    )

    stored_evidence = evidence_path(
        vault_root,
        metadata.evidence_id,
    )

    tampered_evidence = (
        test_root
        / "tampered-size.bin"
    )

    tampered_evidence.write_bytes(
        stored_evidence.read_bytes()
        + b"tampered"
    )

    result = VerificationEngine(
        metadata_path=metadata_path(
            vault_root,
            metadata.evidence_id,
        ),
        evidence_path=tampered_evidence,
        chain_path=chain_path(vault_root),
    ).verify()

    assert result.state is VerificationState.TAMPERED
    assert "size" in result.message.lower()


def test_evidence_hash_tampering_returns_tampered(
    evidence_file: Path,
    vault_root: Path,
    test_root: Path,
) -> None:
    """Same-size evidence modification must return TAMPERED."""

    metadata, _ = ingest_file(
        evidence_file,
        vault_root,
    )

    original = evidence_path(
        vault_root,
        metadata.evidence_id,
    ).read_bytes()

    modified = bytearray(original)
    modified[0] ^= 0xFF

    tampered_evidence = (
        test_root
        / "tampered-hash.bin"
    )

    tampered_evidence.write_bytes(
        bytes(modified)
    )

    result = VerificationEngine(
        metadata_path=metadata_path(
            vault_root,
            metadata.evidence_id,
        ),
        evidence_path=tampered_evidence,
        chain_path=chain_path(vault_root),
    ).verify()

    assert result.state is VerificationState.TAMPERED
    assert "sha-256" in result.message.lower()


def test_metadata_chain_binding_tampering_returns_tampered(
    evidence_file: Path,
    vault_root: Path,
    test_root: Path,
) -> None:
    """Changing metadata without updating its chain binding must fail."""

    metadata, _ = ingest_file(
        evidence_file,
        vault_root,
    )

    original_metadata = metadata_path(
        vault_root,
        metadata.evidence_id,
    )

    tampered_metadata = (
        test_root
        / "tampered-metadata.json"
    )

    data = json.loads(
        original_metadata.read_text(
            encoding="utf-8"
        )
    )

    data["original_filename"] = "modified.log"

    tampered_metadata.write_text(
        json.dumps(data),
        encoding="utf-8",
    )

    result = VerificationEngine(
        metadata_path=tampered_metadata,
        evidence_path=evidence_path(
            vault_root,
            metadata.evidence_id,
        ),
        chain_path=chain_path(vault_root),
    ).verify()

    assert result.state is VerificationState.TAMPERED
    assert "metadata" in result.message.lower()


def test_missing_chain_record_returns_invalid(
    evidence_file: Path,
    vault_root: Path,
) -> None:
    """An evidence object without a matching chain record is INVALID."""

    metadata, _ = ingest_file(
        evidence_file,
        vault_root,
    )

    chain_file = chain_path(vault_root)

    records = read_chain_records(vault_root)

    chain_file.write_text(
        "",
        encoding="utf-8",
    )

    result = build_engine(
        vault_root,
        metadata.evidence_id,
    ).verify()

    assert result.state is VerificationState.INVALID


def test_invalid_metadata_json_returns_invalid(
    evidence_file: Path,
    vault_root: Path,
    test_root: Path,
) -> None:
    """Malformed metadata JSON must produce INVALID."""

    metadata, _ = ingest_file(
        evidence_file,
        vault_root,
    )

    invalid_metadata = (
        test_root
        / "invalid-metadata.json"
    )

    invalid_metadata.write_text(
        "{invalid-json\n",
        encoding="utf-8",
    )

    result = VerificationEngine(
        metadata_path=invalid_metadata,
        evidence_path=evidence_path(
            vault_root,
            metadata.evidence_id,
        ),
        chain_path=chain_path(vault_root),
    ).verify()

    assert result.state is VerificationState.INVALID


def test_empty_chain_returns_invalid(
    evidence_file: Path,
    vault_root: Path,
) -> None:
    """A chain containing no records must be INVALID."""

    metadata, _ = ingest_file(
        evidence_file,
        vault_root,
    )

    chain_file = chain_path(vault_root)

    chain_file.write_text(
        "",
        encoding="utf-8",
    )

    result = build_engine(
        vault_root,
        metadata.evidence_id,
    ).verify()

    assert result.state is VerificationState.INVALID


def test_duplicate_chain_records_return_invalid(
    evidence_file: Path,
    vault_root: Path,
) -> None:
    """Duplicate records for one evidence ID must be INVALID."""

    metadata, _ = ingest_file(
        evidence_file,
        vault_root,
    )

    records = read_chain_records(vault_root)

    duplicated_chain = chain_path(vault_root)

    duplicated_chain.write_text(
        "\n".join(
            json.dumps(
                record,
                sort_keys=True,
                separators=(",", ":"),
            )
            for record in records + records
        )
        + "\n",
        encoding="utf-8",
    )

    result = build_engine(
        vault_root,
        metadata.evidence_id,
    ).verify()

    assert result.state is VerificationState.INVALID
    assert "multiple" in result.message.lower()


def test_chain_record_hash_tampering_returns_tampered(
    evidence_file: Path,
    vault_root: Path,
) -> None:
    """Changing a persisted chain record hash must be detected."""

    metadata, _ = ingest_file(
        evidence_file,
        vault_root,
    )

    records = read_chain_records(vault_root)

    records[0]["record_hash"] = "0" * 64

    write_chain_records(
        chain_path(vault_root),
        records,
    )

    result = build_engine(
        vault_root,
        metadata.evidence_id,
    ).verify()

    assert result.state is VerificationState.TAMPERED
    assert "record hash" in result.message.lower()


def test_broken_previous_chain_link_returns_tampered(
    evidence_file: Path,
    second_evidence_file: Path,
    vault_root: Path,
    test_root: Path,
) -> None:
    """
    A record with a valid own hash but an invalid previous-record
    relationship must be detected as tampered.
    """

    first_metadata, _ = ingest_file(
        evidence_file,
        vault_root,
    )

    second_metadata, _ = ingest_file(
        second_evidence_file,
        vault_root,
    )

    records = read_chain_records(vault_root)

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

    tampered_chain = (
        test_root
        / "tampered-chain.jsonl"
    )

    write_chain_records(
        tampered_chain,
        records,
    )

    result = VerificationEngine(
        metadata_path=metadata_path(
            vault_root,
            second_metadata.evidence_id,
        ),
        evidence_path=evidence_path(
            vault_root,
            second_metadata.evidence_id,
        ),
        chain_path=tampered_chain,
    ).verify()

    assert result.state is VerificationState.TAMPERED
    assert "chain" in result.message.lower()


def test_verification_is_read_only(
    evidence_file: Path,
    vault_root: Path,
) -> None:
    """Successful verification must not modify persisted artifacts."""

    metadata, _ = ingest_file(
        evidence_file,
        vault_root,
    )

    metadata_file = metadata_path(
        vault_root,
        metadata.evidence_id,
    )

    evidence_file_path = evidence_path(
        vault_root,
        metadata.evidence_id,
    )

    chain_file = chain_path(vault_root)

    metadata_before = metadata_file.read_bytes()
    evidence_before = evidence_file_path.read_bytes()
    chain_before = chain_file.read_bytes()

    result = build_engine(
        vault_root,
        metadata.evidence_id,
    ).verify()

    assert result.state is VerificationState.VALID

    assert metadata_file.read_bytes() == metadata_before
    assert evidence_file_path.read_bytes() == evidence_before
    assert chain_file.read_bytes() == chain_before


def test_two_valid_evidence_objects_verify_independently(
    evidence_file: Path,
    second_evidence_file: Path,
    vault_root: Path,
) -> None:
    """Each evidence object must verify independently within the same chain."""

    first_metadata, _ = ingest_file(
        evidence_file,
        vault_root,
    )

    second_metadata, _ = ingest_file(
        second_evidence_file,
        vault_root,
    )

    first_result = build_engine(
        vault_root,
        first_metadata.evidence_id,
    ).verify()

    second_result = build_engine(
        vault_root,
        second_metadata.evidence_id,
    ).verify()

    assert first_result.state is VerificationState.VALID
    assert second_result.state is VerificationState.VALID

    assert first_result.is_valid() is True
    assert second_result.is_valid() is True
