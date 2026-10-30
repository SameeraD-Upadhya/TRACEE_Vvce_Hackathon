"""
TRACEE Metadata Integrity Verification Tests

Tests the V0.1 metadata verification layer.

These tests verify:
    - valid metadata verification
    - metadata loading
    - invalid metadata structure
    - missing metadata files
    - missing evidence files
    - evidence size tampering
    - evidence SHA-256 tampering
    - canonical metadata hash verification
    - chain metadata binding
    - missing chain files
    - malformed chain records
    - missing chain records
    - read-only verification behavior
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tracee.verify_metadata import (
    MetadataVerificationError,
    load_chain_metadata_hash,
    load_metadata,
    verify_metadata,
)


def metadata_path(
    vault_root: Path,
    evidence_id: str,
) -> Path:
    """Return the persisted metadata path for an evidence object."""

    return (
        vault_root
        / "records"
        / f"{evidence_id}.json"
    )


def evidence_path(
    vault_root: Path,
    evidence_id: str,
) -> Path:
    """Return the persisted evidence path for an evidence object."""

    return (
        vault_root
        / "objects"
        / evidence_id
        / "evidence.bin"
    )


def chain_path(vault_root: Path) -> Path:
    """Return the persisted evidence-chain path."""

    return vault_root / "chain" / "chain.jsonl"


def read_chain_records(
    vault_root: Path,
) -> list[dict]:
    """Read persisted chain records as dictionaries."""

    return [
        json.loads(line)
        for line in chain_path(vault_root)
        .read_text(encoding="utf-8")
        .splitlines()
        if line.strip()
    ]


def write_chain_records(
    path: Path,
    records: list[dict],
) -> None:
    """Write chain records as JSONL."""

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


def test_load_metadata_returns_valid_metadata(
    evidence_file: Path,
    vault_root: Path,
) -> None:
    """A valid metadata file should load successfully."""

    from tracee.ingest import ingest_file

    metadata, _ = ingest_file(
        evidence_file,
        vault_root,
    )

    loaded = load_metadata(
        metadata_path(
            vault_root,
            metadata.evidence_id,
        )
    )

    assert loaded == metadata


def test_verify_metadata_accepts_valid_record(
    evidence_file: Path,
    vault_root: Path,
) -> None:
    """A complete valid evidence/metadata/chain set must verify."""

    from tracee.ingest import ingest_file

    metadata, _ = ingest_file(
        evidence_file,
        vault_root,
    )

    verified = verify_metadata(
        metadata_path(
            vault_root,
            metadata.evidence_id,
        ),
        evidence_path(
            vault_root,
            metadata.evidence_id,
        ),
        chain_path(vault_root),
    )

    assert verified == metadata


def test_load_chain_metadata_hash_returns_expected_hash(
    evidence_file: Path,
    vault_root: Path,
) -> None:
    """The chain lookup should return the metadata binding hash."""

    from tracee.ingest import ingest_file

    metadata, record = ingest_file(
        evidence_file,
        vault_root,
    )

    result = load_chain_metadata_hash(
        chain_path(vault_root),
        metadata.evidence_id,
    )

    assert result == record.metadata_sha256


def test_load_metadata_rejects_missing_file(
    test_root: Path,
) -> None:
    """A missing metadata file must fail."""

    missing_path = (
        test_root
        / "missing-metadata.json"
    )

    with pytest.raises(MetadataVerificationError) as exc_info:
        load_metadata(missing_path)

    assert "does not exist" in str(exc_info.value)


def test_load_metadata_rejects_invalid_json(
    test_root: Path,
) -> None:
    """Malformed metadata JSON must fail."""

    path = test_root / "invalid-metadata.json"

    path.write_text(
        "{invalid-json\n",
        encoding="utf-8",
    )

    with pytest.raises(MetadataVerificationError) as exc_info:
        load_metadata(path)

    assert "Unable to read metadata JSON" in str(
        exc_info.value
    )


def test_load_metadata_rejects_non_object_root(
    test_root: Path,
) -> None:
    """Metadata JSON must contain an object at the root."""

    path = test_root / "metadata-array.json"

    path.write_text(
        json.dumps(["invalid", "metadata"]),
        encoding="utf-8",
    )

    with pytest.raises(MetadataVerificationError) as exc_info:
        load_metadata(path)

    assert "must be a JSON object" in str(
        exc_info.value
    )


def test_load_metadata_rejects_invalid_structure(
    evidence_file: Path,
    vault_root: Path,
    test_root: Path,
) -> None:
    """Missing required metadata fields must fail validation."""

    from tracee.ingest import ingest_file

    metadata, _ = ingest_file(
        evidence_file,
        vault_root,
    )

    source_path = metadata_path(
        vault_root,
        metadata.evidence_id,
    )

    broken_path = (
        test_root
        / "broken-metadata.json"
    )

    data = json.loads(
        source_path.read_text(
            encoding="utf-8"
        )
    )

    del data["sha256"]

    broken_path.write_text(
        json.dumps(data),
        encoding="utf-8",
    )

    with pytest.raises(MetadataVerificationError) as exc_info:
        load_metadata(broken_path)

    assert "Invalid metadata structure" in str(
        exc_info.value
    )


def test_verify_metadata_rejects_missing_evidence(
    evidence_file: Path,
    vault_root: Path,
    test_root: Path,
) -> None:
    """Verification must fail when the evidence object is missing."""

    from tracee.ingest import ingest_file

    metadata, _ = ingest_file(
        evidence_file,
        vault_root,
    )

    missing_evidence = (
        test_root
        / "missing-evidence.bin"
    )

    with pytest.raises(MetadataVerificationError) as exc_info:
        verify_metadata(
            metadata_path(
                vault_root,
                metadata.evidence_id,
            ),
            missing_evidence,
            chain_path(vault_root),
        )

    assert "Evidence file does not exist" in str(
        exc_info.value
    )


def test_verify_metadata_rejects_evidence_size_tampering(
    evidence_file: Path,
    vault_root: Path,
    test_root: Path,
) -> None:
    """A changed evidence size must fail verification."""

    from tracee.ingest import ingest_file

    metadata, _ = ingest_file(
        evidence_file,
        vault_root,
    )

    tampered_evidence = (
        test_root
        / "tampered-size.bin"
    )

    tampered_evidence.write_bytes(
        evidence_path(
            vault_root,
            metadata.evidence_id,
        ).read_bytes()
        + b"tampered"
    )

    with pytest.raises(MetadataVerificationError) as exc_info:
        verify_metadata(
            metadata_path(
                vault_root,
                metadata.evidence_id,
            ),
            tampered_evidence,
            chain_path(vault_root),
        )

    assert "Evidence size mismatch" in str(
        exc_info.value
    )


def test_verify_metadata_rejects_evidence_hash_tampering(
    evidence_file: Path,
    vault_root: Path,
    test_root: Path,
) -> None:
    """Same-size evidence modification must fail SHA-256 verification."""

    from tracee.ingest import ingest_file

    metadata, _ = ingest_file(
        evidence_file,
        vault_root,
    )

    original = evidence_path(
        vault_root,
        metadata.evidence_id,
    ).read_bytes()

    assert original

    modified = bytearray(original)
    modified[0] ^= 0xFF

    tampered_evidence = (
        test_root
        / "tampered-hash.bin"
    )

    tampered_evidence.write_bytes(
        bytes(modified)
    )

    assert tampered_evidence.stat().st_size == (
        metadata.size_bytes
    )

    with pytest.raises(MetadataVerificationError) as exc_info:
        verify_metadata(
            metadata_path(
                vault_root,
                metadata.evidence_id,
            ),
            tampered_evidence,
            chain_path(vault_root),
        )

    assert "Evidence SHA-256 mismatch" in str(
        exc_info.value
    )


def test_verify_metadata_rejects_metadata_hash_mismatch(
    evidence_file: Path,
    vault_root: Path,
    test_root: Path,
) -> None:
    """Changing metadata must break its binding to the chain."""

    from tracee.ingest import ingest_file

    metadata, _ = ingest_file(
        evidence_file,
        vault_root,
    )

    original_path = metadata_path(
        vault_root,
        metadata.evidence_id,
    )

    tampered_metadata = (
        test_root
        / "tampered-metadata.json"
    )

    data = json.loads(
        original_path.read_text(
            encoding="utf-8"
        )
    )

    data["original_filename"] = (
        "tampered-name.log"
    )

    tampered_metadata.write_text(
        json.dumps(data),
        encoding="utf-8",
    )

    with pytest.raises(MetadataVerificationError) as exc_info:
        verify_metadata(
            tampered_metadata,
            evidence_path(
                vault_root,
                metadata.evidence_id,
            ),
            chain_path(vault_root),
        )

    assert (
        "Metadata SHA-256 mismatch with chain"
        in str(exc_info.value)
    )


def test_verify_metadata_rejects_missing_chain(
    evidence_file: Path,
    vault_root: Path,
    test_root: Path,
) -> None:
    """Verification must fail when the chain file is missing."""

    from tracee.ingest import ingest_file

    metadata, _ = ingest_file(
        evidence_file,
        vault_root,
    )

    missing_chain = (
        test_root
        / "missing-chain.jsonl"
    )

    with pytest.raises(MetadataVerificationError) as exc_info:
        verify_metadata(
            metadata_path(
                vault_root,
                metadata.evidence_id,
            ),
            evidence_path(
                vault_root,
                metadata.evidence_id,
            ),
            missing_chain,
        )

    assert "Chain file does not exist" in str(
        exc_info.value
    )


def test_load_chain_metadata_hash_rejects_missing_evidence_id(
    evidence_file: Path,
    vault_root: Path,
) -> None:
    """Looking up an unknown evidence ID must fail."""

    from tracee.ingest import ingest_file

    ingest_file(
        evidence_file,
        vault_root,
    )

    with pytest.raises(MetadataVerificationError) as exc_info:
        load_chain_metadata_hash(
            chain_path(vault_root),
            "TRACE-EV-999999",
        )

    assert "No chain record found" in str(
        exc_info.value
    )


def test_load_chain_metadata_hash_rejects_invalid_chain_json(
    evidence_file: Path,
    vault_root: Path,
    test_root: Path,
) -> None:
    """Malformed chain JSON must fail metadata lookup."""

    from tracee.ingest import ingest_file

    ingest_file(
        evidence_file,
        vault_root,
    )

    broken_chain = (
        test_root
        / "broken-chain.jsonl"
    )

    broken_chain.write_text(
        "{invalid-json\n",
        encoding="utf-8",
    )

    with pytest.raises(MetadataVerificationError) as exc_info:
        load_chain_metadata_hash(
            broken_chain,
            "TRACE-EV-000001",
        )

    assert "Invalid chain JSON" in str(
        exc_info.value
    )


def test_load_chain_metadata_hash_rejects_non_object_record(
    evidence_file: Path,
    vault_root: Path,
    test_root: Path,
) -> None:
    """A chain line that is not an object must fail."""

    from tracee.ingest import ingest_file

    ingest_file(
        evidence_file,
        vault_root,
    )

    broken_chain = (
        test_root
        / "non-object-chain.jsonl"
    )

    broken_chain.write_text(
        json.dumps(["not", "an", "object"]) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(MetadataVerificationError) as exc_info:
        load_chain_metadata_hash(
            broken_chain,
            "TRACE-EV-000001",
        )

    assert "is not an object" in str(
        exc_info.value
    )


def test_load_chain_metadata_hash_rejects_missing_metadata_hash(
    evidence_file: Path,
    vault_root: Path,
    test_root: Path,
) -> None:
    """A matching chain record without metadata_sha256 must fail."""

    from tracee.ingest import ingest_file

    metadata, _ = ingest_file(
        evidence_file,
        vault_root,
    )

    records = read_chain_records(vault_root)

    del records[0]["metadata_sha256"]

    broken_chain = (
        test_root
        / "missing-metadata-hash-chain.jsonl"
    )

    write_chain_records(
        broken_chain,
        records,
    )

    with pytest.raises(MetadataVerificationError) as exc_info:
        load_chain_metadata_hash(
            broken_chain,
            metadata.evidence_id,
        )

    assert "Missing metadata_sha256" in str(
        exc_info.value
    )


def test_verify_metadata_is_read_only(
    evidence_file: Path,
    vault_root: Path,
) -> None:
    """Metadata verification must not modify any persisted artifact."""

    from tracee.ingest import ingest_file

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

    verify_metadata(
        metadata_file,
        evidence_file_path,
        chain_file,
    )

    assert metadata_file.read_bytes() == metadata_before
    assert evidence_file_path.read_bytes() == evidence_before
    assert chain_file.read_bytes() == chain_before
