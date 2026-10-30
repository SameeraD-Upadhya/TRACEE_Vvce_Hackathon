"""
TRACEE V0.1 Tamper and Integrity Integration Tests

Tests the complete integrity boundary of the V0.1 foundation.

Each test starts from a valid ingested evidence object and then
introduces one controlled integrity failure.

The tests verify that TRACEE detects:

    - evidence-byte modification
    - metadata modification
    - metadata-to-chain binding modification
    - chain record-hash modification
    - previous-record link modification
    - missing evidence
    - missing metadata
    - missing chain
    - corrupted chain JSON
"""

from __future__ import annotations

import json
from pathlib import Path

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
    """Return the metadata path."""

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


def chain_path(
    vault_root: Path,
) -> Path:
    """Return the chain path."""

    return vault_root / "chain" / "chain.jsonl"


def engine(
    vault_root: Path,
    evidence_id: str,
    *,
    metadata: Path | None = None,
    evidence: Path | None = None,
    chain: Path | None = None,
) -> VerificationEngine:
    """Build a verification engine with optional artifact overrides."""

    return VerificationEngine(
        metadata_path=metadata
        or metadata_path(
            vault_root,
            evidence_id,
        ),
        evidence_path=evidence
        or evidence_path(
            vault_root,
            evidence_id,
        ),
        chain_path=chain
        or chain_path(vault_root),
    )


def read_chain(
    vault_root: Path,
) -> list[dict]:
    """Read the persisted chain into dictionaries."""

    return [
        json.loads(line)
        for line in chain_path(vault_root)
        .read_text(
            encoding="utf-8"
        )
        .splitlines()
        if line.strip()
    ]


def write_chain(
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


def test_clean_evidence_is_valid(
    evidence_file: Path,
    vault_root: Path,
) -> None:
    """Control test: untouched evidence must verify."""

    metadata, _ = ingest_file(
        evidence_file,
        vault_root,
    )

    result = engine(
        vault_root,
        metadata.evidence_id,
    ).verify()

    assert result.state is VerificationState.VALID


def test_evidence_modification_is_detected(
    evidence_file: Path,
    vault_root: Path,
    test_root: Path,
) -> None:
    """A modified evidence copy must fail hash verification."""

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

    tampered = test_root / "tampered-evidence.bin"

    tampered.write_bytes(bytes(modified))

    result = engine(
        vault_root,
        metadata.evidence_id,
        evidence=tampered,
    ).verify()

    assert result.state is VerificationState.TAMPERED
    assert "sha-256" in result.message.lower()


def test_metadata_modification_is_detected(
    evidence_file: Path,
    vault_root: Path,
    test_root: Path,
) -> None:
    """A modified metadata record must fail chain binding."""

    metadata, _ = ingest_file(
        evidence_file,
        vault_root,
    )

    original = metadata_path(
        vault_root,
        metadata.evidence_id,
    )

    tampered = test_root / "tampered-metadata.json"

    data = json.loads(
        original.read_text(
            encoding="utf-8"
        )
    )

    data["original_filename"] = "tampered.log"

    tampered.write_text(
        json.dumps(data),
        encoding="utf-8",
    )

    result = engine(
        vault_root,
        metadata.evidence_id,
        metadata=tampered,
    ).verify()

    assert result.state is VerificationState.TAMPERED
    assert "metadata" in result.message.lower()


def test_metadata_chain_binding_modification_is_detected(
    evidence_file: Path,
    vault_root: Path,
    test_root: Path,
) -> None:
    """
    Changing the chain's metadata hash must invalidate the
    metadata-to-chain relationship.
    """

    metadata, _ = ingest_file(
        evidence_file,
        vault_root,
    )

    records = read_chain(vault_root)

    records[0]["metadata_sha256"] = "0" * 64

    tampered_chain = test_root / "tampered-chain.jsonl"

    write_chain(
        tampered_chain,
        records,
    )

    result = engine(
        vault_root,
        metadata.evidence_id,
        chain=tampered_chain,
    ).verify()

    assert result.state is VerificationState.TAMPERED
    assert "metadata" in result.message.lower()


def test_chain_record_hash_modification_is_detected(
    evidence_file: Path,
    vault_root: Path,
    test_root: Path,
) -> None:
    """Changing a chain record's stored hash must be detected."""

    metadata, _ = ingest_file(
        evidence_file,
        vault_root,
    )

    records = read_chain(vault_root)

    records[0]["record_hash"] = "0" * 64

    tampered_chain = test_root / "tampered-record-hash.jsonl"

    write_chain(
        tampered_chain,
        records,
    )

    result = engine(
        vault_root,
        metadata.evidence_id,
        chain=tampered_chain,
    ).verify()

    assert result.state is VerificationState.TAMPERED
    assert "record hash" in result.message.lower()


def test_previous_record_link_modification_is_detected(
    evidence_file: Path,
    second_evidence_file: Path,
    vault_root: Path,
    test_root: Path,
) -> None:
    """
    A chain record with a valid recalculated own hash but an
    invalid previous-record reference must still fail.
    """

    ingest_file(
        evidence_file,
        vault_root,
    )

    second_metadata, _ = ingest_file(
        second_evidence_file,
        vault_root,
    )

    records = read_chain(vault_root)

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

    tampered_chain = test_root / "tampered-link.jsonl"

    write_chain(
        tampered_chain,
        records,
    )

    result = engine(
        vault_root,
        second_metadata.evidence_id,
        chain=tampered_chain,
    ).verify()

    assert result.state is VerificationState.TAMPERED
    assert "chain" in result.message.lower()


def test_missing_evidence_is_detected(
    evidence_file: Path,
    vault_root: Path,
    test_root: Path,
) -> None:
    """A missing evidence artifact must produce MISSING."""

    metadata, _ = ingest_file(
        evidence_file,
        vault_root,
    )

    missing_evidence = (
        test_root / "missing-evidence.bin"
    )

    result = engine(
        vault_root,
        metadata.evidence_id,
        evidence=missing_evidence,
    ).verify()

    assert result.state is VerificationState.MISSING


def test_missing_metadata_is_detected(
    evidence_file: Path,
    vault_root: Path,
    test_root: Path,
) -> None:
    """A missing metadata artifact must produce MISSING."""

    metadata, _ = ingest_file(
        evidence_file,
        vault_root,
    )

    missing_metadata = (
        test_root / "missing-metadata.json"
    )

    result = engine(
        vault_root,
        metadata.evidence_id,
        metadata=missing_metadata,
    ).verify()

    assert result.state is VerificationState.MISSING


def test_missing_chain_is_detected(
    evidence_file: Path,
    vault_root: Path,
    test_root: Path,
) -> None:
    """A missing chain artifact must produce MISSING."""

    metadata, _ = ingest_file(
        evidence_file,
        vault_root,
    )

    missing_chain = (
        test_root / "missing-chain.jsonl"
    )

    result = engine(
        vault_root,
        metadata.evidence_id,
        chain=missing_chain,
    ).verify()

    assert result.state is VerificationState.MISSING


def test_corrupted_chain_json_is_detected(
    evidence_file: Path,
    vault_root: Path,
    test_root: Path,
) -> None:
    """Malformed chain JSON must produce INVALID."""

    metadata, _ = ingest_file(
        evidence_file,
        vault_root,
    )

    corrupted_chain = (
        test_root / "corrupted-chain.jsonl"
    )

    corrupted_chain.write_text(
        "{this-is-not-valid-json\n",
        encoding="utf-8",
    )

    result = engine(
        vault_root,
        metadata.evidence_id,
        chain=corrupted_chain,
    ).verify()

    assert result.state is VerificationState.INVALID
