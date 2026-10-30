"""
TRACEE V0.1 End-to-End Tests

Tests the complete evidence-integrity workflow from ingestion
through independent verification.

These tests verify that the foundation works as one system:

    source evidence
        -> ingestion
        -> evidence vault
        -> metadata record
        -> evidence chain
        -> metadata verification
        -> chain verification
        -> unified verification
"""

from __future__ import annotations

from pathlib import Path

from tracee.ingest import ingest_file
from tracee.verify import VerificationEngine, VerificationState
from tracee.verify_chain import verify_persistent_chain
from tracee.verify_metadata import verify_metadata


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


def chain_path(
    vault_root: Path,
) -> Path:
    """Return the persisted chain path."""

    return vault_root / "chain" / "chain.jsonl"


def test_complete_single_evidence_workflow(
    evidence_file: Path,
    vault_root: Path,
) -> None:
    """One evidence file must survive the complete V0.1 workflow."""

    metadata, record = ingest_file(
        evidence_file,
        vault_root,
    )

    stored_metadata = metadata_path(
        vault_root,
        metadata.evidence_id,
    )

    stored_evidence = evidence_path(
        vault_root,
        metadata.evidence_id,
    )

    stored_chain = chain_path(
        vault_root,
    )

    verified_metadata = verify_metadata(
        stored_metadata,
        stored_evidence,
        stored_chain,
    )

    verified_chain = verify_persistent_chain(
        stored_chain,
    )

    unified_result = VerificationEngine(
        metadata_path=stored_metadata,
        evidence_path=stored_evidence,
        chain_path=stored_chain,
    ).verify()

    assert verified_metadata == metadata

    assert len(verified_chain) == 1
    assert verified_chain[0] == record

    assert unified_result.state is VerificationState.VALID
    assert unified_result.evidence_id == metadata.evidence_id
    assert unified_result.is_valid() is True


def test_complete_two_evidence_workflow(
    evidence_file: Path,
    second_evidence_file: Path,
    vault_root: Path,
) -> None:
    """Two evidence objects must share one valid integrity chain."""

    first_metadata, first_record = ingest_file(
        evidence_file,
        vault_root,
    )

    second_metadata, second_record = ingest_file(
        second_evidence_file,
        vault_root,
    )

    chain = verify_persistent_chain(
        chain_path(vault_root),
    )

    assert len(chain) == 2
    assert chain[0] == first_record
    assert chain[1] == second_record

    assert chain[0].sequence == 1
    assert chain[1].sequence == 2

    assert (
        chain[1].previous_record_hash
        == chain[0].record_hash
    )

    first_result = VerificationEngine(
        metadata_path=metadata_path(
            vault_root,
            first_metadata.evidence_id,
        ),
        evidence_path=evidence_path(
            vault_root,
            first_metadata.evidence_id,
        ),
        chain_path=chain_path(vault_root),
    ).verify()

    second_result = VerificationEngine(
        metadata_path=metadata_path(
            vault_root,
            second_metadata.evidence_id,
        ),
        evidence_path=evidence_path(
            vault_root,
            second_metadata.evidence_id,
        ),
        chain_path=chain_path(vault_root),
    ).verify()

    assert first_result.state is VerificationState.VALID
    assert second_result.state is VerificationState.VALID


def test_end_to_end_preserves_source_bytes(
    evidence_file: Path,
    vault_root: Path,
) -> None:
    """The vault evidence object must exactly match the source bytes."""

    metadata, _ = ingest_file(
        evidence_file,
        vault_root,
    )

    stored = evidence_path(
        vault_root,
        metadata.evidence_id,
    )

    assert stored.read_bytes() == evidence_file.read_bytes()


def test_end_to_end_metadata_chain_binding_is_valid(
    evidence_file: Path,
    vault_root: Path,
) -> None:
    """Metadata and chain must remain cryptographically bound."""

    metadata, record = ingest_file(
        evidence_file,
        vault_root,
    )

    verified_metadata = verify_metadata(
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

    assert verified_metadata == metadata
    assert record.metadata_sha256


def test_end_to_end_verification_is_read_only(
    evidence_file: Path,
    vault_root: Path,
) -> None:
    """The complete verification process must not modify stored artifacts."""

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

    chain_file = chain_path(
        vault_root,
    )

    metadata_before = metadata_file.read_bytes()
    evidence_before = evidence_file_path.read_bytes()
    chain_before = chain_file.read_bytes()

    verify_metadata(
        metadata_file,
        evidence_file_path,
        chain_file,
    )

    verify_persistent_chain(
        chain_file,
    )

    result = VerificationEngine(
        metadata_path=metadata_file,
        evidence_path=evidence_file_path,
        chain_path=chain_file,
    ).verify()

    assert result.state is VerificationState.VALID

    assert metadata_file.read_bytes() == metadata_before
    assert evidence_file_path.read_bytes() == evidence_before
    assert chain_file.read_bytes() == chain_before
