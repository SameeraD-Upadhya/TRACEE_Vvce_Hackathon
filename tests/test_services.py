"""
TRACEE Application Service Tests

Tests the V0.2 application service layer.

The service layer is intentionally thin. These tests verify that it
correctly delegates to the established V0.1 foundation without
duplicating integrity logic.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tracee.errors import VaultError
from tracee.services import TraceeService
from tracee.verify import VerificationState


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


def test_service_constructor_does_not_create_vault(
    vault_root: Path,
) -> None:
    """Constructing TraceeService must not create the vault."""

    assert not vault_root.exists()

    service = TraceeService(vault_root)

    assert service.vault_dir == vault_root.resolve()
    assert not vault_root.exists()


def test_service_ingest_delegates_to_foundation(
    evidence_file: Path,
    vault_root: Path,
) -> None:
    """Service ingestion should produce normal V0.1 records."""

    service = TraceeService(vault_root)

    metadata, record = service.ingest(
        evidence_file
    )

    assert metadata.evidence_id == "TRACE-EV-000001"
    assert metadata.sha256
    assert metadata.size_bytes == evidence_file.stat().st_size

    assert record.sequence == 1
    assert record.evidence_id == metadata.evidence_id
    assert record.previous_record_hash == "GENESIS"

    assert evidence_path(
        vault_root,
        metadata.evidence_id,
    ).is_file()

    assert metadata_path(
        vault_root,
        metadata.evidence_id,
    ).is_file()

    assert chain_path(vault_root).is_file()


def test_service_ingest_supports_multiple_evidence_objects(
    evidence_file: Path,
    second_evidence_file: Path,
    vault_root: Path,
) -> None:
    """Service ingestion should preserve sequential evidence IDs."""

    service = TraceeService(vault_root)

    first_metadata, first_record = service.ingest(
        evidence_file
    )

    second_metadata, second_record = service.ingest(
        second_evidence_file
    )

    assert first_metadata.evidence_id == "TRACE-EV-000001"
    assert second_metadata.evidence_id == "TRACE-EV-000002"

    assert first_record.sequence == 1
    assert second_record.sequence == 2

    assert (
        second_record.previous_record_hash
        == first_record.record_hash
    )


def test_service_verify_returns_valid_result(
    evidence_file: Path,
    vault_root: Path,
) -> None:
    """A valid evidence object should return VALID."""

    service = TraceeService(vault_root)

    metadata, _ = service.ingest(
        evidence_file
    )

    result = service.verify(
        metadata.evidence_id
    )

    assert result.state is VerificationState.VALID
    assert result.evidence_id == metadata.evidence_id
    assert result.is_valid() is True


def test_service_verify_detects_missing_metadata(
    evidence_file: Path,
    vault_root: Path,
) -> None:
    """
    The service should expose missing-artifact verification results.

    When the metadata itself is missing, VerificationEngine cannot
    recover the evidence ID from the missing artifact and therefore
    correctly returns UNKNOWN.
    """

    service = TraceeService(vault_root)

    metadata, _ = service.ingest(
        evidence_file
    )

    metadata_file = metadata_path(
        vault_root,
        metadata.evidence_id,
    )

    metadata_file.unlink()

    result = service.verify(
        metadata.evidence_id
    )

    assert result.state is VerificationState.MISSING
    assert result.evidence_id == "UNKNOWN"


def test_service_verify_detects_tampered_chain(
    evidence_file: Path,
    vault_root: Path,
) -> None:
    """The service should expose chain integrity failures."""

    service = TraceeService(vault_root)

    metadata, _ = service.ingest(
        evidence_file
    )

    chain_file = chain_path(vault_root)

    records = [
        json.loads(line)
        for line in chain_file.read_text(
            encoding="utf-8"
        ).splitlines()
        if line.strip()
    ]

    records[0]["record_hash"] = "0" * 64

    chain_file.write_text(
        "".join(
            json.dumps(
                record,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
            for record in records
        ),
        encoding="utf-8",
    )

    result = service.verify(
        metadata.evidence_id
    )

    assert result.state is VerificationState.TAMPERED


def test_service_verify_chain_returns_verified_records(
    evidence_file: Path,
    second_evidence_file: Path,
    vault_root: Path,
) -> None:
    """verify_chain should return the complete verified chain."""

    service = TraceeService(vault_root)

    first_metadata, first_record = service.ingest(
        evidence_file
    )

    second_metadata, second_record = service.ingest(
        second_evidence_file
    )

    records = service.verify_chain()

    assert len(records) == 2

    assert records[0] == first_record
    assert records[1] == second_record

    assert records[0].sequence == 1
    assert records[1].sequence == 2

    assert (
        records[0].evidence_id
        == first_metadata.evidence_id
    )

    assert (
        records[1].evidence_id
        == second_metadata.evidence_id
    )


def test_service_verify_metadata_returns_verified_metadata(
    evidence_file: Path,
    vault_root: Path,
) -> None:
    """verify_metadata should delegate to the metadata verifier."""

    service = TraceeService(vault_root)

    metadata, _ = service.ingest(
        evidence_file
    )

    verified = service.verify_metadata(
        metadata.evidence_id
    )

    assert verified == metadata


def test_service_get_metadata_returns_persisted_record(
    evidence_file: Path,
    vault_root: Path,
) -> None:
    """get_metadata should return the stored metadata dictionary."""

    service = TraceeService(vault_root)

    metadata, _ = service.ingest(
        evidence_file
    )

    result = service.get_metadata(
        metadata.evidence_id
    )

    assert result == metadata.to_dict()


def test_service_get_metadata_is_read_only(
    evidence_file: Path,
    vault_root: Path,
) -> None:
    """Reading metadata through the service must not modify the record."""

    service = TraceeService(vault_root)

    metadata, _ = service.ingest(
        evidence_file
    )

    path = metadata_path(
        vault_root,
        metadata.evidence_id,
    )

    before = path.read_bytes()

    result = service.get_metadata(
        metadata.evidence_id
    )

    after = path.read_bytes()

    assert result == metadata.to_dict()
    assert after == before


def test_service_verify_chain_is_read_only(
    evidence_file: Path,
    vault_root: Path,
) -> None:
    """Chain verification through the service must not modify the chain."""

    service = TraceeService(vault_root)

    service.ingest(
        evidence_file
    )

    path = chain_path(vault_root)

    before = path.read_bytes()

    records = service.verify_chain()

    after = path.read_bytes()

    assert len(records) == 1
    assert after == before


def test_service_rejects_invalid_evidence_id_for_metadata_lookup(
    vault_root: Path,
) -> None:
    """Vault-backed service operations must reject invalid IDs."""

    service = TraceeService(vault_root)

    with pytest.raises(VaultError):
        service.get_metadata(
            "TRACE-EV-000000"
        )


def test_service_rejects_invalid_evidence_id_for_verification(
    vault_root: Path,
) -> None:
    """Verification lookup must reject invalid evidence IDs."""

    service = TraceeService(vault_root)

    with pytest.raises(VaultError):
        service.verify(
            "TRACE-EV-000000"
        )
