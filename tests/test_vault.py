"""
TRACEE Evidence Vault Tests

Tests the filesystem-backed evidence vault used by the V0.1
integrity foundation.

All filesystem state is isolated inside pytest's temporary
directory.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from src.tracee.errors import VaultError
from src.tracee.vault import (
    CHAIN_FILENAME,
    EVIDENCE_FILENAME,
    LOCK_FILENAME,
    FilesystemVaultStore,
)


VALID_EVIDENCE_ID = "TRACE-EV-000001"

VALID_RECORD = {
    "schema_version": "1.0",
    "evidence_id": VALID_EVIDENCE_ID,
    "original_filename": "evidence.log",
    "size_bytes": 10,
    "sha256": "a" * 64,
    "ingested_at": "2026-10-03T10:00:00Z",
    "media_type": "text/plain",
}


def test_vault_initialize_creates_required_directories(
    vault_root: Path,
) -> None:
    """Vault initialization must create the complete directory layout."""

    vault = FilesystemVaultStore(vault_root)
    vault.initialize()

    assert vault.objects_dir.is_dir()
    assert vault.records_dir.is_dir()
    assert vault.chain_dir.is_dir()
    assert vault.staging_dir.is_dir()


def test_vault_initialize_creates_chain_file(
    vault_root: Path,
) -> None:
    """Initialization must create an empty chain file."""

    vault = FilesystemVaultStore(vault_root)
    vault.initialize()

    assert vault.chain_path == (
        vault.chain_dir / CHAIN_FILENAME
    )
    assert vault.chain_path.is_file()
    assert vault.chain_path.read_text(
        encoding="utf-8"
    ) == ""


def test_vault_initialize_creates_lock_file(
    vault_root: Path,
) -> None:
    """Initialization must create the vault lock file."""

    vault = FilesystemVaultStore(vault_root)
    vault.initialize()

    assert vault.lock_path == (
        vault.root / LOCK_FILENAME
    )
    assert vault.lock_path.is_file()


def test_vault_initialization_is_idempotent(
    vault_root: Path,
) -> None:
    """Calling initialize repeatedly must not destroy existing state."""

    vault = FilesystemVaultStore(vault_root)

    vault.initialize()

    vault.chain_path.write_text(
        "existing\n",
        encoding="utf-8",
    )

    vault.initialize()

    assert vault.chain_path.read_text(
        encoding="utf-8"
    ) == "existing\n"


def test_evidence_paths_use_expected_layout(
    vault_root: Path,
) -> None:
    """Evidence paths must follow the V0.1 vault layout."""

    vault = FilesystemVaultStore(vault_root)

    assert vault.evidence_dir(
        VALID_EVIDENCE_ID
    ) == (
        vault.objects_dir
        / VALID_EVIDENCE_ID
    )

    assert vault.evidence_path(
        VALID_EVIDENCE_ID
    ) == (
        vault.objects_dir
        / VALID_EVIDENCE_ID
        / EVIDENCE_FILENAME
    )

    assert vault.record_path(
        VALID_EVIDENCE_ID
    ) == (
        vault.records_dir
        / f"{VALID_EVIDENCE_ID}.json"
    )

    assert vault.staging_path(
        VALID_EVIDENCE_ID
    ) == (
        vault.staging_dir
        / VALID_EVIDENCE_ID
    )


@pytest.mark.parametrize(
    "evidence_id",
    [
        "",
        "TRACE-EV-000000",
        "TRACE-EV-ABCDEF",
        "invalid",
        "../TRACE-EV-000001",
    ],
)
def test_vault_rejects_invalid_evidence_id(
    vault_root: Path,
    evidence_id: str,
) -> None:
    """Vault paths must reject malformed evidence IDs."""

    vault = FilesystemVaultStore(vault_root)

    with pytest.raises(VaultError):
        vault.evidence_dir(evidence_id)


def test_stage_evidence_copies_source(
    vault_root: Path,
    evidence_file: Path,
) -> None:
    """Staging must copy evidence into the isolated staging area."""

    vault = FilesystemVaultStore(vault_root)

    staged = vault.stage_evidence(
        VALID_EVIDENCE_ID,
        evidence_file,
    )

    assert staged.is_file()
    assert staged == (
        vault.staging_dir
        / VALID_EVIDENCE_ID
        / EVIDENCE_FILENAME
    )

    assert staged.read_bytes() == (
        evidence_file.read_bytes()
    )


def test_stage_evidence_creates_staging_directory(
    vault_root: Path,
    evidence_file: Path,
) -> None:
    """Staging must create the evidence-specific staging directory."""

    vault = FilesystemVaultStore(vault_root)

    vault.stage_evidence(
        VALID_EVIDENCE_ID,
        evidence_file,
    )

    assert vault.staging_path(
        VALID_EVIDENCE_ID
    ).is_dir()


def test_stage_evidence_rejects_missing_source(
    vault_root: Path,
    test_root: Path,
) -> None:
    """Missing source evidence must fail explicitly."""

    vault = FilesystemVaultStore(vault_root)
    missing = test_root / "missing.log"

    with pytest.raises(VaultError):
        vault.stage_evidence(
            VALID_EVIDENCE_ID,
            missing,
        )


def test_stage_evidence_replaces_existing_stage(
    vault_root: Path,
    evidence_file: Path,
    second_evidence_file: Path,
) -> None:
    """Restaging the same evidence ID must replace the previous stage."""

    vault = FilesystemVaultStore(vault_root)

    first = vault.stage_evidence(
        VALID_EVIDENCE_ID,
        evidence_file,
    )

    assert first.read_bytes() == (
        evidence_file.read_bytes()
    )

    second = vault.stage_evidence(
        VALID_EVIDENCE_ID,
        second_evidence_file,
    )

    assert second.read_bytes() == (
        second_evidence_file.read_bytes()
    )


def test_commit_staged_evidence_promotes_atomically(
    vault_root: Path,
    evidence_file: Path,
) -> None:
    """Committed evidence must move from staging into the vault."""

    vault = FilesystemVaultStore(vault_root)

    staged = vault.stage_evidence(
        VALID_EVIDENCE_ID,
        evidence_file,
    )

    committed = vault.commit_staged_evidence(
        VALID_EVIDENCE_ID
    )

    assert committed.is_file()
    assert committed == vault.evidence_path(
        VALID_EVIDENCE_ID
    )

    assert committed.read_bytes() == (
        evidence_file.read_bytes()
    )

    assert not staged.exists()
    assert not vault.staging_path(
        VALID_EVIDENCE_ID
    ).exists()


def test_commit_staged_evidence_rejects_missing_stage(
    vault_root: Path,
) -> None:
    """Committing without staged evidence must fail."""

    vault = FilesystemVaultStore(vault_root)

    with pytest.raises(VaultError):
        vault.commit_staged_evidence(
            VALID_EVIDENCE_ID
        )


def test_commit_staged_evidence_rejects_duplicate_destination(
    vault_root: Path,
    evidence_file: Path,
) -> None:
    """An existing evidence object must not be overwritten."""

    vault = FilesystemVaultStore(vault_root)

    vault.stage_evidence(
        VALID_EVIDENCE_ID,
        evidence_file,
    )

    vault.commit_staged_evidence(
        VALID_EVIDENCE_ID
    )

    vault.stage_evidence(
        VALID_EVIDENCE_ID,
        evidence_file,
    )

    with pytest.raises(VaultError):
        vault.commit_staged_evidence(
            VALID_EVIDENCE_ID
        )


def test_write_and_read_record(
    vault_root: Path,
) -> None:
    """Metadata records must survive a write/read round trip."""

    vault = FilesystemVaultStore(vault_root)

    written = vault.write_record(
        VALID_EVIDENCE_ID,
        VALID_RECORD,
    )

    assert written.is_file()

    loaded = vault.read_record(
        VALID_EVIDENCE_ID
    )

    assert loaded == VALID_RECORD


def test_metadata_record_is_valid_json(
    vault_root: Path,
) -> None:
    """Persisted metadata must be valid JSON."""

    vault = FilesystemVaultStore(vault_root)

    path = vault.write_record(
        VALID_EVIDENCE_ID,
        VALID_RECORD,
    )

    data = json.loads(
        path.read_text(
            encoding="utf-8"
        )
    )

    assert data == VALID_RECORD


def test_read_record_rejects_missing_record(
    vault_root: Path,
) -> None:
    """Reading a missing metadata record must fail."""

    vault = FilesystemVaultStore(vault_root)

    with pytest.raises(VaultError):
        vault.read_record(
            VALID_EVIDENCE_ID
        )


def test_read_record_rejects_non_object_json(
    vault_root: Path,
) -> None:
    """Metadata files must contain JSON objects."""

    vault = FilesystemVaultStore(vault_root)

    vault.initialize()

    path = vault.record_path(
        VALID_EVIDENCE_ID
    )

    path.write_text(
        json.dumps(["not", "an", "object"]),
        encoding="utf-8",
    )

    with pytest.raises(VaultError):
        vault.read_record(
            VALID_EVIDENCE_ID
        )


def test_cleanup_staging(
    vault_root: Path,
    evidence_file: Path,
) -> None:
    """Staging cleanup must remove the evidence staging directory."""

    vault = FilesystemVaultStore(vault_root)

    vault.stage_evidence(
        VALID_EVIDENCE_ID,
        evidence_file,
    )

    assert vault.staging_path(
        VALID_EVIDENCE_ID
    ).exists()

    vault.cleanup_staging(
        VALID_EVIDENCE_ID
    )

    assert not vault.staging_path(
        VALID_EVIDENCE_ID
    ).exists()


def test_cleanup_staging_is_safe_when_missing(
    vault_root: Path,
) -> None:
    """Cleaning an absent staging directory must be harmless."""

    vault = FilesystemVaultStore(vault_root)

    vault.cleanup_staging(
        VALID_EVIDENCE_ID
    )


def test_exclusive_lock_can_be_acquired(
    vault_root: Path,
) -> None:
    """The vault must provide an exclusive filesystem lock."""

    vault = FilesystemVaultStore(vault_root)

    with vault.exclusive_lock():
        assert vault.lock_path.is_file()


def test_vault_permissions_follow_platform_semantics(
    vault_root: Path,
    evidence_file: Path,
) -> None:
    """
    POSIX uses private mode bits; Windows uses inherited ACLs and a
    read-only attribute for committed evidence.
    """

    vault = FilesystemVaultStore(vault_root)

    staged = vault.stage_evidence(
        VALID_EVIDENCE_ID,
        evidence_file,
    )

    staged_mode = os.stat(staged).st_mode & 0o777
    if os.name == "nt":
        # Windows uses inherited NTFS ACLs; Python mode bits are not ACLs.
        assert os.access(staged, os.R_OK)
    else:
        assert staged_mode == 0o600

    committed = vault.commit_staged_evidence(
        VALID_EVIDENCE_ID
    )

    committed_mode = os.stat(
        committed
    ).st_mode & 0o777
    if os.name == "nt":
        assert not os.access(committed, os.W_OK)
    else:
        assert committed_mode == 0o400

    metadata = vault.write_record(
        "TRACE-EV-000002",
        {
            **VALID_RECORD,
            "evidence_id": "TRACE-EV-000002",
        },
    )

    metadata_mode = os.stat(
        metadata
    ).st_mode & 0o777
    if os.name == "nt":
        assert os.access(metadata, os.R_OK)
    else:
        assert metadata_mode == 0o600


def test_cleanup_removes_read_only_committed_evidence(
    vault_root: Path,
    evidence_file: Path,
) -> None:
    vault = FilesystemVaultStore(vault_root)
    vault.stage_evidence("TRACE-EV-000001", evidence_file)
    vault.commit_staged_evidence("TRACE-EV-000001")

    vault._remove_path(vault.evidence_dir("TRACE-EV-000001"))

    assert not vault.evidence_dir("TRACE-EV-000001").exists()
