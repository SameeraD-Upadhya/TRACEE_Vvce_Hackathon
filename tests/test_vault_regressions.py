"""
TRACEE Vault Regression Tests

Tests edge cases identified during the V0.1 foundation audit.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tracee.errors import VaultError
from tracee.vault import FilesystemVaultStore


def test_initialize_rejects_file_where_objects_directory_is_required(
    tmp_path: Path,
) -> None:
    """
    Vault initialization must fail when a required directory path
    is occupied by a regular file.
    """

    vault_root = tmp_path / "vault"

    objects_file = vault_root / "objects"
    objects_file.parent.mkdir(
        parents=True,
        exist_ok=True,
    )
    objects_file.write_text(
        "not a directory",
        encoding="utf-8",
    )

    chain_dir = vault_root / "chain"
    chain_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    chain_path = chain_dir / "chain.jsonl"
    chain_path.touch()

    lock_path = vault_root / ".vault.lock"
    lock_path.touch()

    vault = FilesystemVaultStore(vault_root)

    with pytest.raises(VaultError):
        vault.initialize()
