"""
TRACEE Application Services

Provides the application-facing service layer for TRACEE V0.2.

This module orchestrates the established V0.1 foundation:

    - evidence ingestion
    - evidence verification
    - metadata verification
    - evidence-chain verification
    - metadata retrieval

The service layer does not implement hashing, chain construction,
filesystem storage, or verification algorithms itself.

Those responsibilities remain in the underlying V0.1 modules.
"""

from __future__ import annotations

from pathlib import Path

from .chain import ChainRecord
from .ingest import ingest_file
from .models import EvidenceMetadata
from .vault import FilesystemVaultStore
from .verify import (
    VerificationEngine,
    VerificationResult,
)
from .verify_chain import verify_persistent_chain
from .verify_metadata import verify_metadata


class TraceeService:
    """
    Application service interface for one TRACEE vault.

    The class provides a stable boundary between future interfaces
    such as the CLI/API and the lower-level V0.1 foundation.
    """

    def __init__(
        self,
        vault_dir: str | Path,
    ) -> None:
        """
        Create a service instance for the specified vault.

        The constructor does not create or modify the vault.
        """

        self.vault_dir = Path(vault_dir).resolve()

        self.vault = FilesystemVaultStore(
            self.vault_dir
        )

    def ingest(
        self,
        source_path: str | Path,
    ) -> tuple[EvidenceMetadata, ChainRecord]:
        """
        Ingest one evidence source into the configured vault.

        Returns:
            A tuple containing the generated evidence metadata
            and the corresponding chain record.
        """

        return ingest_file(
            source_path=source_path,
            vault_dir=self.vault_dir,
        )

    def verify(
        self,
        evidence_id: str,
    ) -> VerificationResult:
        """
        Perform complete verification of one evidence object.

        Verification remains read-only and delegates all integrity
        checks to the existing VerificationEngine.
        """

        metadata_path = self.vault.record_path(
            evidence_id
        )

        evidence_path = self.vault.evidence_path(
            evidence_id
        )

        chain_path = self.vault.chain_path

        engine = VerificationEngine(
            metadata_path=metadata_path,
            evidence_path=evidence_path,
            chain_path=chain_path,
        )

        return engine.verify()

    def verify_chain(self) -> list[ChainRecord]:
        """
        Verify the complete persisted evidence chain.

        Returns:
            The verified chain records.

        Raises:
            ChainVerificationError:
                When the persisted chain is invalid or unavailable.
        """

        return verify_persistent_chain(
            self.vault.chain_path
        )

    def verify_metadata(
        self,
        evidence_id: str,
    ) -> EvidenceMetadata:
        """
        Verify one evidence object's metadata against its evidence
        file and persisted chain binding.

        Returns:
            The verified EvidenceMetadata instance.
        """

        metadata_path = self.vault.record_path(
            evidence_id
        )

        evidence_path = self.vault.evidence_path(
            evidence_id
        )

        return verify_metadata(
            metadata_path=metadata_path,
            evidence_path=evidence_path,
            chain_path=self.vault.chain_path,
        )

    def get_metadata(
        self,
        evidence_id: str,
    ) -> dict:
        """
        Read one persisted metadata record.

        This operation is read-only and does not perform
        integrity verification.
        """

        return self.vault.read_record(
            evidence_id
        )
