"""
TRACEE Evidence Data Models

Defines the structured records used by the V0.1 evidence foundation.

This module contains data definitions and validation only.
It does not perform hashing, storage, ingestion, or verification.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Dict

from .hashing import validate_sha256
from .ids import is_valid_evidence_id


EVIDENCE_SCHEMA_VERSION = "1.0"
CHAIN_SCHEMA_VERSION = "1.0"


class ModelValidationError(ValueError):
    """Raised when a TRACEE data model contains invalid values."""


@dataclass(frozen=True)
class EvidenceMetadata:
    """Metadata describing one evidence object stored by TRACEE."""

    schema_version: str
    evidence_id: str
    original_filename: str
    size_bytes: int
    sha256: str
    ingested_at: str
    media_type: str

    def __post_init__(self) -> None:
        if not self.schema_version:
            raise ModelValidationError(
                "schema_version must not be empty"
            )

        if not is_valid_evidence_id(self.evidence_id):
            raise ModelValidationError(
                f"Invalid evidence ID: {self.evidence_id!r}"
            )

        if not self.original_filename:
            raise ModelValidationError(
                "original_filename must not be empty"
            )

        if (
            not isinstance(self.size_bytes, int)
            or isinstance(self.size_bytes, bool)
            or self.size_bytes < 0
        ):
            raise ModelValidationError(
                "size_bytes must be a non-negative integer"
            )

        if not validate_sha256(self.sha256):
            raise ModelValidationError(
                "sha256 must be a lowercase 64-character SHA-256 digest"
            )

        if not self.ingested_at:
            raise ModelValidationError(
                "ingested_at must not be empty"
            )

        if not self.media_type:
            raise ModelValidationError(
                "media_type must not be empty"
            )

    def to_dict(self) -> Dict[str, Any]:
        """Return metadata as a plain dictionary."""

        return asdict(self)


@dataclass(frozen=True)
class ChainRecord:
    """
    One append-only record in the TRACEE evidence chain.

    metadata_sha256 cryptographically binds the evidence metadata
    record to this chain entry.
    """

    schema_version: str
    sequence: int
    evidence_id: str
    timestamp: str
    metadata_sha256: str
    previous_record_hash: str
    record_hash: str

    def __post_init__(self) -> None:
        if not self.schema_version:
            raise ModelValidationError(
                "schema_version must not be empty"
            )

        if (
            not isinstance(self.sequence, int)
            or isinstance(self.sequence, bool)
            or self.sequence <= 0
        ):
            raise ModelValidationError(
                "sequence must be greater than zero"
            )

        if not is_valid_evidence_id(self.evidence_id):
            raise ModelValidationError(
                f"Invalid evidence ID: {self.evidence_id!r}"
            )

        if not self.timestamp:
            raise ModelValidationError(
                "timestamp must not be empty"
            )

        if not validate_sha256(self.metadata_sha256):
            raise ModelValidationError(
                "metadata_sha256 must be a lowercase "
                "64-character SHA-256 digest"
            )

        if (
            self.previous_record_hash != "GENESIS"
            and not validate_sha256(self.previous_record_hash)
        ):
            raise ModelValidationError(
                "previous_record_hash must be GENESIS "
                "or a valid SHA-256 digest"
            )

        if not validate_sha256(self.record_hash):
            raise ModelValidationError(
                "record_hash must be a valid SHA-256 digest"
            )

    def to_dict(self) -> Dict[str, Any]:
        """Return the complete chain record."""

        return asdict(self)

    def hashable_dict(self) -> Dict[str, Any]:
        """
        Return exactly the fields used to calculate record_hash.

        record_hash itself is deliberately excluded.
        """

        return {
            "schema_version": self.schema_version,
            "sequence": self.sequence,
            "evidence_id": self.evidence_id,
            "timestamp": self.timestamp,
            "metadata_sha256": self.metadata_sha256,
            "previous_record_hash": self.previous_record_hash,
        }
