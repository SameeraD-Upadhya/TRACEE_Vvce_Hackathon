"""
TRACEE Error Model

Defines stable error codes and typed exceptions for the V0.1
evidence-integrity foundation.
"""

from __future__ import annotations

from enum import IntEnum


class ExitCode(IntEnum):
    """Stable TRACEE process exit codes."""

    SUCCESS = 0

    INVALID_INPUT = 10
    DUPLICATE_EVIDENCE = 11
    VAULT_FAILURE = 12
    METADATA_FAILURE = 13
    CHAIN_FAILURE = 14
    VERIFICATION_FAILURE = 15
    INGESTION_FAILURE = 16

    EVIDENCE_TAMPERED = 20
    EVIDENCE_MISSING = 21


class TraceeError(Exception):
    """
    Base exception for expected TRACEE application errors.
    """

    exit_code = ExitCode.VERIFICATION_FAILURE

    def __init__(
        self,
        message: str,
        *,
        exit_code: ExitCode | None = None,
    ) -> None:
        super().__init__(message)

        if exit_code is not None:
            self.exit_code = exit_code


class InvalidInputError(TraceeError):
    """Input evidence or configuration is invalid."""

    exit_code = ExitCode.INVALID_INPUT


class DuplicateEvidenceError(TraceeError):
    """Evidence already exists in the vault."""

    exit_code = ExitCode.DUPLICATE_EVIDENCE


class VaultError(TraceeError):
    """Evidence vault operation failed."""

    exit_code = ExitCode.VAULT_FAILURE


class MetadataError(TraceeError):
    """Evidence metadata is invalid or cannot be persisted."""

    exit_code = ExitCode.METADATA_FAILURE


class ChainError(TraceeError):
    """Evidence chain operation failed."""

    exit_code = ExitCode.CHAIN_FAILURE


class IngestionError(TraceeError):
    """Evidence ingestion operation failed."""

    exit_code = ExitCode.INGESTION_FAILURE


class VerificationError(TraceeError):
    """Generic verification failure."""

    exit_code = ExitCode.VERIFICATION_FAILURE


class EvidenceTamperedError(VerificationError):
    """Evidence bytes do not match their recorded digest."""

    exit_code = ExitCode.EVIDENCE_TAMPERED


class EvidenceMissingError(VerificationError):
    """Expected evidence object does not exist."""

    exit_code = ExitCode.EVIDENCE_MISSING


def exit_code_for(exception: BaseException) -> int:
    """
    Convert a TRACEE exception into its stable process exit code.

    Unknown exceptions map to verification failure rather than being
    silently treated as successful execution.
    """

    if isinstance(exception, TraceeError):
        return int(exception.exit_code)

    return int(ExitCode.VERIFICATION_FAILURE)
