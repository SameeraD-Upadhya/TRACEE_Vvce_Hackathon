"""
TRACEE Evidence Ingestion

Connects an evidence source file to the TRACEE V0.1
evidence-integrity foundation.

Ingestion performs:

1. Source validation
2. Vault locking
3. Evidence SHA-256 calculation
4. Duplicate-evidence detection
5. Evidence ID assignment
6. Evidence staging
7. Staged-evidence integrity verification
8. Evidence metadata creation
9. Canonical metadata hashing
10. Atomic evidence promotion
11. Metadata record storage
12. Chain-record creation
13. Append-only chain update
14. Cleanup on failure

This module does not perform parsing, correlation,
timeline generation, graph construction, or investigation analysis.
"""

from __future__ import annotations

import json
import mimetypes
import os
from datetime import datetime, timezone
from pathlib import Path

from .canonical import canonicalize
from .chain import (
    create_chain_record,
    verify_chain_link,
    verify_chain_record,
)
from .errors import (
    ChainError,
    DuplicateEvidenceError,
    IngestionError,
    MetadataError,
    TraceeError,
    VaultError,
)
from .hashing import sha256_bytes, sha256_file
from .ids import format_evidence_id
from .models import (
    EVIDENCE_SCHEMA_VERSION,
    ChainRecord,
    EvidenceMetadata,
)
from .vault import FilesystemVaultStore


# Use only Python's built-in MIME map. Loading OS MIME databases can make
# evidence metadata differ by host (for example, for the .log extension).
_MIME_TYPES = mimetypes.MimeTypes(filenames=())


def utc_now() -> str:
    """Return the current UTC timestamp in ISO-8601 format."""

    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def detect_media_type(path: Path) -> str:
    """
    Determine the MIME type of an evidence file.

    Falls back to application/octet-stream when no type
    can be detected.
    """

    media_type, _ = _MIME_TYPES.guess_type(path.name)

    return media_type or "application/octet-stream"


def metadata_sha256(
    metadata: EvidenceMetadata,
) -> str:
    """Calculate the SHA-256 of canonical metadata."""

    canonical_metadata = canonicalize(
        metadata.to_dict()
    )

    return sha256_bytes(canonical_metadata)


def _load_chain_records(
    vault: FilesystemVaultStore,
) -> list[ChainRecord]:
    """
    Load and validate all existing chain records.

    Ingestion fails closed if the existing chain is invalid.
    """

    chain_path = vault.chain_path

    if not chain_path.exists():
        return []

    records: list[ChainRecord] = []

    try:
        with chain_path.open(
            "r",
            encoding="utf-8",
        ) as stream:
            for line_number, line in enumerate(
                stream,
                start=1,
            ):
                stripped = line.strip()

                if not stripped:
                    raise ChainError(
                        f"Chain contains a blank record at "
                        f"line {line_number}"
                    )

                try:
                    data = json.loads(stripped)
                except json.JSONDecodeError as exc:
                    raise ChainError(
                        f"Invalid chain JSON at line "
                        f"{line_number}"
                    ) from exc

                if not isinstance(data, dict):
                    raise ChainError(
                        f"Chain record at line "
                        f"{line_number} is not a JSON object"
                    )

                try:
                    record = ChainRecord(
                        schema_version=data["schema_version"],
                        sequence=data["sequence"],
                        evidence_id=data["evidence_id"],
                        timestamp=data["timestamp"],
                        metadata_sha256=data["metadata_sha256"],
                        previous_record_hash=data[
                            "previous_record_hash"
                        ],
                        record_hash=data["record_hash"],
                    )
                except (
                    KeyError,
                    TypeError,
                    ValueError,
                ) as exc:
                    raise ChainError(
                        f"Invalid chain record at line "
                        f"{line_number}"
                    ) from exc

                records.append(record)

    except OSError as exc:
        raise ChainError(
            f"Unable to read evidence chain: {chain_path}"
        ) from exc

    _verify_complete_chain(records)

    return records


def _verify_complete_chain(
    records: list[ChainRecord],
) -> None:
    """Verify sequence continuity, hashes, and chain links."""

    if not records:
        return

    ordered = sorted(
        records,
        key=lambda record: record.sequence,
    )

    if ordered[0].sequence != 1:
        raise ChainError(
            "Evidence chain must begin at sequence 1"
        )

    for index, record in enumerate(ordered):
        expected_sequence = index + 1

        if record.sequence != expected_sequence:
            raise ChainError(
                "Evidence chain sequence is invalid"
            )

        if not verify_chain_record(record):
            raise ChainError(
                f"Chain record hash verification failed "
                f"at sequence {record.sequence}"
            )

        previous_record = (
            ordered[index - 1]
            if index > 0
            else None
        )

        if not verify_chain_link(
            previous_record,
            record,
        ):
            raise ChainError(
                f"Chain link verification failed "
                f"at sequence {record.sequence}"
            )


def _find_duplicate_sha256(
    vault: FilesystemVaultStore,
    evidence_sha256: str,
) -> str | None:
    """
    Search existing metadata records for the same
    evidence SHA-256 digest.
    """

    if not vault.records_dir.exists():
        return None

    for record_path in vault.records_dir.glob("*.json"):
        try:
            data = json.loads(
                record_path.read_text(
                    encoding="utf-8"
                )
            )

            if not isinstance(data, dict):
                continue

            existing_hash = data.get("sha256")
            existing_id = data.get("evidence_id")

            if (
                existing_hash == evidence_sha256
                and isinstance(existing_id, str)
            ):
                return existing_id

        except (
            OSError,
            json.JSONDecodeError,
        ):
            continue

    return None


def _next_sequence(
    records: list[ChainRecord],
) -> int:
    """Return the next evidence sequence number."""

    if not records:
        return 1

    return max(
        record.sequence
        for record in records
    ) + 1


def _append_chain_record(
    vault: FilesystemVaultStore,
    record: ChainRecord,
) -> int:
    """
    Append one chain record and fsync the chain file.

    Returns the original file size so the caller can
    roll back the append if a later operation fails.
    """

    chain_path = vault.chain_path

    try:
        chain_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        with chain_path.open(
            "a+",
            encoding="utf-8",
        ) as stream:
            stream.seek(0, os.SEEK_END)

            original_size = stream.tell()

            serialized = (
                json.dumps(
                    record.to_dict(),
                    sort_keys=True,
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
                + "\n"
            )

            stream.write(serialized)
            stream.flush()
            os.fsync(stream.fileno())

            return original_size

    except OSError as exc:
        raise ChainError(
            f"Unable to append chain record: {chain_path}"
        ) from exc


def _rollback_chain(
    vault: FilesystemVaultStore,
    original_size: int,
) -> None:
    """Restore the chain file to its previous size."""

    try:
        with vault.chain_path.open(
            "r+b"
        ) as stream:
            stream.truncate(original_size)
            stream.flush()
            os.fsync(stream.fileno())

    except OSError as exc:
        raise ChainError(
            "Unable to roll back evidence chain"
        ) from exc


def _write_metadata(
    vault: FilesystemVaultStore,
    metadata: EvidenceMetadata,
) -> Path:
    """Write metadata through the vault storage layer."""

    try:
        return vault.write_record(
            metadata.evidence_id,
            metadata.to_dict(),
        )

    except VaultError as exc:
        raise MetadataError(
            f"Unable to store metadata for "
            f"{metadata.evidence_id}"
        ) from exc


def ingest_file(
    source_path: str | Path,
    vault_dir: str | Path,
) -> tuple[EvidenceMetadata, ChainRecord]:
    """
    Ingest one evidence file into a TRACEE vault.

    The complete operation executes under the vault's
    exclusive lock.
    """

    source = Path(source_path).resolve()

    if not source.is_file():
        raise IngestionError(
            f"Evidence source does not exist: {source}"
        )

    try:
        source_size = source.stat().st_size
    except OSError as exc:
        raise IngestionError(
            f"Unable to inspect evidence source: {source}"
        ) from exc

    if source_size < 0:
        raise IngestionError(
            f"Invalid evidence size: {source_size}"
        )

    vault = FilesystemVaultStore(
        Path(vault_dir).resolve()
    )

    try:
        with vault.exclusive_lock():

            vault.initialize()

            existing_records = _load_chain_records(
                vault
            )

            evidence_hash = sha256_file(
                source
            )

            duplicate_id = _find_duplicate_sha256(
                vault,
                evidence_hash,
            )

            if duplicate_id is not None:
                raise DuplicateEvidenceError(
                    f"Evidence already exists as "
                    f"{duplicate_id}"
                )

            sequence = _next_sequence(
                existing_records
            )

            evidence_id = format_evidence_id(
                sequence
            )

            evidence_path = vault.evidence_path(
                evidence_id
            )

            record_path = vault.record_path(
                evidence_id
            )

            if evidence_path.exists():
                raise VaultError(
                    f"Evidence object already exists: "
                    f"{evidence_id}"
                )

            if record_path.exists():
                raise VaultError(
                    f"Metadata record already exists: "
                    f"{evidence_id}"
                )

            previous_record = (
                existing_records[-1]
                if existing_records
                else None
            )

            if previous_record is None:
                previous_hash = "GENESIS"
                chain_sequence = 1
            else:
                previous_hash = (
                    previous_record.record_hash
                )
                chain_sequence = (
                    previous_record.sequence + 1
                )

            if chain_sequence != sequence:
                raise ChainError(
                    "Evidence ID sequence and chain "
                    "sequence diverged"
                )

            ingested_at = utc_now()

            metadata = EvidenceMetadata(
                schema_version=EVIDENCE_SCHEMA_VERSION,
                evidence_id=evidence_id,
                original_filename=source.name,
                size_bytes=source_size,
                sha256=evidence_hash,
                ingested_at=ingested_at,
                media_type=detect_media_type(
                    source
                ),
            )

            metadata_hash = metadata_sha256(
                metadata
            )

            record = create_chain_record(
                sequence=chain_sequence,
                evidence_id=evidence_id,
                timestamp=ingested_at,
                metadata_sha256=metadata_hash,
                previous_record_hash=previous_hash,
            )

            staged_evidence_committed = False
            metadata_written = False
            chain_original_size: int | None = None
            chain_appended = False

            try:
                staged_path = vault.stage_evidence(
                    evidence_id,
                    source,
                )

                staged_size = staged_path.stat().st_size

                if staged_size != source_size:
                    raise IngestionError(
                        "Staged evidence size does not "
                        "match source evidence"
                    )

                staged_hash = sha256_file(
                    staged_path
                )

                if staged_hash != evidence_hash:
                    raise IngestionError(
                        "Staged evidence SHA-256 does "
                        "not match source evidence"
                    )

                committed_path = (
                    vault.commit_staged_evidence(
                        evidence_id
                    )
                )

                staged_evidence_committed = True

                committed_size = (
                    committed_path.stat().st_size
                )

                if committed_size != source_size:
                    raise IngestionError(
                        "Committed evidence size does "
                        "not match source evidence"
                    )

                committed_hash = sha256_file(
                    committed_path
                )

                if committed_hash != evidence_hash:
                    raise IngestionError(
                        "Committed evidence SHA-256 does "
                        "not match source evidence"
                    )

                _write_metadata(
                    vault,
                    metadata,
                )

                metadata_written = True

                chain_original_size = (
                    _append_chain_record(
                        vault,
                        record,
                    )
                )

                chain_appended = True

                return metadata, record

            except (
                TraceeError,
                OSError,
                ValueError,
                TypeError,
            ) as exc:

                if (
                    chain_appended
                    and chain_original_size is not None
                ):
                    _rollback_chain(
                        vault,
                        chain_original_size,
                    )

                if metadata_written:
                    try:
                        record_path.unlink(
                            missing_ok=True
                        )
                    except OSError:
                        pass

                if staged_evidence_committed:
                    try:
                        vault._remove_path(
                            vault.evidence_dir(
                                evidence_id
                            )
                        )
                    except OSError:
                        pass

                try:
                    vault.cleanup_staging(
                        evidence_id
                    )
                except VaultError:
                    pass

                if isinstance(
                    exc,
                    TraceeError,
                ):
                    raise

                raise IngestionError(
                    f"Evidence ingestion failed: "
                    f"{source}"
                ) from exc

    except (
        DuplicateEvidenceError,
        ChainError,
        MetadataError,
        VaultError,
        IngestionError,
    ):
        raise

    except Exception as exc:
        raise IngestionError(
            f"Evidence ingestion failed unexpectedly: "
            f"{source}"
        ) from exc
