"""
TRACEE Evidence Vault

Provides filesystem storage primitives for the V0.1 evidence foundation.

Responsibilities:
- Define the vault directory layout.
- Create required directories.
- Provide exclusive filesystem locking.
- Provide staging locations.
- Atomically promote staged evidence into the vault.
- Store and load metadata records.

This module does not perform hashing, evidence ID generation,
chain management, or verification.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import stat
import subprocess
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from .errors import VaultError
from .ids import is_valid_evidence_id
from .locking import (
    exclusive_file_lock,
    remove_path,
    set_private_permissions,
    set_read_only,
)


EVIDENCE_FILENAME = "evidence.bin"
CHAIN_FILENAME = "chain.jsonl"
LOCK_FILENAME = ".vault.lock"
_logger = logging.getLogger(__name__)


def _rename_diagnostics_enabled() -> bool:
    return os.environ.get("TRACEE_VAULT_RENAME_DIAGNOSTICS") == "1"


def _rename_diagnostics(
    staged_dir: Path,
    destination_dir: Path,
    staged_file: Path,
    destination_file: Path,
    *,
    phase: str,
    error: OSError | None = None,
) -> None:
    """Log opt-in, content-free filesystem state around object promotion."""

    if not _rename_diagnostics_enabled():
        return

    def path_state(path: Path) -> dict[str, Any]:
        state: dict[str, Any] = {
            "path": str(path),
            "parent": str(path.parent),
            "drive": path.drive,
            "exists": path.exists(),
            "is_symlink": path.is_symlink(),
        }
        try:
            info = path.lstat()
        except OSError as exc:
            state["lstat_error"] = {
                "winerror": getattr(exc, "winerror", None),
                "errno": exc.errno,
                "message": exc.strerror,
            }
        else:
            attributes = getattr(info, "st_file_attributes", None)
            readonly_flag = getattr(stat, "FILE_ATTRIBUTE_READONLY", 0x1)
            state.update({
                "st_mode": info.st_mode,
                "is_directory": stat.S_ISDIR(info.st_mode),
                "st_size": info.st_size,
                "st_dev": info.st_dev,
                "st_ino": info.st_ino,
                "st_file_attributes": attributes,
                "read_only_attribute": (
                    bool(attributes & readonly_flag) if attributes is not None else None
                ),
            })
        try:
            state["resolved"] = str(path.resolve(strict=False))
        except OSError as exc:
            state["resolve_error"] = {
                "winerror": getattr(exc, "winerror", None),
                "errno": exc.errno,
                "message": exc.strerror,
            }
        return state

    relevant_paths = (
        staged_dir,
        staged_dir.parent,
        destination_dir,
        destination_dir.parent,
        staged_file,
        destination_file,
    )
    states = [path_state(path) for path in relevant_paths]
    source_parent = states[1]
    destination_parent = states[3]
    same_device = source_parent.get("st_dev") == destination_parent.get("st_dev")
    if source_parent["drive"] and destination_parent["drive"]:
        same_volume: bool | None = (
            source_parent["drive"].casefold()
            == destination_parent["drive"].casefold()
        )
    else:
        same_volume = same_device if source_parent.get("st_dev") is not None else None
    record: dict[str, Any] = {
        "event": "vault_directory_replace_diagnostics",
        "phase": phase,
        "vault_root": str(staged_dir.parent.parent),
        "source": str(staged_dir),
        "source_parent": str(staged_dir.parent),
        "destination": str(destination_dir),
        "destination_parent": str(destination_dir.parent),
        "same_volume": same_volume,
        "paths": states,
        "application_handle_notes": [
            "stage_evidence closes its source and staged-file handles before returning.",
            "commit_staged_evidence does not open source or destination evidence files.",
            "A caller may hold the vault lock file; it is outside both renamed directories.",
        ],
    }
    if error is not None:
        record["os_error"] = {
            "type": type(error).__name__,
            "winerror": getattr(error, "winerror", None),
            "errno": error.errno,
            "message": error.strerror,
            "exception_text": str(error),
            "filename": error.filename,
            "filename2": getattr(error, "filename2", None),
        }

    if os.name == "nt":
        icacls = shutil.which("icacls.exe") or shutil.which("icacls")
        acl_paths = (staged_dir, staged_dir.parent, destination_dir.parent, staged_dir.parent.parent)
        acl_records = []
        for path in dict.fromkeys(acl_paths):
            if icacls is None:
                acl_records.append({"path": str(path), "error": "icacls_unavailable"})
                continue
            try:
                result = subprocess.run(
                    [icacls, str(path)],
                    capture_output=True,
                    text=True,
                    errors="replace",
                    timeout=5,
                    check=False,
                )
                acl_records.append({
                    "path": str(path),
                    "returncode": result.returncode,
                    "output": (result.stdout + result.stderr).strip(),
                })
            except (OSError, subprocess.SubprocessError) as exc:
                acl_records.append({
                    "path": str(path),
                    "error": type(exc).__name__,
                    "message": str(exc),
                })
        record["acl"] = acl_records

    level = logging.ERROR if error is not None else logging.INFO
    _logger.log(level, "%s", json.dumps(record, ensure_ascii=False, sort_keys=True))


def _emit_rename_diagnostics(*args: Any, **kwargs: Any) -> None:
    """Keep optional diagnostics from affecting filesystem behavior."""

    try:
        _rename_diagnostics(*args, **kwargs)
    except Exception:
        _logger.debug("Unable to collect opt-in vault rename diagnostics", exc_info=True)


class FilesystemVaultStore:
    """
    Filesystem-backed TRACEE evidence vault.
    """

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)

        self.objects_dir = self.root / "objects"
        self.records_dir = self.root / "records"
        self.chain_dir = self.root / "chain"
        self.staging_dir = self.root / ".staging"

        self.lock_path = self.root / LOCK_FILENAME
        self.chain_path = self.chain_dir / CHAIN_FILENAME

    def initialize(self) -> None:
        """
        Create the complete vault directory structure.

        Initialization is idempotent. Calling this method repeatedly
        must not modify existing evidence or metadata.

        Required directory paths must actually be directories.
        Required file paths must actually be regular files.
        """

        required_directories = (
            self.objects_dir,
            self.records_dir,
            self.chain_dir,
            self.staging_dir,
        )

        for directory in required_directories:
            try:
                directory.mkdir(
                    parents=True,
                    exist_ok=True,
                )
            except OSError as exc:
                raise VaultError(
                    f"Unable to initialize vault: {self.root}"
                ) from exc

            if directory.is_symlink() or not directory.is_dir():
                raise VaultError(
                    f"Vault path is not a directory: {directory}"
                )

        required_files = (
            self.chain_path,
            self.lock_path,
        )

        for file_path in required_files:
            try:
                file_path.touch(
                    mode=0o600,
                    exist_ok=False,
                )
            except FileExistsError:
                pass
            except OSError as exc:
                raise VaultError(
                    f"Unable to initialize vault: {self.root}"
                ) from exc

            if file_path.is_symlink() or not file_path.is_file():
                raise VaultError(
                    f"Vault path is not a regular file: "
                    f"{file_path}"
                )

    @contextmanager
    def exclusive_lock(self) -> Iterator[None]:
        """
        Acquire an exclusive process-level filesystem lock.

        The lock is held for the lifetime of the context manager.
        """

        self.initialize()

        try:
            with self.lock_path.open("r+b") as lock_file:
                try:
                    with exclusive_file_lock(lock_file):
                        yield
                except OSError as exc:
                    raise VaultError(
                        "Unable to acquire vault lock"
                    ) from exc

        except OSError as exc:
            raise VaultError(
                "Unable to access vault lock file"
            ) from exc

    def evidence_dir(self, evidence_id: str) -> Path:
        """
        Return the object directory for an evidence ID.
        """

        self._validate_evidence_id(evidence_id)

        return self.objects_dir / evidence_id

    def evidence_path(self, evidence_id: str) -> Path:
        """
        Return the stored evidence object path.
        """

        return self.evidence_dir(evidence_id) / EVIDENCE_FILENAME

    def record_path(self, evidence_id: str) -> Path:
        """
        Return the metadata record path.
        """

        self._validate_evidence_id(evidence_id)

        return self.records_dir / f"{evidence_id}.json"

    def staging_path(self, evidence_id: str) -> Path:
        """
        Return a unique staging path for an evidence object.
        """

        self._validate_evidence_id(evidence_id)

        return self.staging_dir / evidence_id

    def stage_evidence(
        self,
        evidence_id: str,
        source: str | Path,
    ) -> Path:
        """
        Copy source evidence into a staging location.

        The caller is responsible for verifying the staged content
        before committing it.
        """

        self._validate_evidence_id(evidence_id)
        self.initialize()

        source_path = Path(source)

        if not source_path.is_file():
            raise VaultError(
                f"Source evidence does not exist: {source_path}"
            )

        destination = self.staging_path(evidence_id)

        try:
            if destination.exists():
                shutil.rmtree(destination)

            destination.mkdir(
                parents=True,
                exist_ok=False,
            )

            staged_file = destination / EVIDENCE_FILENAME

            with source_path.open("rb") as source_file:
                with staged_file.open("wb") as destination_file:
                    shutil.copyfileobj(
                        source_file,
                        destination_file,
                        length=1024 * 1024,
                    )

            set_private_permissions(staged_file, 0o600)

            return staged_file

        except OSError as exc:
            self._remove_path(destination)

            raise VaultError(
                f"Unable to stage evidence: {source_path}"
            ) from exc

    def commit_staged_evidence(
        self,
        evidence_id: str,
    ) -> Path:
        """
        Atomically promote staged evidence into the vault.

        The destination must not already exist.
        """

        self._validate_evidence_id(evidence_id)
        self.initialize()

        staged_dir = self.staging_path(evidence_id)
        destination_dir = self.evidence_dir(evidence_id)

        staged_file = staged_dir / EVIDENCE_FILENAME
        destination_file = destination_dir / EVIDENCE_FILENAME

        if not staged_file.is_file():
            raise VaultError(
                f"Staged evidence does not exist: {staged_file}"
            )

        if destination_dir.exists():
            raise VaultError(
                f"Evidence object already exists: {evidence_id}"
            )

        replace_completed = False
        try:
            _emit_rename_diagnostics(
                staged_dir,
                destination_dir,
                staged_file,
                destination_file,
                phase="before",
            )
            os.replace(
                staged_dir,
                destination_dir,
            )
            replace_completed = True

            set_read_only(destination_file)

            return destination_file

        except OSError as exc:
            if not replace_completed:
                _emit_rename_diagnostics(
                    staged_dir,
                    destination_dir,
                    staged_file,
                    destination_file,
                    phase="failure",
                    error=exc,
                )
            raise VaultError(
                f"Unable to commit staged evidence: {evidence_id}"
            ) from exc

    def write_record(
        self,
        evidence_id: str,
        record: dict[str, Any],
    ) -> Path:
        """
        Atomically write a metadata record.

        The record is written to a temporary file and then promoted
        with os.replace().
        """

        self._validate_evidence_id(evidence_id)
        self.initialize()

        destination = self.record_path(evidence_id)

        temporary = self.records_dir / (
            f".{evidence_id}.json.tmp"
        )

        try:
            serialized = json.dumps(
                record,
                indent=2,
                ensure_ascii=False,
            )

            with temporary.open(
                "w",
                encoding="utf-8",
            ) as file:
                file.write(serialized)
                file.write("\n")
                file.flush()
                os.fsync(file.fileno())

            set_private_permissions(temporary, 0o600)

            os.replace(
                temporary,
                destination,
            )

            return destination

        except (OSError, TypeError, ValueError) as exc:
            self._remove_path(temporary)

            raise VaultError(
                f"Unable to write metadata record: {evidence_id}"
            ) from exc

    def read_record(
        self,
        evidence_id: str,
    ) -> dict[str, Any]:
        """
        Load a metadata record from the vault.
        """

        self._validate_evidence_id(evidence_id)

        path = self.record_path(evidence_id)

        if not path.is_file():
            raise VaultError(
                f"Metadata record does not exist: {evidence_id}"
            )

        try:
            with path.open(
                "r",
                encoding="utf-8",
            ) as file:
                record = json.load(file)

        except (OSError, json.JSONDecodeError) as exc:
            raise VaultError(
                f"Unable to read metadata record: {evidence_id}"
            ) from exc

        if not isinstance(record, dict):
            raise VaultError(
                f"Metadata record is not a JSON object: {evidence_id}"
            )

        return record

    def cleanup_staging(
        self,
        evidence_id: str,
    ) -> None:
        """
        Remove a staging directory if it exists.
        """

        self._validate_evidence_id(evidence_id)

        self._remove_path(
            self.staging_path(evidence_id)
        )

    def _validate_evidence_id(
        self,
        evidence_id: str,
    ) -> None:
        if not is_valid_evidence_id(evidence_id):
            raise VaultError(
                f"Invalid evidence ID: {evidence_id!r}"
            )

    @staticmethod
    def _remove_path(path: Path) -> None:
        try:
            remove_path(path)

        except OSError:
            pass
