"""Tamper-evident local operational activity records for a TRACEE vault."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, BinaryIO

from .canonical import canonicalize
from .ids import is_valid_evidence_id
from .locking import (
    exclusive_file_lock,
    set_private_file_permissions,
    set_private_permissions,
)

ACTIVITY_SCHEMA_VERSION = "1.0"
GENESIS_HASH = "GENESIS"
ACTIVITY_FILENAME = "activity.jsonl"
ACTIVITY_LOCK_FILENAME = ".activity.lock"
_EVENT_TYPES = {
    "evidence_viewed",
    "integrity_verification",
    "evidence_acquisition_started",
    "evidence_acquired",
    "evidence_acquisition_failed",
    "evidence_analysis_started",
    "evidence_analysis_completed",
    "evidence_analysis_failed",
    "evidence_reconstruction_started",
    "evidence_reconstruction_completed",
    "evidence_reconstruction_failed",
}
_ACTORS = {
    "unauthenticated_local_client",
    "local_api_token",
    "local_upload_token",
    "local_cli",
}
_VERIFICATION_OUTCOMES = {"VALID", "TAMPERED", "MISSING", "INVALID"}
_FAILURE_OUTCOMES = {
    "duplicate_evidence", "invalid_upload", "upload_too_large",
    "ingestion_failed", "storage_failure", "internal_error",
    "invalid_multipart", "missing_file", "unexpected_form_field",
    "empty_file", "invalid_filename", "unavailable_vault",
    "unsupported_media_type", "invalid_content_length",
    "unsupported_parser", "parser_mismatch", "integrity_verification_failed",
    "evidence_not_found", "evidence_unavailable", "analysis_limit_exceeded",
    "source_changed", "invalid_record", "analysis_storage_failed",
    "malformed_metadata", "unreadable_metadata",
    "analysis_configuration_invalid",
    "vault_unavailable", "analysis_id_conflict", "analysis_unavailable",
    "unsupported_source_type", "analysis_invalid", "reconstruction_failed",
    "reconstruction_storage_failed", "reconstruction_storage_unavailable",
    "reconstruction_limit_exceeded", "reconstruction_id_conflict",
    "stale_analysis", "stale_reconstruction", "invalid_request",
    "invalid_evidence_id", "invalid_analysis_id", "evidence_not_found",
    "vault_not_configured", "integrity_verification_failed", "unreadable_metadata",
    "analysis_invalid", "analysis_not_found", "analysis_unavailable",
    "analysis_limit_exceeded", "unsupported_parser", "parser_mismatch",
    "invalid_pagination", "evidence_unavailable", "malformed_metadata",
    "reconstruction_invalid", "reconstruction_not_found", "invalid_reconstruction_id",
    "reconstruction_unavailable", "invalid_pagination", "analysis_configuration_invalid",
    "reconstruction_configuration_invalid",
    "unsupported_platform", "dependency_missing", "unsupported_channel",
    "channel_unavailable", "access_denied", "collection_failed", "no_events",
    "invalid_event_record", "invalid_event_timestamp", "size_limit_exceeded",
    "invalid_filter", "no_matching_events",
}
_LOCKS: dict[str, threading.Lock] = {}
_LOCKS_GUARD = threading.Lock()


class ActivityLogError(Exception):
    """The activity log is unavailable or its integrity is invalid."""


class ActivityLogIntegrityError(ActivityLogError):
    """Existing activity history is malformed or has a broken hash chain."""


def _lock_for(path: Path) -> threading.Lock:
    key = str(path.resolve())
    with _LOCKS_GUARD:
        return _LOCKS.setdefault(key, threading.Lock())


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def _digest(record: dict[str, Any]) -> str:
    return hashlib.sha256(canonicalize(record)).hexdigest()


def _validate_entry(entry: Any, expected_previous: str) -> dict[str, Any]:
    fields = {
        "schema_version", "event_id", "timestamp", "event_type", "actor",
        "outcome", "evidence_id", "filename", "size_bytes", "sha256",
        "previous_hash", "record_hash",
    }
    if not isinstance(entry, dict) or set(entry) != fields:
        raise ActivityLogIntegrityError("Activity record has an invalid structure")
    if entry["schema_version"] != ACTIVITY_SCHEMA_VERSION:
        raise ActivityLogIntegrityError("Activity record schema is unsupported")
    try:
        if str(uuid.UUID(entry["event_id"])) != entry["event_id"]:
            raise ValueError
    except (ValueError, TypeError, AttributeError) as exc:
        raise ActivityLogIntegrityError("Activity event ID is invalid") from exc
    timestamp = entry["timestamp"]
    if not isinstance(timestamp, str) or not timestamp.endswith("Z"):
        raise ActivityLogIntegrityError("Activity timestamp is invalid")
    try:
        parsed_timestamp = datetime.fromisoformat(timestamp[:-1] + "+00:00")
    except ValueError as exc:
        raise ActivityLogIntegrityError("Activity timestamp is invalid") from exc
    if parsed_timestamp.utcoffset() != timezone.utc.utcoffset(parsed_timestamp):
        raise ActivityLogIntegrityError("Activity timestamp must be UTC")
    if not isinstance(entry["event_type"], str) or entry["event_type"] not in _EVENT_TYPES:
        raise ActivityLogIntegrityError("Activity event type is unsupported")
    if not isinstance(entry["actor"], str) or entry["actor"] not in _ACTORS:
        raise ActivityLogIntegrityError("Activity actor classification is invalid")
    if not isinstance(entry["outcome"], str) or not entry["outcome"]:
        raise ActivityLogIntegrityError("Activity outcome is invalid")
    if entry["event_type"] in {
        "evidence_viewed", "integrity_verification", "evidence_analysis_started",
        "evidence_analysis_completed", "evidence_analysis_failed",
        "evidence_reconstruction_started", "evidence_reconstruction_completed",
        "evidence_reconstruction_failed",
    }:
        if entry["actor"] not in {"unauthenticated_local_client", "local_api_token"}:
            raise ActivityLogIntegrityError("Activity actor does not match event type")
    elif entry["event_type"] in {
        "evidence_acquisition_started", "evidence_acquired", "evidence_acquisition_failed",
    }:
        if entry["actor"] not in {"local_upload_token", "local_cli"}:
            raise ActivityLogIntegrityError("Activity actor does not match event type")
    else:
        if entry["actor"] != "local_upload_token":
            raise ActivityLogIntegrityError("Activity actor does not match event type")
    allowed_outcomes = {
        "evidence_viewed": {"success"},
        "integrity_verification": _VERIFICATION_OUTCOMES,
        "evidence_acquisition_started": {"accepted"},
        "evidence_acquired": {"success"},
        "evidence_acquisition_failed": _FAILURE_OUTCOMES,
        "evidence_analysis_started": {"accepted"},
        "evidence_analysis_completed": {"success"},
        "evidence_analysis_failed": _FAILURE_OUTCOMES,
        "evidence_reconstruction_started": {"accepted"},
        "evidence_reconstruction_completed": {"success"},
        "evidence_reconstruction_failed": _FAILURE_OUTCOMES,
    }
    if entry["outcome"] not in allowed_outcomes[entry["event_type"]]:
        raise ActivityLogIntegrityError("Activity outcome is invalid")
    evidence_id = entry["evidence_id"]
    if evidence_id is not None and (
        not isinstance(evidence_id, str) or not is_valid_evidence_id(evidence_id)
    ):
        raise ActivityLogIntegrityError("Activity evidence ID is invalid")
    filename = entry["filename"]
    if filename is not None and (
        not isinstance(filename, str)
        or not filename
        or filename in {".", ".."}
        or "/" in filename
        or "\\" in filename
        or any(ord(char) < 32 or ord(char) == 127 for char in filename)
    ):
        raise ActivityLogIntegrityError("Activity filename is invalid")
    size = entry["size_bytes"]
    if size is not None and (
        not isinstance(size, int) or isinstance(size, bool) or size < 0
    ):
        raise ActivityLogIntegrityError("Activity file size is invalid")
    sha256 = entry["sha256"]
    if sha256 is not None and (
        not isinstance(sha256, str)
        or len(sha256) != 64
        or any(char not in "0123456789abcdef" for char in sha256)
    ):
        raise ActivityLogIntegrityError("Activity digest is invalid")
    if entry["previous_hash"] != expected_previous:
        raise ActivityLogIntegrityError("Activity hash chain is discontinuous")
    supplied_hash = entry["record_hash"]
    unhashed = {key: value for key, value in entry.items() if key != "record_hash"}
    try:
        expected_hash = _digest(unhashed)
    except (TypeError, ValueError) as exc:
        raise ActivityLogIntegrityError("Activity record is not canonical JSON") from exc
    if not isinstance(supplied_hash, str) or supplied_hash != expected_hash:
        raise ActivityLogIntegrityError("Activity record hash is invalid")
    return entry


class ActivityLog:
    """Append and validate a local activity hash chain."""

    def __init__(self, vault_dir: str | Path) -> None:
        self.vault_dir = Path(vault_dir)
        self.directory = self.vault_dir / "audit"
        self.path = self.directory / ACTIVITY_FILENAME
        self.lock_path = self.directory / ACTIVITY_LOCK_FILENAME
        self._lock = _lock_for(self.path)

    def _read_all_unlocked(self) -> list[dict[str, Any]]:
        if self.directory.is_symlink():
            raise ActivityLogIntegrityError("Activity directory is unavailable")
        if not self.directory.exists():
            return []
        if not self.directory.is_dir():
            raise ActivityLogIntegrityError("Activity directory is unavailable")
        if self.path.is_symlink():
            raise ActivityLogIntegrityError("Activity file is unavailable")
        if not self.path.exists():
            return []
        if not self.path.is_file():
            raise ActivityLogIntegrityError("Activity file is unavailable")
        try:
            raw_lines = self.path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeError) as exc:
            raise ActivityLogError("Activity file could not be read") from exc
        entries: list[dict[str, Any]] = []
        previous = GENESIS_HASH
        for line in raw_lines:
            if not line.strip():
                raise ActivityLogIntegrityError("Activity log contains a blank record")
            try:
                entry = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ActivityLogIntegrityError("Activity log contains invalid JSON") from exc
            validated = _validate_entry(entry, previous)
            entries.append(validated)
            previous = validated["record_hash"]
        return entries

    def _open_lock_file(self) -> BinaryIO:
        if self.lock_path.is_symlink():
            raise ActivityLogIntegrityError("Activity lock path is unavailable")
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        flags |= getattr(os, "O_BINARY", 0)
        descriptor = os.open(self.lock_path, flags, 0o600)
        try:
            if self.lock_path.is_symlink() or not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise ActivityLogIntegrityError("Activity lock path is unavailable")
            set_private_file_permissions(descriptor, 0o600)
            return os.fdopen(descriptor, "r+b")
        except BaseException:
            os.close(descriptor)
            raise

    def append(
        self,
        *,
        event_type: str,
        actor: str,
        outcome: str,
        evidence_id: str | None = None,
        filename: str | None = None,
        size_bytes: int | None = None,
        sha256: str | None = None,
    ) -> dict[str, Any]:
        """Validate history and append one canonical, fsynced entry."""
        with self._lock:
            if not self.directory.exists():
                try:
                    self.directory.mkdir(mode=0o700)
                except FileExistsError:
                    pass
                except OSError as exc:
                    raise ActivityLogError("Activity directory could not be created") from exc
            if self.directory.is_symlink() or not self.directory.is_dir():
                raise ActivityLogError("Activity directory is unavailable")
            try:
                set_private_permissions(self.directory, 0o700)
            except OSError as exc:
                raise ActivityLogError("Activity directory permissions could not be secured") from exc
            try:
                with self._open_lock_file() as lock_file:
                    with exclusive_file_lock(lock_file, lock_path=self.lock_path):
                        return self._append_locked(
                            event_type=event_type,
                            actor=actor,
                            outcome=outcome,
                            evidence_id=evidence_id,
                            filename=filename,
                            size_bytes=size_bytes,
                            sha256=sha256,
                        )
            except OSError as exc:
                raise ActivityLogError("Activity lock could not be acquired") from exc

    def _append_locked(
        self,
        *,
        event_type: str,
        actor: str,
        outcome: str,
        evidence_id: str | None,
        filename: str | None,
        size_bytes: int | None,
        sha256: str | None,
    ) -> dict[str, Any]:
        entries = self._read_all_unlocked()
        previous = entries[-1]["record_hash"] if entries else GENESIS_HASH
        record: dict[str, Any] = {
            "schema_version": ACTIVITY_SCHEMA_VERSION,
            "event_id": str(uuid.uuid4()),
            "timestamp": _utc_now(),
            "event_type": event_type,
            "actor": actor,
            "outcome": outcome,
            "evidence_id": evidence_id,
            "filename": filename,
            "size_bytes": size_bytes,
            "sha256": sha256,
            "previous_hash": previous,
        }
        record["record_hash"] = _digest(record)
        _validate_entry(record, previous)
        serialized = json.dumps(
            record, sort_keys=True, ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8") + b"\n"
        descriptor = None
        original_size = 0
        rollback_allowed = False
        try:
            if self.path.is_symlink():
                raise ActivityLogIntegrityError("Activity file is unavailable")
            flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
            flags |= getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(self.path, flags, 0o600)
            if self.path.is_symlink():
                os.close(descriptor)
                descriptor = None
                raise ActivityLogIntegrityError("Activity file is unavailable")
            file_stat = os.fstat(descriptor)
            if not stat.S_ISREG(file_stat.st_mode):
                raise OSError("Activity path is not a regular file")
            original_size = file_stat.st_size
            rollback_allowed = True
            set_private_file_permissions(descriptor, 0o600)
            with os.fdopen(descriptor, "ab", closefd=True) as stream:
                descriptor = None
                stream.write(serialized)
                stream.flush()
                os.fsync(stream.fileno())
        except OSError as exc:
            if descriptor is not None:
                os.close(descriptor)
            try:
                if rollback_allowed and self.path.is_file() and not self.path.is_symlink():
                    with self.path.open("r+b") as stream:
                        stream.truncate(original_size)
                        stream.flush()
                        os.fsync(stream.fileno())
            except OSError:
                pass
            raise ActivityLogError("Activity record could not be written") from exc
        return record

    def recent(self, limit: int = 50) -> list[dict[str, Any]]:
        """Return the newest validated entries without creating audit files."""
        with self._lock:
            if not self.path.exists():
                return []
            try:
                with self._open_lock_file() as lock_file:
                    with exclusive_file_lock(lock_file, lock_path=self.lock_path):
                        return list(reversed(self._read_all_unlocked()))[:limit]
            except OSError as exc:
                raise ActivityLogError("Activity lock could not be acquired") from exc
