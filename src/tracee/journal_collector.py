"""Opt-in, checkpointed acquisition of local systemd journal JSON exports.

The collector reads journalctl output; it does not copy or modify journald's
native storage. Captured JSONL batches are ingested unchanged by TraceeService
and analyzed with the registered systemd_journal parser.
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import re
import selectors
import signal
import stat
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Sequence

from .analysis import AnalysisError, EvidenceAnalysisService, is_valid_analysis_id
from .errors import DuplicateEvidenceError, TraceeError
from .hashing import sha256_file
from .ids import is_valid_evidence_id
from .locking import exclusive_file_lock, set_private_file_permissions, set_private_permissions
from .models import EvidenceMetadata
from .services import TraceeService
from .verify import VerificationState


LOGGER = logging.getLogger(__name__)
STATE_VERSION = 2
STATE_FILENAME = "collector-state.json"
LOCK_FILENAME = ".collector.lock"
STAGED_FILENAME = "pending-batch.jsonl"
MAX_CURSOR_BYTES = 4096
DEFAULT_MAX_RECORD_BYTES = 1024 * 1024
MAX_BATCH_BYTES = 64 * 1024 * 1024


class CollectorError(Exception):
    """Safe, stable collector failure suitable for CLI display."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _format_watermark(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise CollectorError("bootstrap_clock_invalid", "The collector clock did not provide a timezone-aware UTC timestamp.")
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _parse_watermark(value: Any) -> datetime:
    if not isinstance(value, str):
        raise ValueError("invalid watermark")
    parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    if parsed.strftime("%Y-%m-%dT%H:%M:%S.%fZ") != value:
        raise ValueError("non-canonical watermark")
    return parsed


def _datetime_epoch_microseconds(value: datetime) -> int:
    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    delta = value.astimezone(timezone.utc) - epoch
    return delta.days * 86_400_000_000 + delta.seconds * 1_000_000 + delta.microseconds


Runner = Callable[..., bytes]


def _path_has_symlink(path: Path) -> bool:
    """Check every existing component without following a symlink."""
    absolute = Path(os.path.abspath(path))
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current = current / part
        try:
            if current.is_symlink():
                return True
        except OSError:
            return True
    return False


def _is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"Invalid JSON constant: {value}")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def _validate_jsonl(data: bytes, *, max_record_bytes: int) -> tuple[str, str, int]:
    """Validate exact JSONL bytes and return first/last cursor and count."""
    if not data:
        raise CollectorError("invalid_journal_output", "The journal returned an invalid empty batch.")
    if not data.endswith(b"\n"):
        raise CollectorError("invalid_journal_output", "The journal returned a record without a line terminator.")
    lines = data.splitlines(keepends=True)
    first = last = None
    seen_cursors: set[str] = set()
    for line in lines:
        raw = line[:-1]
        if raw.endswith(b"\r"):
            raw = raw[:-1]
        if not raw or len(raw) > max_record_bytes:
            raise CollectorError("record_limit_exceeded", "A journal record is empty or exceeds the configured record limit.")
        try:
            record = json.loads(raw.decode("utf-8"), parse_constant=_reject_json_constant, object_pairs_hook=_reject_duplicate_keys)
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError):
            raise CollectorError("invalid_journal_output", "The journal returned malformed JSON.") from None
        if not isinstance(record, dict):
            raise CollectorError("invalid_journal_output", "The journal returned a record that is not a JSON object.")
        cursor = record.get("__CURSOR")
        if not _valid_cursor(cursor):
            raise CollectorError("invalid_journal_cursor", "A journal record has no usable __CURSOR value.")
        if cursor in seen_cursors:
            raise CollectorError("invalid_journal_cursor", "A journal batch contains a repeated __CURSOR value.")
        seen_cursors.add(cursor)
        if first is None:
            first = cursor
        last = cursor
    assert first is not None and last is not None
    return first, last, len(lines)


def _valid_cursor(cursor: Any) -> bool:
    if not isinstance(cursor, str) or not cursor:
        return False
    try:
        return len(cursor.encode("utf-8")) <= MAX_CURSOR_BYTES and all(
            character.isprintable() and character != "\x00" for character in cursor
        )
    except UnicodeEncodeError:
        return False


def _journalctl_capture(
    args: Sequence[str], *, timeout: float, max_records: int,
    max_batch_bytes: int, max_record_bytes: int,
) -> bytes:
    """Stream the earliest journalctl JSON lines within strict bounds.

    ``--lines`` is intentionally not used for normal capture: systemd defines
    it as a most-recent-N limit, which could skip intermediate entries.
    We stop the chronological stream after the first bounded batch instead.
    """
    if sys.platform != "linux" or os.name != "posix":
        raise CollectorError("unsupported_platform", "Journal collection requires a local POSIX Linux environment.")
    try:
        process = subprocess.Popen(
            ["journalctl", *args], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            shell=False, bufsize=0,
        )
    except FileNotFoundError:
        raise CollectorError("journalctl_unavailable", "journalctl is not installed or is not available on PATH.") from None
    except PermissionError:
        raise CollectorError("journal_permission_denied", "Permission was denied while starting journalctl.") from None
    except OSError:
        raise CollectorError("journalctl_unavailable", "journalctl could not be started.") from None

    assert process.stdout is not None
    output = bytearray()
    line_buffer = bytearray()
    record_count = 0
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    deadline = time.monotonic() + timeout
    capped = False
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise CollectorError("journal_timeout", "journalctl exceeded the configured subprocess timeout.")
            if not selector.select(remaining):
                if process.poll() is not None:
                    break
                raise CollectorError("journal_timeout", "journalctl exceeded the configured subprocess timeout.")
            chunk = os.read(process.stdout.fileno(), 65536)
            if not chunk:
                break
            line_buffer.extend(chunk)
            while True:
                newline = line_buffer.find(b"\n")
                if newline < 0:
                    if len(line_buffer) > max_record_bytes + 1:
                        raise CollectorError("record_limit_exceeded", "A journal record exceeds the configured record limit.")
                    break
                line = bytes(line_buffer[:newline + 1])
                del line_buffer[:newline + 1]
                raw = line[:-1]
                if raw.endswith(b"\r"):
                    raw = raw[:-1]
                if not raw or len(raw) > max_record_bytes:
                    raise CollectorError("record_limit_exceeded", "A journal record is empty or exceeds the configured record limit.")
                try:
                    record = json.loads(raw.decode("utf-8"), parse_constant=_reject_json_constant, object_pairs_hook=_reject_duplicate_keys)
                except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError):
                    raise CollectorError("invalid_journal_output", "The journal returned malformed JSON.") from None
                if not isinstance(record, dict):
                    raise CollectorError("invalid_journal_output", "The journal returned a record that is not a JSON object.")
                cursor = record.get("__CURSOR")
                if not _valid_cursor(cursor):
                    raise CollectorError("invalid_journal_cursor", "A journal record has no usable __CURSOR value.")
                if len(output) + len(line) > max_batch_bytes:
                    if not output:
                        raise CollectorError("batch_limit_exceeded", "A journal record exceeds the configured batch byte limit.")
                    capped = True
                    break
                output.extend(line)
                record_count += 1
                if record_count >= max_records:
                    capped = True
                    break
            if capped:
                break
        if line_buffer and not capped:
            raise CollectorError("invalid_journal_output", "The journal returned a record without a line terminator.")
        if capped and process.poll() is None:
            try:
                process.terminate()
            except OSError:
                pass
        try:
            return_code = process.wait(timeout=max(0.1, min(timeout, 2.0)))
        except subprocess.TimeoutExpired:
            process.kill()
            return_code = process.wait(timeout=2.0)
        if not capped and return_code != 0:
            LOGGER.error("journalctl exited with status %s", return_code)
            raise CollectorError("journalctl_failed", "journalctl could not read the local journal; check journal read permissions.")
        return bytes(output)
    except CollectorError:
        if process.poll() is None:
            process.kill()
            process.wait()
        raise
    except BaseException:
        if process.poll() is None:
            process.kill()
            process.wait()
        raise
    finally:
        selector.close()
        process.stdout.close()


class JournalCollector:
    """One explicit operator-started local journal collector."""

    def __init__(
        self, vault_dir: str | Path, state_dir: str | Path, *,
        interval_seconds: float = 5.0, batch_size: int = 100,
        max_batch_bytes: int = 4 * 1024 * 1024,
        max_record_bytes: int = DEFAULT_MAX_RECORD_BYTES,
        subprocess_timeout: float = 15.0, initial_position: str = "tail",
        runner: Runner | None = None,
    ) -> None:
        self.vault_path = Path(vault_dir).expanduser().absolute()
        self.state_path = Path(state_dir).expanduser().absolute()
        self._validate_configuration(interval_seconds, batch_size, max_batch_bytes, max_record_bytes, subprocess_timeout, initial_position)
        if _path_has_symlink(self.vault_path) or _path_has_symlink(self.state_path):
            raise CollectorError("unsafe_path", "Vault and collector state paths must not contain symbolic links.")
        vault_resolved = self.vault_path.resolve(strict=False)
        state_resolved = self.state_path.resolve(strict=False)
        if _is_within(state_resolved, vault_resolved) or _is_within(vault_resolved, state_resolved):
            raise CollectorError("unsafe_path", "The collector state directory and evidence vault must be separate, non-nested paths.")
        self.vault_identity = str(vault_resolved)
        self.interval_seconds = interval_seconds
        self.batch_size = batch_size
        self.max_batch_bytes = max_batch_bytes
        self.max_record_bytes = max_record_bytes
        self.subprocess_timeout = subprocess_timeout
        self.initial_position = initial_position
        self.runner = runner or _journalctl_capture
        self.service = TraceeService(self.vault_path)
        self.analysis_service = EvidenceAnalysisService(self.service)
        self.state_file = self.state_path / STATE_FILENAME
        self.lock_file = self.state_path / LOCK_FILENAME
        self.staged_file = self.state_path / STAGED_FILENAME

    @staticmethod
    def _validate_configuration(interval: float, count: int, batch: int, record: int, timeout: float, position: str) -> None:
        if not isinstance(interval, (int, float)) or isinstance(interval, bool) or not math.isfinite(interval) or not 0.1 <= interval <= 3600:
            raise CollectorError("invalid_configuration", "Polling interval must be between 0.1 and 3600 seconds.")
        if not isinstance(count, int) or isinstance(count, bool) or not 1 <= count <= 10000:
            raise CollectorError("invalid_configuration", "Batch size must be between 1 and 10000 records.")
        if not isinstance(batch, int) or isinstance(batch, bool) or not 1 <= batch <= MAX_BATCH_BYTES:
            raise CollectorError("invalid_configuration", "Maximum batch bytes must be between 1 byte and 64 MiB.")
        if not isinstance(record, int) or isinstance(record, bool) or not 1 <= record <= MAX_BATCH_BYTES:
            raise CollectorError("invalid_configuration", "Maximum record bytes must be between 1 byte and 64 MiB.")
        if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or not math.isfinite(timeout) or not 0.1 <= timeout <= 300:
            raise CollectorError("invalid_configuration", "Subprocess timeout must be between 0.1 and 300 seconds.")
        if position not in {"tail", "beginning"}:
            raise CollectorError("invalid_configuration", "Initial position must be 'tail' or 'beginning'.")

    def _prepare_state_directory(self) -> None:
        if _path_has_symlink(self.state_path):
            raise CollectorError("unsafe_path", "The collector state directory must not contain symbolic links.")
        try:
            self.state_path.mkdir(mode=0o700, parents=True, exist_ok=True)
            if self.state_path.is_symlink() or not self.state_path.is_dir():
                raise OSError("not a safe directory")
            set_private_permissions(self.state_path, 0o700)
        except OSError:
            raise CollectorError("state_unavailable", "The collector state directory could not be prepared safely.") from None
        for path in (self.state_file, self.lock_file, self.staged_file, self.state_path / ".collector-state.tmp"):
            if path.is_symlink():
                raise CollectorError("unsafe_path", "A collector state or staging path is a symbolic link.")
        if self.state_path.joinpath(".collector-state.tmp").exists():
            raise CollectorError("state_recovery_required", "An incomplete collector state write was found; inspect the state directory before recovery.")
        if self.staged_file.exists() and not self.staged_file.is_file():
            raise CollectorError("unsafe_path", "The pending batch path is not a regular file.")
        # Establish the persistent lock inode during state preparation so
        # callers and competing processes can coordinate before reading state.
        # O_NOFOLLOW prevents a substituted lock symlink from being opened on
        # platforms that provide the flag; the file type is checked by fstat.
        lock_flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
        try:
            descriptor = os.open(self.lock_file, lock_flags, 0o600)
            try:
                if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                    raise OSError("lock path is not a regular file")
                set_private_file_permissions(descriptor, 0o600)
            finally:
                os.close(descriptor)
        except OSError:
            raise CollectorError("collector_lock_unavailable", "The collector lock file could not be prepared safely.") from None

    def _read_state(self) -> dict[str, Any] | None:
        if not self.state_file.exists():
            if self.staged_file.exists():
                raise CollectorError("state_recovery_required", "An unaccounted staged batch exists without collector state; no cursor will be advanced.")
            return None
        if self.state_file.is_symlink() or not self.state_file.is_file():
            raise CollectorError("unsafe_path", "The collector state file is not a regular file.")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
        try:
            descriptor = os.open(self.state_file, flags)
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                os.close(descriptor)
                raise OSError("not regular")
            with os.fdopen(descriptor, "rb") as stream:
                raw = stream.read(1024 * 1024 + 1)
            if len(raw) > 1024 * 1024:
                raise ValueError("oversized")
            state = json.loads(raw.decode("utf-8"), parse_constant=_reject_json_constant)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError):
            raise CollectorError("state_invalid", "Collector state is malformed or unreadable; do not reset it automatically.") from None
        expected = {"schema_version", "vault", "initial_position", "initialized", "committed_cursor", "bootstrap", "pending", "last_completed"}
        if not isinstance(state, dict) or set(state) != expected or state.get("schema_version") != STATE_VERSION:
            raise CollectorError("state_incompatible", "Collector state has an unsupported schema; deliberate operator recovery is required.")
        if state.get("vault") != self.vault_identity or state.get("initial_position") != self.initial_position:
            raise CollectorError("state_incompatible", "Collector state belongs to a different vault or initial-position mode.")
        if not isinstance(state.get("initialized"), bool):
            raise CollectorError("state_invalid", "Collector state has invalid initialization data.")
        cursor = state.get("committed_cursor")
        if cursor is not None and not _valid_cursor(cursor):
            raise CollectorError("state_invalid", "Collector state has an invalid committed cursor.")
        bootstrap = state.get("bootstrap")
        if bootstrap is not None:
            if (
                not isinstance(bootstrap, dict)
                or set(bootstrap) != {"phase", "since_utc"}
                or bootstrap.get("phase") not in {"probing", "since"}
                or state["initial_position"] != "tail"
                or cursor is not None
            ):
                raise CollectorError("state_invalid", "Collector empty-journal bootstrap state is invalid.")
            try:
                _parse_watermark(bootstrap.get("since_utc"))
            except (TypeError, ValueError):
                raise CollectorError("state_invalid", "Collector bootstrap watermark is malformed; no cursor will be advanced.") from None
            if bootstrap["phase"] == "probing" and (state["initialized"] or state.get("pending") is not None):
                raise CollectorError("state_invalid", "Collector bootstrap probe checkpoint is inconsistent.")
            if bootstrap["phase"] == "since" and not state["initialized"]:
                raise CollectorError("state_invalid", "Collector empty-journal checkpoint is inconsistent.")
        elif state["initial_position"] == "tail" and state["initialized"] and cursor is None:
            raise CollectorError("state_invalid", "Tail-mode checkpoint has neither a cursor nor a bootstrap watermark.")
        pending = state.get("pending")
        if pending is not None:
            keys = {"stage", "sha256", "size_bytes", "start_cursor", "first_cursor", "last_cursor", "record_count", "evidence_id", "analysis_id", "phase"}
            if not isinstance(pending, dict) or set(pending) != keys or pending.get("stage") != STAGED_FILENAME:
                raise CollectorError("state_invalid", "Collector pending-batch state has an invalid structure.")
            if pending.get("phase") not in {"staged", "acquired", "analyzed"}:
                raise CollectorError("state_invalid", "Collector pending-batch phase is invalid.")
            if pending.get("start_cursor") != cursor:
                raise CollectorError("state_invalid", "Pending batch does not begin at the committed cursor.")
            for key in ("first_cursor", "last_cursor"):
                if not _valid_cursor(pending.get(key)):
                    raise CollectorError("state_invalid", "Pending batch cursor range is invalid.")
            if not isinstance(pending.get("sha256"), str) or re.fullmatch(r"[0-9a-f]{64}", pending["sha256"]) is None or not isinstance(pending.get("size_bytes"), int) or isinstance(pending.get("size_bytes"), bool) or not 1 <= pending["size_bytes"] <= self.max_batch_bytes:
                raise CollectorError("state_invalid", "Pending batch digest or size is invalid.")
            if not isinstance(pending.get("record_count"), int) or isinstance(pending.get("record_count"), bool) or not 1 <= pending["record_count"] <= self.batch_size:
                raise CollectorError("state_invalid", "Pending batch record count is invalid.")
            if pending.get("evidence_id") is not None and (not isinstance(pending["evidence_id"], str) or not is_valid_evidence_id(pending["evidence_id"])):
                raise CollectorError("state_invalid", "Pending batch evidence ID is invalid.")
            if pending.get("analysis_id") is not None and (not isinstance(pending["analysis_id"], str) or not is_valid_analysis_id(pending["analysis_id"])):
                raise CollectorError("state_invalid", "Pending batch analysis ID is invalid.")
            if (pending["phase"] == "staged" and (pending["evidence_id"] is not None or pending["analysis_id"] is not None)) or (pending["phase"] == "acquired" and (pending["evidence_id"] is None or pending["analysis_id"] is not None)) or (pending["phase"] == "analyzed" and (pending["evidence_id"] is None or pending["analysis_id"] is None)):
                raise CollectorError("state_invalid", "Pending batch identifiers do not match its recovery phase.")
        completed = state.get("last_completed")
        if completed is not None and (not isinstance(completed, dict) or set(completed) != {"stage", "sha256", "last_cursor"} or completed.get("stage") != STAGED_FILENAME or not isinstance(completed.get("sha256"), str) or re.fullmatch(r"[0-9a-f]{64}", completed["sha256"]) is None or not _valid_cursor(completed.get("last_cursor")) or completed.get("last_cursor") != cursor):
            raise CollectorError("state_invalid", "The last completed batch marker is invalid.")
        if pending is None and self.staged_file.exists():
            completed = state.get("last_completed")
            try:
                staged_hash = sha256_file(self.staged_file)
            except OSError:
                raise CollectorError("state_recovery_required", "An unaccounted staged batch exists and cannot be inspected safely.") from None
            if completed is None or completed["sha256"] != staged_hash or completed["last_cursor"] != cursor:
                raise CollectorError("state_recovery_required", "An unaccounted staged batch exists; no cursor will be advanced.")
            self._remove_completed_stage()
        if pending is not None and not self.staged_file.exists():
            raise CollectorError("state_recovery_required", "The pending batch is missing; no cursor will be advanced.")
        return state

    def _write_state(self, state: dict[str, Any]) -> None:
        temporary = self.state_path / ".collector-state.tmp"
        if temporary.exists() or temporary.is_symlink() or self.state_file.is_symlink():
            raise CollectorError("unsafe_path", "A collector state write path is not safe.")
        data = json.dumps(state, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8") + b"\n"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
        try:
            descriptor = os.open(temporary, flags, 0o600)
            set_private_file_permissions(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.state_file)
            if os.name == "posix":
                descriptor = os.open(self.state_path, os.O_RDONLY)
                try:
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
        except OSError:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass
            raise CollectorError("state_write_failed", "Collector checkpoint could not be written durably.") from None

    def _new_state(self) -> dict[str, Any]:
        return {"schema_version": STATE_VERSION, "vault": self.vault_identity, "initial_position": self.initial_position, "initialized": False, "committed_cursor": None, "bootstrap": None, "pending": None, "last_completed": None}

    def _query(self, *, cursor: str | None, tail: bool = False, since_utc: str | None = None) -> bytes:
        args = ["--no-pager", "--output=json"]
        if tail:
            args.extend(["--lines=1"])
        elif since_utc is not None:
            try:
                _parse_watermark(since_utc)
            except (TypeError, ValueError):
                raise CollectorError("state_invalid", "Collector bootstrap watermark is malformed; no cursor will be advanced.") from None
            args.extend([f"--since={since_utc}", "--lines=all"])
        else:
            args.append("--lines=all")
            if cursor is not None:
                args.append(f"--after-cursor={cursor}")
        try:
            result = self.runner(
                args, timeout=self.subprocess_timeout,
                max_records=1 if tail else self.batch_size,
                max_batch_bytes=self.max_batch_bytes,
                max_record_bytes=self.max_record_bytes,
            )
        except CollectorError:
            raise
        except PermissionError:
            raise CollectorError("journal_permission_denied", "Permission was denied while reading the local journal.") from None
        except FileNotFoundError:
            raise CollectorError("journalctl_unavailable", "journalctl is not installed or is not available on PATH.") from None
        except (OSError, subprocess.TimeoutExpired):
            raise CollectorError("journalctl_failed", "The local journal could not be read safely.") from None
        if not isinstance(result, bytes):
            raise CollectorError("invalid_journal_output", "The journal reader returned an invalid response.")
        if result:
            if len(result) > self.max_batch_bytes or result.count(b"\n") > (1 if tail else self.batch_size):
                raise CollectorError("batch_limit_exceeded", "The journal returned more data than the configured batch limits.")
            _validate_jsonl(result, max_record_bytes=self.max_record_bytes)
        return result

    def _initialize_position(self, state: dict[str, Any]) -> dict[str, Any]:
        if state["initialized"]:
            return state
        if state["initial_position"] == "tail":
            if (state.get("bootstrap") or {}).get("phase") == "probing":
                raise CollectorError("bootstrap_recovery_required", "Tail initialization was interrupted before its boundary could be established; preserve state and recover deliberately.")
            state["bootstrap"] = {"phase": "probing", "since_utc": _format_watermark(_utc_now())}
            # The durable watermark precedes the probe. A restart that finds
            # phase=probing cannot safely infer which records were present at
            # activation, so it will fail closed instead of moving the tail.
            self._write_state(state)
            data = self._query(cursor=None, tail=True)
            if data:
                record = json.loads(data.splitlines()[0].decode("utf-8"))
                realtime = record.get("__REALTIME_TIMESTAMP")
                if not isinstance(realtime, str) or not realtime.isascii() or not realtime.isdecimal():
                    raise CollectorError("invalid_journal_timestamp", "The journal tail has no usable realtime timestamp to establish a safe tail boundary.")
                watermark = _parse_watermark(state["bootstrap"]["since_utc"])
                observed_now = _utc_now()
                if observed_now.tzinfo is None or observed_now.utcoffset() is None or observed_now.astimezone(timezone.utc) < watermark:
                    raise CollectorError("bootstrap_clock_moved", "The system clock moved behind the tail bootstrap watermark; collection is paused to avoid skipping events.")
                if int(realtime) < _datetime_epoch_microseconds(watermark):
                    state["committed_cursor"] = record["__CURSOR"]
                    state["bootstrap"] = None
                else:
                    # A record at or after activation may have arrived between
                    # persisting the watermark and probing the current tail.
                    # Preserve the watermark so the following poll acquires it.
                    state["bootstrap"]["phase"] = "since"
            else:
                state["bootstrap"]["phase"] = "since"
        state["initialized"] = True
        self._write_state(state)
        return state

    def _stage(self, data: bytes, state: dict[str, Any]) -> dict[str, Any]:
        first, last, count = _validate_jsonl(data, max_record_bytes=self.max_record_bytes)
        if len(data) > self.max_batch_bytes or count > self.batch_size:
            raise CollectorError("batch_limit_exceeded", "Journal batch exceeds configured limits.")
        if state["committed_cursor"] is not None and first == state["committed_cursor"]:
            raise CollectorError("journal_cursor_invalid", "journalctl repeated the committed cursor.")
        if self.staged_file.exists() or self.staged_file.is_symlink():
            raise CollectorError("state_recovery_required", "A staged batch already exists without matching pending state.")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
        try:
            descriptor = os.open(self.staged_file, flags, 0o600)
            set_private_file_permissions(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            if os.name == "posix":
                directory_descriptor = os.open(self.state_path, os.O_RDONLY)
                try:
                    os.fsync(directory_descriptor)
                finally:
                    os.close(directory_descriptor)
        except OSError:
            raise CollectorError("staging_failed", "The journal batch could not be staged durably.") from None
        state["pending"] = {
            "stage": STAGED_FILENAME, "sha256": hashlib.sha256(data).hexdigest(), "size_bytes": len(data),
            "start_cursor": state["committed_cursor"], "first_cursor": first, "last_cursor": last,
            "record_count": count, "evidence_id": None, "analysis_id": None, "phase": "staged",
        }
        try:
            self._write_state(state)
        except Exception:
            # Stage-without-state is detected and intentionally left for review.
            raise
        return state

    def _read_pending_bytes(self, pending: dict[str, Any]) -> bytes:
        if self.staged_file.is_symlink() or not self.staged_file.is_file():
            raise CollectorError("state_recovery_required", "The staged batch is unavailable or unsafe.")
        descriptor = -1
        try:
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
            descriptor = os.open(self.staged_file, flags)
            if not stat.S_ISREG(os.fstat(descriptor).st_mode) or os.fstat(descriptor).st_size != pending["size_bytes"]:
                raise OSError("size mismatch")
            with os.fdopen(descriptor, "rb") as stream:
                descriptor = -1
                data = stream.read(self.max_batch_bytes + 1)
            if len(data) > self.max_batch_bytes:
                raise OSError("batch too large")
        except OSError:
            raise CollectorError("state_recovery_required", "The staged batch could not be read safely.") from None
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        if hashlib.sha256(data).hexdigest() != pending["sha256"]:
            raise CollectorError("state_recovery_required", "The staged batch digest does not match its checkpoint.")
        first, last, count = _validate_jsonl(data, max_record_bytes=self.max_record_bytes)
        if (first, last, count) != (pending["first_cursor"], pending["last_cursor"], pending["record_count"]):
            raise CollectorError("state_recovery_required", "The staged batch cursor range does not match its checkpoint.")
        return data

    def _resolve_existing_duplicate(self, digest: str) -> str:
        records_dir = self.service.vault.records_dir
        if not records_dir.exists():
            raise CollectorError("acquisition_unresolved", "Duplicate acquisition was reported but no matching verified evidence record was found.")
        try:
            paths = sorted(records_dir.glob("*.json"))
        except OSError:
            raise CollectorError("acquisition_unresolved", "Existing evidence records could not be inspected to resolve duplicate acquisition.") from None
        matches: list[str] = []
        for path in paths:
            evidence_id = path.stem
            if path.is_symlink() or not path.is_file() or not is_valid_evidence_id(evidence_id):
                raise CollectorError("acquisition_unresolved", "An existing evidence record prevents safe duplicate-acquisition recovery.")
            try:
                metadata = EvidenceMetadata(**self.service.get_metadata(evidence_id))
                evidence_path = self.service.vault.evidence_path(evidence_id)
                if evidence_path.is_symlink():
                    raise OSError("unsafe evidence path")
                object_digest = sha256_file(evidence_path)
            except (Exception,):
                raise CollectorError("acquisition_unresolved", "An existing evidence record could not be validated for duplicate-acquisition recovery.") from None
            if metadata.evidence_id != evidence_id:
                raise CollectorError("acquisition_unresolved", "An existing evidence record has an inconsistent identity.")
            if object_digest == digest:
                result = self.service.verify(evidence_id)
                if result.state is not VerificationState.VALID:
                    raise CollectorError("acquisition_unresolved", "Matching evidence exists but does not pass integrity verification.")
                matches.append(evidence_id)
        if len(matches) != 1:
            raise CollectorError("acquisition_unresolved", "Duplicate acquisition could not be resolved to exactly one verified evidence record.")
        return matches[0]

    def _find_stored_analysis(self, evidence_id: str, digest: str) -> str | None:
        offset = 0
        while True:
            summaries, total = self.analysis_service.list_analyses(evidence_id, offset=offset, limit=100)
            for summary in summaries:
                if summary.get("parser") == "systemd_journal" and summary.get("source_sha256") == digest:
                    # list_analyses already validates source binding; load once
                    # more through the public boundary before relying on it.
                    self.analysis_service.load_analysis(evidence_id, summary["analysis_id"])
                    return summary["analysis_id"]
            offset += len(summaries)
            if offset >= total or not summaries:
                return None

    def _recover_pending(self, state: dict[str, Any]) -> dict[str, Any]:
        pending = state["pending"]
        if pending is None:
            return state
        self._read_pending_bytes(pending)
        if pending["evidence_id"] is None:
            try:
                metadata, _chain = self.service.ingest(self.staged_file)
                evidence_id = metadata.evidence_id
            except DuplicateEvidenceError:
                evidence_id = self._resolve_existing_duplicate(pending["sha256"])
            except TraceeError:
                raise CollectorError("acquisition_failed", "Evidence acquisition failed; the pending batch and cursor were preserved for retry.") from None
            except Exception:
                LOGGER.exception("Unexpected journal batch acquisition failure")
                raise CollectorError("acquisition_failed", "Evidence acquisition failed; the pending batch and cursor were preserved for retry.") from None
            if not is_valid_evidence_id(evidence_id):
                raise CollectorError("acquisition_unresolved", "Evidence acquisition returned an invalid evidence identifier.")
            pending["evidence_id"] = evidence_id
            pending["phase"] = "acquired"
            self._write_state(state)
        if pending["analysis_id"] is None:
            try:
                analysis_id = self._find_stored_analysis(pending["evidence_id"], pending["sha256"])
                if analysis_id is None:
                    summary = self.analysis_service.analyze(pending["evidence_id"], "systemd_journal")
                    analysis_id = summary["analysis_id"]
            except AnalysisError:
                raise CollectorError("analysis_failed", "Automatic systemd journal analysis failed; acquired evidence and the pending cursor were preserved for retry.") from None
            except Exception:
                LOGGER.exception("Unexpected journal batch analysis failure")
                raise CollectorError("analysis_failed", "Automatic systemd journal analysis failed; acquired evidence and the pending cursor were preserved for retry.") from None
            pending["analysis_id"] = analysis_id
            pending["phase"] = "analyzed"
            self._write_state(state)
        state["committed_cursor"] = pending["last_cursor"]
        state["last_completed"] = {"stage": STAGED_FILENAME, "sha256": pending["sha256"], "last_cursor": pending["last_cursor"]}
        state["pending"] = None
        state["bootstrap"] = None
        self._write_state(state)
        self._remove_completed_stage()
        LOGGER.info("Committed journal batch through cursor %s as evidence %s", pending["last_cursor"], pending["evidence_id"])
        return state

    def _remove_completed_stage(self) -> None:
        if self.staged_file.is_symlink():
            raise CollectorError("unsafe_path", "The staged batch path became a symbolic link.")
        try:
            self.staged_file.unlink(missing_ok=True)
            if os.name == "posix":
                directory_descriptor = os.open(self.state_path, os.O_RDONLY)
                try:
                    os.fsync(directory_descriptor)
                finally:
                    os.close(directory_descriptor)
        except OSError:
            raise CollectorError("stage_cleanup_failed", "A completed staged batch could not be cleaned up safely.") from None

    def run_once(self) -> int:
        """Run at most one acquisition batch (or one initialization step)."""
        self._prepare_state_directory()
        if self.lock_file.is_symlink():
            raise CollectorError("unsafe_path", "The collector lock path is a symbolic link.")
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
        try:
            descriptor = os.open(self.lock_file, flags, 0o600)
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                os.close(descriptor)
                raise OSError("not regular")
            set_private_file_permissions(descriptor, 0o600)
            with os.fdopen(descriptor, "r+b") as lock_stream:
                with exclusive_file_lock(lock_stream, lock_path=self.lock_file):
                    state = self._read_state()
                    if state is None:
                        state = self._new_state()
                        self._write_state(state)
                    was_initialized = state["initialized"]
                    state = self._initialize_position(state)
                    if not was_initialized and self.initial_position == "tail":
                        return 0
                    if state["pending"] is not None:
                        self._recover_pending(state)
                        return 1
                    bootstrap = state.get("bootstrap")
                    if bootstrap is not None:
                        watermark = _parse_watermark(bootstrap["since_utc"])
                        now = _utc_now()
                        if now.tzinfo is None or now.utcoffset() is None or now.astimezone(timezone.utc) < watermark:
                            raise CollectorError("bootstrap_clock_moved", "The system clock moved behind the empty-journal watermark; collection is paused to avoid skipping events.")
                        data = self._query(cursor=None, since_utc=bootstrap["since_utc"])
                    else:
                        data = self._query(cursor=state["committed_cursor"])
                    if not data:
                        return 0
                    state = self._stage(data, state)
                    self._recover_pending(state)
                    return 1
        except CollectorError:
            raise
        except OSError:
            raise CollectorError("collector_lock_unavailable", "Another collector may be active or the collector state could not be locked.") from None

    def run_forever(self) -> None:
        """Run continuously until SIGTERM or Ctrl+C, preserving pending state."""
        LOGGER.info("Starting explicitly requested systemd journal collection")
        if threading.current_thread() is not threading.main_thread():
            raise CollectorError("signal_handler_unavailable", "Continuous collection must run on the main thread to handle SIGTERM safely.")
        stop_requested = threading.Event()

        def request_stop(_signum: int, _frame: Any) -> None:
            # Do not raise from the signal handler: the current bounded cycle
            # must finish its acquisition, analysis, and checkpoint recovery.
            stop_requested.set()

        previous_sigterm_handler = signal.signal(signal.SIGTERM, request_stop)
        try:
            while not stop_requested.is_set():
                self.run_once()
                if not stop_requested.is_set():
                    stop_requested.wait(self.interval_seconds)
        except KeyboardInterrupt:
            LOGGER.info("Collector stopped; any pending batch remains checkpointed for restart")
        except CollectorError as exc:
            LOGGER.error("Journal collector stopped (%s): %s", exc.code, exc.message)
            raise
        finally:
            signal.signal(signal.SIGTERM, previous_sigterm_handler)
