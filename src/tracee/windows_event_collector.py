"""One-shot acquisition of a bounded batch from a local Windows Event Log.

The native pywin32 dependency is loaded only when collection is explicitly
requested on Windows. Tests and other callers may supply a native API adapter;
all evidence still goes through the regular TRACEE ingest and verification
services.
"""

from __future__ import annotations

import os
import errno
import json
import logging
import sys
import tempfile
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from parsers.windows_event import (
    ENVELOPE_MAX_BYTES,
    MAX_EVENT_ID,
    serialize_windows_event_xml,
)

from .activity import ActivityLog, ActivityLogError
from .errors import DuplicateEvidenceError, TraceeError
from .locking import set_private_permissions
from .services import TraceeService
from .verify import VerificationState


SUPPORTED_CHANNELS = ("Application", "System")
DEFAULT_MAX_RECORDS = 100
MAX_RECORDS = 1000
DEFAULT_MAX_RECORD_BYTES = ENVELOPE_MAX_BYTES
MAX_RECORD_BYTES = ENVELOPE_MAX_BYTES
DEFAULT_MAX_BATCH_BYTES = 1024 * 1024
MAX_BATCH_BYTES = 16 * 1024 * 1024
MAX_PROVIDER_NAME_LENGTH = 256
MAX_WINDOWS_EVENT_ID = MAX_EVENT_ID
_ACTIVITY_ACTOR = "local_cli"
_DIAGNOSTICS_ENV = "TRACEE_WINDOWS_COLLECTOR_DIAGNOSTICS"
_logger = logging.getLogger(__name__)


def _diagnostic_error_detail(error: BaseException) -> str | None:
    """Return a fixed, path-free description for common local storage errors."""
    winerror = getattr(error, "winerror", None)
    if isinstance(winerror, int):
        return {
            2: "The file was not found.",
            3: "The directory was not found.",
            5: "Access is denied.",
            32: "The file is in use by another process.",
            80: "A file with the same name already exists.",
            183: "A file with the same name already exists.",
        }.get(winerror)
    error_number = getattr(error, "errno", None)
    return {
        errno.EACCES: "Access is denied.",
        errno.EPERM: "The operation is not permitted.",
        errno.ENOENT: "The file or directory was not found.",
        errno.EEXIST: "A file with the same name already exists.",
        errno.ENOSPC: "The storage device is full.",
        errno.EBUSY: "The resource is in use.",
    }.get(error_number)


def _log_storage_diagnostic(stage: str, error: BaseException) -> None:
    """Emit opt-in, path-free diagnostics without affecting the collection result."""
    if os.environ.get(_DIAGNOSTICS_ENV) != "1":
        return
    try:
        error_code = getattr(error, "code", None)
        if not (
            isinstance(error_code, str)
            and error_code.isascii()
            and error_code.replace("_", "").isalnum()
            and len(error_code) <= 64
        ):
            error_code = None
        exit_code = getattr(error, "exit_code", None)
        if not isinstance(exit_code, int):
            exit_code = None
        diagnostic = {
            "stage": stage,
            "exception_type": type(error).__name__,
            "error_code": error_code,
            "exit_code": exit_code,
            "errno": getattr(error, "errno", None)
            if isinstance(getattr(error, "errno", None), int)
            else None,
            "winerror": getattr(error, "winerror", None)
            if isinstance(getattr(error, "winerror", None), int)
            else None,
            "detail": _diagnostic_error_detail(error),
        }
        _logger.error(
            "TRACEE Windows collector diagnostic %s",
            json.dumps(diagnostic, sort_keys=True, separators=(",", ":")),
            extra={"tracee_windows_collector_diagnostic": diagnostic},
        )
    except BaseException:
        # Diagnostics are best-effort and must never mask the original failure.
        return


class WindowsCollectorError(Exception):
    """Safe collection error suitable for CLI display and activity records."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class NativeEventLogApi(Protocol):
    """Small adapter boundary around the Windows Event Log API."""

    def open_query(
        self,
        channel: str,
        provider_name: str | None = None,
        event_id: int | None = None,
    ) -> Any: ...
    def next_events(self, query_handle: Any, count: int) -> Any: ...
    def render_xml(self, event_handle: Any) -> str: ...
    def get_record_id(self, event_handle: Any) -> int | None: ...
    def close_handle(self, handle: Any) -> None: ...


@dataclass(frozen=True)
class WindowsAcquisitionResult:
    channel: str
    record_count: int
    serialized_bytes: int
    evidence_id: str
    sha256: str
    verification_state: str
    verification_message: str


def _positive_int(value: Any, name: str, maximum: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= maximum:
        raise WindowsCollectorError(
            "invalid_configuration",
            f"{name} must be an integer from 1 to {maximum}.",
        )
    return value


def _validate_provider_name(value: Any) -> str | None:
    if value is None:
        return None
    if (
        not isinstance(value, str)
        or not value
        or len(value) > MAX_PROVIDER_NAME_LENGTH
        or value != value.strip()
        or "'" in value
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        raise WindowsCollectorError(
            "invalid_filter",
            "Provider must be a non-empty exact name of at most 256 characters; quotes and control characters are not supported.",
        )
    return value


def _validate_event_id(value: Any) -> int | None:
    if value is None:
        return None
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not 0 <= value <= MAX_WINDOWS_EVENT_ID
    ):
        raise WindowsCollectorError(
            "invalid_filter",
            f"Event ID must be an integer from 0 to {MAX_WINDOWS_EVENT_ID}.",
        )
    return value


def build_event_log_query(
    provider_name: str | None = None,
    event_id: int | None = None,
) -> str:
    """Build a constrained Event Log XPath query from validated filters."""
    provider_name = _validate_provider_name(provider_name)
    event_id = _validate_event_id(event_id)
    predicates: list[str] = []
    if provider_name is not None:
        predicates.append(f"Provider[@Name='{provider_name}']")
    if event_id is not None:
        predicates.append(f"EventID={event_id}")
    if not predicates:
        return "*"
    return "*[System[" + " and ".join(predicates) + "]]"


class _PyWin32EventLogApi:
    """Lazy local-only adapter for the pywin32 Event Log functions."""

    def __init__(self) -> None:
        try:
            import win32evtlog
        except ImportError:
            raise WindowsCollectorError(
                "dependency_missing",
                "Windows Event Log collection requires the `windows` extra (pywin32).",
            ) from None
        self._api = win32evtlog

    def open_query(
        self,
        channel: str,
        provider_name: str | None = None,
        event_id: int | None = None,
    ) -> Any:
        flags = self._api.EvtQueryChannelPath | self._api.EvtQueryReverseDirection
        query = build_event_log_query(provider_name, event_id)
        return self._api.EvtQuery(channel, flags, query)

    def next_events(self, query_handle: Any, count: int) -> Any:
        # The query is local, already available history; do not wait for new events.
        return self._api.EvtNext(query_handle, count, 0)

    def render_xml(self, event_handle: Any) -> str:
        rendered = self._api.EvtRender(event_handle, self._api.EvtRenderEventXml)
        if not isinstance(rendered, str):
            raise TypeError("EvtRender did not return event XML text")
        return rendered

    @staticmethod
    def get_record_id(event_handle: Any) -> int | None:
        # The current pywin32 EVT handle wrapper exposes Close(), not a separate
        # EventRecordID property. The rendered System XML is the available source.
        del event_handle
        return None

    @staticmethod
    def close_handle(handle: Any) -> None:
        handle.Close()


def _winerror(error: BaseException) -> int | None:
    value = getattr(error, "winerror", None)
    if not isinstance(value, int):
        args = getattr(error, "args", ())
        value = args[0] if args and isinstance(args[0], int) else None
    return value


def _native_error(error: BaseException) -> WindowsCollectorError:
    code = _winerror(error)
    if code == 5:
        return WindowsCollectorError(
            "access_denied",
            "Access to the selected local Windows Event Log channel was denied.",
        )
    if code == 15007:
        return WindowsCollectorError(
            "channel_unavailable",
            "The selected Windows Event Log channel is unavailable.",
        )
    return WindowsCollectorError(
        "collection_failed",
        "The local Windows Event Log query or rendering operation failed.",
    )


class WindowsEventLogCollector:
    """Collect the newest bounded event batch from one supported local channel."""

    def __init__(
        self,
        vault_dir: str | Path,
        *,
        native_api: NativeEventLogApi | None = None,
        max_records: int = DEFAULT_MAX_RECORDS,
        max_record_bytes: int = DEFAULT_MAX_RECORD_BYTES,
        max_batch_bytes: int = DEFAULT_MAX_BATCH_BYTES,
        provider_name: str | None = None,
        event_id: int | None = None,
    ) -> None:
        self.vault_dir = Path(vault_dir)
        self.max_records = _positive_int(max_records, "max_records", MAX_RECORDS)
        self.max_record_bytes = _positive_int(
            max_record_bytes, "max_record_bytes", MAX_RECORD_BYTES
        )
        self.max_batch_bytes = _positive_int(
            max_batch_bytes, "max_batch_bytes", MAX_BATCH_BYTES
        )
        self.provider_name = _validate_provider_name(provider_name)
        self.event_id = _validate_event_id(event_id)
        self._native_api = native_api
        self.service = TraceeService(self.vault_dir)
        self.activity = ActivityLog(self.service.vault_dir)

    def _api(self) -> NativeEventLogApi:
        if self._native_api is not None:
            return self._native_api
        if sys.platform != "win32" or os.name != "nt":
            raise WindowsCollectorError(
                "unsupported_platform",
                "Windows Event Log collection is available only on Windows.",
            )
        self._native_api = _PyWin32EventLogApi()
        return self._native_api

    def _read_newest_xml(
        self,
        channel: str,
        api: NativeEventLogApi,
    ) -> list[tuple[str, int | None]]:
        try:
            with ExitStack() as stack:
                query_handle = api.open_query(
                    channel,
                    self.provider_name,
                    self.event_id,
                )
                stack.callback(api.close_handle, query_handle)
                handles = api.next_events(query_handle, self.max_records)
                if not isinstance(handles, (tuple, list)):
                    raise TypeError("native event query returned an invalid handle collection")
                for handle in handles:
                    stack.callback(api.close_handle, handle)
                if len(handles) > self.max_records:
                    raise WindowsCollectorError(
                        "collection_failed",
                        "The native Event Log API exceeded the configured record limit.",
                    )
                xml_records: list[tuple[str, int | None]] = []
                for handle in handles:
                    xml = api.render_xml(handle)
                    if not isinstance(xml, str):
                        raise TypeError("native event rendering returned a non-text record")
                    native_record_id = api.get_record_id(handle)
                    xml_records.append((xml, native_record_id))
                return xml_records
        except WindowsCollectorError:
            raise
        except Exception as exc:
            raise _native_error(exc) from None

    def _serialize_batch(
        self,
        channel: str,
        xml_records: list[tuple[str, int | None]],
    ) -> bytes:
        if not xml_records:
            if self.provider_name is not None or self.event_id is not None:
                raise WindowsCollectorError(
                    "no_matching_events",
                    "No events matched the configured filters; no evidence was created.",
                )
            raise WindowsCollectorError(
                "no_events",
                "No events were available in the selected channel; no evidence was created.",
            )
        records: list[tuple[tuple[str, int, str], bytes]] = []
        for xml, native_record_id in xml_records:
            try:
                line, envelope = serialize_windows_event_xml(
                    xml,
                    native_record_id=native_record_id,
                )
            except (ValueError, TypeError):
                raise WindowsCollectorError(
                    "invalid_event_record",
                    "A selected event could not be represented by the supported Windows event envelope.",
                ) from None
            if envelope["channel"] != channel:
                raise WindowsCollectorError(
                    "invalid_event_record",
                    "A selected event did not report the requested channel in its source XML.",
                )
            if (
                self.provider_name is not None
                and envelope["provider"]["name"] != self.provider_name
            ) or (
                self.event_id is not None
                and envelope["event_id"] != self.event_id
            ):
                continue
            timestamp = envelope["timestamp"]
            if not timestamp["raw"] or not timestamp["normalized_utc"]:
                raise WindowsCollectorError(
                    "invalid_event_timestamp",
                    "A selected event has no valid timezone-qualified source timestamp.",
                )
            if len(line[:-1]) > self.max_record_bytes:
                raise WindowsCollectorError(
                    "size_limit_exceeded",
                    "A selected event exceeds the configured individual-record size limit.",
                )
            record_id = envelope["record_id"]
            order = (
                timestamp["normalized_utc"],
                record_id if record_id is not None else -1,
                xml,
            )
            records.append((order, line))
        if not records:
            raise WindowsCollectorError(
                "no_matching_events",
                "No events matched the configured filters; no evidence was created.",
            )
        records.sort(key=lambda item: item[0])
        data = b"".join(line for _, line in records)
        if len(data) > self.max_batch_bytes:
            raise WindowsCollectorError(
                "size_limit_exceeded",
                "The selected events exceed the configured serialized batch size limit.",
            )
        return data

    @staticmethod
    def _failure_outcome(error: WindowsCollectorError) -> str:
        return error.code

    def _append_failure(
        self,
        error: WindowsCollectorError,
        *,
        evidence_id: str | None = None,
        size_bytes: int | None = None,
        sha256: str | None = None,
    ) -> None:
        try:
            self.activity.append(
                event_type="evidence_acquisition_failed",
                actor=_ACTIVITY_ACTOR,
                outcome=self._failure_outcome(error),
                evidence_id=evidence_id,
                filename="windows-events.jsonl",
                size_bytes=size_bytes,
                sha256=sha256,
            )
        except ActivityLogError as exc:
            _log_storage_diagnostic("failure_activity_recording", exc)
            # Preserve the actual collection failure; do not expose audit internals.
            return

    def collect(self, channel: str) -> WindowsAcquisitionResult:
        if channel not in SUPPORTED_CHANNELS:
            raise WindowsCollectorError(
                "unsupported_channel",
                "Select one supported local channel: Application or System.",
            )
        api = self._api()
        stage = "vault_initialization"
        try:
            self.service.vault.initialize()
            stage = "activity_recording_started"
            self.activity.append(
                event_type="evidence_acquisition_started",
                actor=_ACTIVITY_ACTOR,
                outcome="accepted",
                filename="windows-events.jsonl",
            )
        except (TraceeError, ActivityLogError, OSError) as exc:
            _log_storage_diagnostic(stage, exc)
            raise WindowsCollectorError(
                "activity_audit_failed",
                "The local vault or activity log could not be prepared safely; no Event Log query was started.",
            ) from None

        metadata = None
        serialized_bytes = 0
        stage = "event_log_query"
        try:
            xml_records = self._read_newest_xml(channel, api)
            stage = "event_serialization"
            data = self._serialize_batch(channel, xml_records)
            serialized_bytes = len(data)
            # Keep the short-lived plaintext serialization inside the selected
            # vault, whose parent is already initialized and access-controlled.
            # The OS temp directory may be unavailable in restricted Windows
            # environments, and can have weaker access controls than the vault.
            stage = "temporary_storage_preparation"
            temporary = tempfile.TemporaryDirectory(
                prefix=".tracee-windows-events-",
                dir=self.service.vault_dir,
            )
            try:
                temporary_path = Path(temporary.name) / "windows-events.jsonl"
                with temporary_path.open("xb") as stream:
                    set_private_permissions(temporary_path, 0o600)
                    stream.write(data)
                    stream.flush()
                    os.fsync(stream.fileno())
                stage = "evidence_ingestion"
                metadata, _ = self.service.ingest(temporary_path)
            finally:
                if sys.exc_info()[0] is None:
                    stage = "temporary_storage_cleanup"
                temporary.cleanup()

            stage = "evidence_verification"
            verification = self.service.verify(metadata.evidence_id)
            if verification.state is not VerificationState.VALID:
                raise WindowsCollectorError(
                    "integrity_verification_failed",
                    "The ingested Windows event evidence did not pass integrity verification.",
                )
        except WindowsCollectorError as exc:
            self._append_failure(
                exc,
                evidence_id=metadata.evidence_id if metadata else None,
                size_bytes=serialized_bytes or None,
                sha256=metadata.sha256 if metadata else None,
            )
            raise
        except DuplicateEvidenceError:
            error = WindowsCollectorError(
                "duplicate_evidence",
                "An identical Windows event batch is already present in this vault.",
            )
            self._append_failure(error, size_bytes=serialized_bytes or None)
            raise error from None
        except (TraceeError, OSError, ActivityLogError) as exc:
            _log_storage_diagnostic(stage, exc)
            error = WindowsCollectorError(
                "storage_failure",
                "The Windows event batch could not be safely ingested, verified, or audited.",
            )
            self._append_failure(
                error,
                evidence_id=metadata.evidence_id if metadata else None,
                size_bytes=serialized_bytes or None,
                sha256=metadata.sha256 if metadata else None,
            )
            raise error from None
        except Exception:
            error = WindowsCollectorError(
                "internal_error",
                "An unexpected local acquisition error occurred; no successful acquisition is reported.",
            )
            self._append_failure(
                error,
                evidence_id=metadata.evidence_id if metadata else None,
                size_bytes=serialized_bytes or None,
                sha256=metadata.sha256 if metadata else None,
            )
            raise error from None

        try:
            self.activity.append(
                event_type="evidence_acquired",
                actor=_ACTIVITY_ACTOR,
                outcome="success",
                evidence_id=metadata.evidence_id,
                filename="windows-events.jsonl",
                size_bytes=metadata.size_bytes,
                sha256=metadata.sha256,
            )
        except ActivityLogError as exc:
            _log_storage_diagnostic("activity_recording_completed", exc)
            raise WindowsCollectorError(
                "activity_audit_failed",
                f"Evidence {metadata.evidence_id} was stored and verified, but acquisition completion could not be recorded in activity history.",
            ) from None

        return WindowsAcquisitionResult(
            channel=channel,
            record_count=len(xml_records),
            serialized_bytes=serialized_bytes,
            evidence_id=metadata.evidence_id,
            sha256=metadata.sha256,
            verification_state=verification.state.value,
            verification_message=verification.message,
        )
