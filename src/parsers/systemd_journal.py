"""Conservative parser for one-record-per-line ``journalctl --output=json`` data.

Only the documented journal fields below are promoted into normalized
attributes. The original acquired bytes remain the authoritative source.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .base import BaseParser


JOURNAL_MARKERS = frozenset({
    "__CURSOR", "__REALTIME_TIMESTAMP", "__MONOTONIC_TIMESTAMP", "_BOOT_ID",
})
ATTRIBUTE_FIELDS = {
    "MESSAGE": ("message", 4096),
    "PRIORITY": ("priority", 64),
    "_SYSTEMD_UNIT": ("systemd_unit", 512),
    "SYSLOG_IDENTIFIER": ("syslog_identifier", 512),
    "_PID": ("pid", 64),
    "_UID": ("uid", 64),
    "_GID": ("gid", 64),
    "_COMM": ("comm", 512),
    "_EXE": ("exe", 1024),
    "_HOSTNAME": ("hostname", 512),
    "_BOOT_ID": ("boot_id", 128),
    "__CURSOR": ("journal_cursor", 1024),
    "__MONOTONIC_TIMESTAMP": ("monotonic_timestamp_us", 64),
    "__REALTIME_TIMESTAMP": ("journal_realtime_timestamp_us", 64),
}
MAX_MESSAGE_BYTES = 4096
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-standard JSON constant: {value}")


def _journal_object(line: str) -> dict[str, Any] | None:
    try:
        record = json.loads(line, parse_constant=_reject_constant)
    except (json.JSONDecodeError, RecursionError, ValueError):
        return None
    if not isinstance(record, dict) or not JOURNAL_MARKERS.intersection(record):
        return None
    return record


def _text_value(value: str, maximum: int) -> str | dict[str, Any]:
    if len(value) <= maximum:
        return value
    return {"value": value[:maximum], "truncated": True, "original_length": len(value)}


def _safe_attribute(value: Any, maximum: int) -> Any:
    if isinstance(value, str):
        return _text_value(value, maximum)
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value if value.bit_length() <= 63 else _text_value(str(value), maximum)
    return {"value_type": type(value).__name__}


def _message_value(value: Any) -> Any:
    if isinstance(value, str):
        return _text_value(value, MAX_MESSAGE_BYTES)
    if isinstance(value, list) and all(
        isinstance(item, int) and not isinstance(item, bool) and 0 <= item <= 255
        for item in value
    ):
        clipped = value[:MAX_MESSAGE_BYTES]
        return {
            "encoding": "byte_array",
            "bytes": clipped,
            "byte_length": len(value),
            "truncated": len(value) > len(clipped),
        }
    if value is None:
        return None
    return {"encoding": "unsupported", "json_type": type(value).__name__}


def _normalized_realtime(value: Any) -> str | None:
    """Convert nonnegative epoch microseconds exactly, without local time or float."""
    if isinstance(value, int) and not isinstance(value, bool):
        microseconds = value
    elif isinstance(value, str) and value.isascii() and value.isdecimal():
        try:
            microseconds = int(value)
        except ValueError:
            return None
    else:
        return None
    if microseconds < 0:
        return None
    try:
        instant = _EPOCH + timedelta(microseconds=microseconds)
    except (OverflowError, ValueError):
        return None
    return instant.isoformat(timespec="microseconds").replace("+00:00", "Z")


class SystemdJournalParser(BaseParser):
    """Read JSON records containing journal-specific systemd metadata."""

    name = "systemd_journal"

    def can_parse(self, file_path: Path, sample_lines: list[str]) -> bool:
        del file_path
        return any(_journal_object(line) is not None for line in sample_lines if line.strip())

    def parse_line(self, line: str) -> dict[str, Any] | None:
        record = _journal_object(line)
        if record is None:
            return None
        attributes: dict[str, Any] = {}
        for source_name, (attribute_name, maximum) in ATTRIBUTE_FIELDS.items():
            if source_name not in record:
                continue
            value = record[source_name]
            if source_name == "MESSAGE":
                attributes[attribute_name] = _message_value(value)
            else:
                attributes[attribute_name] = _safe_attribute(value, maximum)
        return {
            "timestamp": _normalized_realtime(record.get("__REALTIME_TIMESTAMP")),
            "event_type": "journal_entry",
            "attributes": attributes,
        }
