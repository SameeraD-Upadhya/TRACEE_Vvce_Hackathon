"""Parser for TRACEE's versioned Windows Event Log JSONL envelope.

This module parses static evidence only. It has no Windows API dependencies.
The embedded event XML is retained verbatim as a provenance attribute.
"""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .base import BaseParser


ENVELOPE_SCHEMA_VERSION = "1.0"
SOURCE_TYPE = "windows_event_log"
EVENT_XML_MAX_BYTES = 12 * 1024
ENVELOPE_MAX_BYTES = 16 * 1024
MAX_EVENT_ID = (1 << 16) - 1
MAX_RECORD_ID = (1 << 64) - 1
EVENT_NAMESPACE = "http://schemas.microsoft.com/win/2004/08/events/event"
_FORBIDDEN_XML_DECLARATION = re.compile(r"<!\s*(?:DOCTYPE|ENTITY)\b", re.IGNORECASE)


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-standard JSON constant: {value}")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _json_object(line: str) -> dict[str, Any] | None:
    try:
        value = json.loads(
            line,
            parse_constant=_reject_constant,
            object_pairs_hook=_unique_object,
        )
    except (json.JSONDecodeError, RecursionError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def _normalized_utc(raw: str | None) -> str | None:
    if raw is None or not raw:
        return None
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except (ValueError, OverflowError):
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    return parsed.astimezone(timezone.utc).isoformat(
        timespec="microseconds"
    ).replace("+00:00", "Z")


def _integer_text(value: str | None, *, required: bool) -> int | None:
    if value is None:
        if required:
            raise ValueError("missing integer field")
        return None
    stripped = value.strip()
    if not stripped or not stripped.isascii() or not stripped.isdecimal():
        raise ValueError("invalid integer field")
    return int(stripped)


def _optional_string(value: Any) -> bool:
    return value is None or isinstance(value, str)


def _single_child(parent: ET.Element, tag: str) -> ET.Element | None | bool:
    matches = parent.findall(tag)
    if len(matches) > 1:
        return False
    return matches[0] if matches else None


def _extract_event_xml_fields(xml_text: str) -> dict[str, Any] | None:
    if not isinstance(xml_text, str) or not xml_text:
        return None
    try:
        if len(xml_text.encode("utf-8")) > EVENT_XML_MAX_BYTES:
            return None
    except UnicodeEncodeError:
        return None
    if _FORBIDDEN_XML_DECLARATION.search(xml_text):
        return None
    try:
        root = ET.fromstring(xml_text)
    except (ET.ParseError, RecursionError, ValueError):
        return None
    if root.tag != f"{{{EVENT_NAMESPACE}}}Event":
        return None
    system = _single_child(root, f"{{{EVENT_NAMESPACE}}}System")
    if system is None or system is False:
        return None
    provider_xml = _single_child(system, f"{{{EVENT_NAMESPACE}}}Provider")
    event_id_xml = _single_child(system, f"{{{EVENT_NAMESPACE}}}EventID")
    channel_xml = _single_child(system, f"{{{EVENT_NAMESPACE}}}Channel")
    computer_xml = _single_child(system, f"{{{EVENT_NAMESPACE}}}Computer")
    time_xml = _single_child(system, f"{{{EVENT_NAMESPACE}}}TimeCreated")
    if any(item is False for item in (provider_xml, event_id_xml, channel_xml, computer_xml, time_xml)):
        return None
    record_id_element = _single_child(system, f"{{{EVENT_NAMESPACE}}}EventRecordID")
    if record_id_element is False:
        return None
    # Windows renders EventRecordID as a System child element. Retain support
    # for the earlier envelope fixture form that encoded it as an attribute.
    record_id_attribute = system.get("EventRecordID")
    record_id_text = (
        None if record_id_element is None else record_id_element.text
    )
    raw_time_xml = None if time_xml is None else time_xml.get("SystemTime")
    provider_name_xml = None if provider_xml is None else provider_xml.get("Name")
    provider_guid_xml = None if provider_xml is None else provider_xml.get("Guid")
    try:
        event_id_xml_value = _integer_text(
            None if event_id_xml is None else event_id_xml.text,
            required=True,
        )
        record_id_xml_value = _integer_text(
            record_id_text,
            required=record_id_element is not None,
        )
        record_id_attribute_value = _integer_text(
            record_id_attribute,
            required=False,
        )
    except ValueError:
        return None
    if (
        event_id_xml_value is None or event_id_xml_value > MAX_EVENT_ID
        or (record_id_xml_value is not None and record_id_xml_value > MAX_RECORD_ID)
        or (record_id_attribute_value is not None and record_id_attribute_value > MAX_RECORD_ID)
        or (
            record_id_xml_value is not None
            and record_id_attribute_value is not None
            and record_id_xml_value != record_id_attribute_value
        )
    ):
        return None
    channel_value = None if channel_xml is None else (channel_xml.text or "")
    computer_value = None if computer_xml is None else (computer_xml.text or "")
    return {
        "host": computer_value,
        "channel": channel_value,
        "provider": {"name": provider_name_xml, "guid": provider_guid_xml},
        "event_id": event_id_xml_value,
        "record_id": (
            record_id_xml_value
            if record_id_xml_value is not None
            else record_id_attribute_value
        ),
        "timestamp": {
            "raw": raw_time_xml,
            "normalized_utc": _normalized_utc(raw_time_xml),
        },
        "event_xml": xml_text,
    }


def _validate_envelope(record: dict[str, Any]) -> dict[str, Any] | None:
    required = {
        "schema_version", "source_type", "host", "channel", "provider",
        "event_id", "record_id", "timestamp", "event_xml",
    }
    if set(record) != required:
        return None
    if record.get("schema_version") != ENVELOPE_SCHEMA_VERSION:
        return None
    if record.get("source_type") != SOURCE_TYPE:
        return None
    if not _optional_string(record.get("host")) or not _optional_string(record.get("channel")):
        return None
    provider = record.get("provider")
    if not isinstance(provider, dict) or set(provider) != {"name", "guid"}:
        return None
    if not _optional_string(provider.get("name")) or not _optional_string(provider.get("guid")):
        return None
    event_id = record.get("event_id")
    record_id = record.get("record_id")
    if (
        not isinstance(event_id, int) or isinstance(event_id, bool)
        or event_id < 0 or event_id > MAX_EVENT_ID
    ):
        return None
    if record_id is not None and (
        not isinstance(record_id, int) or isinstance(record_id, bool)
        or record_id < 0 or record_id > MAX_RECORD_ID
    ):
        return None
    timestamp = record.get("timestamp")
    if not isinstance(timestamp, dict) or set(timestamp) != {"raw", "normalized_utc"}:
        return None
    raw_time = timestamp.get("raw")
    normalized = timestamp.get("normalized_utc")
    if not _optional_string(raw_time) or not _optional_string(normalized):
        return None
    if normalized != _normalized_utc(raw_time):
        return None
    xml_fields = _extract_event_xml_fields(record.get("event_xml"))
    if xml_fields is None:
        return None
    if any(record.get(field) != xml_fields[field] for field in (
        "host", "channel", "provider", "event_id", "timestamp", "event_xml",
    )):
        return None
    if (
        xml_fields["record_id"] is not None
        and record.get("record_id") != xml_fields["record_id"]
    ):
        return None
    try:
        line_bytes = json.dumps(record, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    except (UnicodeEncodeError, TypeError, ValueError, RecursionError):
        return None
    if len(line_bytes) > ENVELOPE_MAX_BYTES:
        return None
    return record


def serialize_windows_event_xml(
    xml_text: str,
    *,
    native_record_id: int | None = None,
) -> tuple[bytes, dict[str, Any]]:
    """Create the canonical validated UTF-8 JSONL record for Event XML."""
    fields = _extract_event_xml_fields(xml_text)
    if fields is None:
        raise ValueError("Rendered event XML is malformed or exceeds the event size limit.")
    if native_record_id is not None:
        if (
            not isinstance(native_record_id, int)
            or isinstance(native_record_id, bool)
            or not 0 <= native_record_id <= MAX_RECORD_ID
        ):
            raise ValueError("Native event record ID is outside the supported unsigned 64-bit range.")
        if fields["record_id"] is not None and fields["record_id"] != native_record_id:
            raise ValueError("Native event record ID conflicts with the rendered event XML.")
        if fields["record_id"] is None:
            fields["record_id"] = native_record_id
    envelope = {
        "schema_version": ENVELOPE_SCHEMA_VERSION,
        "source_type": SOURCE_TYPE,
        **fields,
    }
    if _validate_envelope(envelope) is None:
        raise ValueError("Rendered event XML cannot be represented by the Windows event envelope.")
    line = json.dumps(envelope, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n"
    return line, envelope


class WindowsEventParser(BaseParser):
    """Validate and normalize one Windows Event Log JSONL envelope."""

    name = "windows_event"

    def can_parse(self, file_path: Path, sample_lines: list[str]) -> bool:
        del file_path
        for line in sample_lines:
            if not line.strip():
                continue
            record = _json_object(line)
            if record is not None and record.get("source_type") == SOURCE_TYPE:
                return True
        return False

    def parse_line(self, line: str) -> dict[str, Any] | None:
        try:
            if len(line.encode("utf-8")) > ENVELOPE_MAX_BYTES:
                return None
        except UnicodeEncodeError:
            return None
        record = _json_object(line)
        if record is None:
            return None
        record = _validate_envelope(record)
        if record is None:
            return None
        provider = record["provider"]
        timestamp = record["timestamp"]
        attributes = {
            "envelope_schema_version": record["schema_version"],
            "source_type": record["source_type"],
            "host": record["host"],
            "channel": record["channel"],
            "provider_name": provider["name"],
            "provider_guid": provider["guid"],
            "event_id": record["event_id"],
            "record_id": record["record_id"],
            "timestamp_raw": timestamp["raw"],
            "timestamp_normalized_utc": timestamp["normalized_utc"],
            "event_xml": record["event_xml"],
        }
        return {
            "timestamp": timestamp["raw"] if isinstance(timestamp["raw"], str) and timestamp["raw"].strip() else None,
            "event_type": "windows_event",
            "attributes": attributes,
        }
