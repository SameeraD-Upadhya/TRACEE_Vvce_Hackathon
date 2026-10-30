import json
from pathlib import Path

import pytest

from parsers.registry import get_parsers
from parsers.windows_event import (
    ENVELOPE_SCHEMA_VERSION,
    EVENT_NAMESPACE,
    SOURCE_TYPE,
    WindowsEventParser,
    serialize_windows_event_xml,
)
from tracee.analysis import EvidenceAnalysisService
from tracee.services import TraceeService


def _xml(
    *,
    timestamp="2026-10-18T10:30:40.1234567Z",
    event_id="4624",
    record_id="91",
    host="WS-01",
    channel="Security",
    provider_name="Microsoft-Windows-Security-Auditing",
    provider_guid="{54849625-5478-4994-A5BA-3E3B0328C30D}",
    extra="<EventData><Data Name=\"SubjectUserName\">Jörg &amp; analyst</Data><Data Name=\"UnknownFutureField\">kept</Data></EventData>",
):
    n = EVENT_NAMESPACE
    provider_attrs = ""
    if provider_name is not None:
        provider_attrs += f' Name="{provider_name}"'
    if provider_guid is not None:
        provider_attrs += f' Guid="{provider_guid}"'
    system_fields = (
        (f"<TimeCreated SystemTime=\"{timestamp}\"/>" if timestamp is not None else "")
        + (f"<Channel>{channel}</Channel>" if channel is not None else "")
        + (f"<Computer>{host}</Computer>" if host is not None else "")
    )
    record_element = (
        f"<EventRecordID>{record_id}</EventRecordID>"
        if record_id is not None
        else ""
    )
    return (
        f'<Event xmlns="{n}"><System><Provider{provider_attrs}/>'
        f"<EventID>{event_id}</EventID>{record_element}{system_fields}</System>{extra}</Event>"
    )


def _envelope(**overrides):
    event_xml = overrides.pop("event_xml", _xml())
    timestamp_raw = overrides.pop("timestamp_raw", "2026-10-18T10:30:40.1234567Z")
    record = {
        "schema_version": ENVELOPE_SCHEMA_VERSION,
        "source_type": SOURCE_TYPE,
        "host": "WS-01",
        "channel": "Security",
        "provider": {
            "name": "Microsoft-Windows-Security-Auditing",
            "guid": "{54849625-5478-4994-A5BA-3E3B0328C30D}",
        },
        "event_id": 4624,
        "record_id": 91,
        "timestamp": {
            "raw": timestamp_raw,
            "normalized_utc": "2026-10-18T10:30:40.123456Z",
        },
        "event_xml": event_xml,
    }
    record.update(overrides)
    return record


def _line(record=None):
    return json.dumps(record or _envelope(), ensure_ascii=False, separators=(",", ":"))


def test_windows_event_parser_preserves_provenance_unicode_and_extra_xml_data():
    parsed = WindowsEventParser().parse_line(_line())
    assert parsed is not None
    assert parsed["event_type"] == "windows_event"
    assert parsed["timestamp"] == "2026-10-18T10:30:40.1234567Z"
    attrs = parsed["attributes"]
    assert attrs["source_type"] == "windows_event_log"
    assert attrs["host"] == "WS-01"
    assert attrs["channel"] == "Security"
    assert attrs["provider_name"] == "Microsoft-Windows-Security-Auditing"
    assert attrs["provider_guid"] == "{54849625-5478-4994-A5BA-3E3B0328C30D}"
    assert attrs["event_id"] == 4624
    assert attrs["record_id"] == 91
    assert attrs["timestamp_normalized_utc"] == "2026-10-18T10:30:40.123456Z"
    assert "Jörg &amp; analyst" in attrs["event_xml"]
    assert "UnknownFutureField" in attrs["event_xml"]


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("2026-10-18T10:30:40.1200000Z", "2026-10-18T10:30:40.120000Z"),
        ("2026-10-18T12:30:40.1234567+02:00", "2026-10-18T10:30:40.123456Z"),
    ],
)
def test_timestamp_preserves_source_precision_and_validates_utc(raw, expected):
    xml = _xml(timestamp=raw)
    record = _envelope(
        event_xml=xml,
        timestamp_raw=raw,
        timestamp={"raw": raw, "normalized_utc": expected},
    )
    assert WindowsEventParser().parse_line(_line(record))["attributes"]["timestamp_normalized_utc"] == expected


@pytest.mark.parametrize("raw", [None, "2026-10-18T10:30:40"])
def test_missing_and_timezone_unknown_timestamps_are_not_assumed_utc(raw):
    xml = _xml(timestamp=raw)
    record = _envelope(
        event_xml=xml,
        timestamp_raw=raw,
        timestamp={"raw": raw, "normalized_utc": None},
    )
    parsed = WindowsEventParser().parse_line(_line(record))
    assert parsed is not None
    assert parsed["attributes"]["timestamp_normalized_utc"] is None


def test_missing_optional_fields_and_record_id_are_explicitly_null():
    xml = _xml(
        record_id=None,
        host=None,
        channel=None,
        provider_name=None,
        provider_guid=None,
    )
    record = _envelope(
        event_xml=xml,
        host=None,
        channel=None,
        provider={"name": None, "guid": None},
        record_id=None,
    )
    parsed = WindowsEventParser().parse_line(_line(record))
    assert parsed is not None
    assert parsed["attributes"]["record_id"] is None
    assert parsed["attributes"]["host"] is None
    assert parsed["attributes"]["channel"] is None
    assert parsed["attributes"]["provider_name"] is None
    assert parsed["attributes"]["provider_guid"] is None
    _, serialized = serialize_windows_event_xml(xml)
    assert serialized["record_id"] is None


def test_serializer_preserves_standard_event_record_id_and_xml_provenance():
    xml = _xml(record_id="140313", provider_guid=None)

    jsonl, envelope = serialize_windows_event_xml(xml)
    parsed = WindowsEventParser().parse_line(jsonl.decode("utf-8").strip())

    assert envelope["record_id"] == 140313
    assert envelope["provider"]["guid"] is None
    assert envelope["event_xml"] == xml
    assert parsed is not None
    assert parsed["attributes"]["record_id"] == 140313
    assert parsed["attributes"]["provider_guid"] is None


def test_serializer_keeps_compatibility_with_earlier_system_record_id_attribute():
    legacy_xml = (
        _xml(record_id="91")
        .replace("<System>", '<System EventRecordID="91">')
        .replace("<EventRecordID>91</EventRecordID>", "")
    )
    _, envelope = serialize_windows_event_xml(legacy_xml)
    assert envelope["record_id"] == 91


def test_empty_event_record_id_element_is_rejected():
    with pytest.raises(ValueError, match="malformed"):
        serialize_windows_event_xml(_xml(record_id=""))


def test_native_record_id_fallback_and_conflict_validation():
    xml_without_id = _xml(record_id=None, provider_guid=None)
    _, fallback = serialize_windows_event_xml(
        xml_without_id,
        native_record_id=140313,
    )
    assert fallback["record_id"] == 140313
    assert WindowsEventParser().parse_line(
        json.dumps(fallback, ensure_ascii=False, separators=(",", ":"))
    ) is not None

    with pytest.raises(ValueError, match="conflicts"):
        serialize_windows_event_xml(_xml(record_id="140313"), native_record_id=140314)


@pytest.mark.parametrize(
    "line",
    [
        "{",
        _line(_envelope(schema_version="2.0")),
        _line(_envelope(event_id=4625)),
        _line(_envelope(record_id=92)),
        _line(_envelope(host="OTHER")),
        _line(_envelope(channel="System")),
        _line(_envelope(provider={"name": "Other", "guid": "{54849625-5478-4994-A5BA-3E3B0328C30D}"})),
        _line(_envelope(timestamp={"raw": "2026-10-18T10:30:40.1234567Z", "normalized_utc": "2026-10-18T10:30:40Z"})),
        _line(_envelope(event_xml="<Event")),
        _line(_envelope(event_xml=f'<!DOCTYPE x [<!ENTITY e SYSTEM "file:///secret">]><Event xmlns="{EVENT_NAMESPACE}"/>')),
        _line(_envelope(event_xml=_xml(event_id=""))),
    ],
)
def test_malformed_unsupported_and_inconsistent_records_are_rejected(line):
    assert WindowsEventParser().parse_line(line) is None


@pytest.mark.parametrize("field", ["source_type", "event_id", "provider", "timestamp", "event_xml"])
def test_missing_required_envelope_fields_are_rejected(field):
    record = _envelope()
    record.pop(field)
    assert WindowsEventParser().parse_line(_line(record)) is None


def test_oversized_event_xml_and_envelope_are_rejected():
    xml = _xml(extra=f"<EventData><Data>{'x' * (12 * 1024)}</Data></EventData>")
    assert WindowsEventParser().parse_line(_line(_envelope(event_xml=xml))) is None
    oversized = _line(_envelope()) + (" " * (16 * 1024))
    assert WindowsEventParser().parse_line(oversized) is None


def test_windows_parser_detection_and_existing_json_event_detection_are_distinct():
    parser = WindowsEventParser()
    line = _line()
    assert parser.can_parse(Path("event.jsonl"), [line])
    assert not parser.can_parse(Path("event.jsonl"), ['{"timestamp":"2026-01-01T00:00:00Z","event_type":"login"}'])
    assert any(isinstance(item, WindowsEventParser) for item in get_parsers())


def test_windows_envelopes_integrate_with_analysis_and_keep_line_provenance(tmp_path):
    source = tmp_path / "synthetic-windows-events.jsonl"
    records = [
        _envelope(),
        _envelope(
            event_xml=_xml(
                timestamp="2026-10-18T12:30:40.1234567+02:00",
                event_id="4634",
                record_id="92",
                extra="<EventData><Data Name=\"Session\">退出</Data></EventData>",
            ),
            event_id=4634,
            record_id=92,
            timestamp_raw="2026-10-18T12:30:40.1234567+02:00",
            timestamp={
                "raw": "2026-10-18T12:30:40.1234567+02:00",
                "normalized_utc": "2026-10-18T10:30:40.123456Z",
            },
        ),
    ]
    source.write_text("\n".join(_line(record) for record in records) + "\n", encoding="utf-8")
    service = TraceeService(tmp_path / "vault")
    metadata, _ = service.ingest(source)
    analyzer = EvidenceAnalysisService(service)
    summary = analyzer.analyze(metadata.evidence_id, "windows_event")
    result = analyzer.get_analysis(
        metadata.evidence_id, summary["analysis_id"], offset=0, limit=10,
    )

    assert summary["parser"] == "windows_event"
    assert summary["event_count"] == 2
    assert [item["source_locator"] for item in result["observations"]] == ["line:1", "line:2"]
    assert result["events"][0]["event_type"] == "windows_event"
    assert result["events"][0]["attributes"]["record_id"] == 91
    assert "UnknownFutureField" in result["events"][0]["attributes"]["event_xml"]
    first = result["observations"][0]
    assert first["source_type"] == "windows_event"
    assert first["attributes"]["source_type"] == "windows_event_log"
    assert first["attributes"]["record_id"] == 91
    assert first["timestamp"]["raw_value"] == "2026-10-18T10:30:40.1234567Z"
    assert first["timestamp"]["normalized_extent"]["earliest_utc"] == "2026-10-18T10:30:40.123456Z"
    second = result["observations"][1]
    assert second["timestamp"]["normalized_extent"]["earliest_utc"] == "2026-10-18T10:30:40.123456Z"
    assert "退出" in second["attributes"]["event_xml"]
    assert analyzer.get_analysis(metadata.evidence_id, summary["analysis_id"], offset=0, limit=10)["event_count"] == 2


def test_invalid_windows_envelope_uses_existing_bounded_record_diagnostics(tmp_path):
    source = tmp_path / "synthetic-windows-events.jsonl"
    source.write_text(
        _line() + "\n" + _line(_envelope(schema_version="9.0")) + "\n{\n",
        encoding="utf-8",
    )
    service = TraceeService(tmp_path / "vault")
    metadata, _ = service.ingest(source)
    analyzer = EvidenceAnalysisService(service)
    summary = analyzer.analyze(metadata.evidence_id, "windows_event")
    assert summary["event_count"] == 1
    assert summary["diagnostics"]["malformed_lines"] == 2
    assert summary["diagnostics"]["issues"] == [
        {"line_number": 2, "code": "unsupported_record"},
        {"line_number": 3, "code": "unsupported_record"},
    ]


def test_invalid_source_timestamp_remains_visible_as_partial_observation(tmp_path):
    raw_timestamp = "not-a-Windows-timestamp"
    record = _envelope(
        event_xml=_xml(timestamp=raw_timestamp),
        timestamp_raw=raw_timestamp,
        timestamp={"raw": raw_timestamp, "normalized_utc": None},
    )
    source = tmp_path / "synthetic-windows-event.jsonl"
    source.write_text(_line(record) + "\n", encoding="utf-8")
    service = TraceeService(tmp_path / "vault")
    metadata, _ = service.ingest(source)
    analyzer = EvidenceAnalysisService(service)
    summary = analyzer.analyze(metadata.evidence_id, "windows_event")
    result = analyzer.get_analysis(
        metadata.evidence_id, summary["analysis_id"], offset=0, limit=10,
    )
    assert summary["event_count"] == 1
    assert summary["diagnostics"]["partial_records"] == 1
    assert result["observations"][0]["timestamp"]["raw_value"] == raw_timestamp
    assert result["observations"][0]["timestamp"]["normalized_extent"] == {
        "earliest_utc": None,
        "latest_utc": None,
    }
