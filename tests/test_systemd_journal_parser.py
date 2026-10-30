import json
from pathlib import Path

import pytest

from parsers.registry import get_parsers
from parsers.systemd_journal import SystemdJournalParser


def _record(**overrides):
    record = {
        "__CURSOR": "s=abc;i=1;b=boot;m=10;t=20;x=cursor",
        "__REALTIME_TIMESTAMP": "1792319400123456",
        "__MONOTONIC_TIMESTAMP": "123456789",
        "_BOOT_ID": "boot-id",
        "_HOSTNAME": "host-a",
        "_SYSTEMD_UNIT": "sshd.service",
        "SYSLOG_IDENTIFIER": "sshd",
        "PRIORITY": "4",
        "_PID": "123",
        "_UID": "1000",
        "_GID": "1000",
        "_COMM": "sshd",
        "_EXE": "/usr/sbin/sshd",
        "MESSAGE": "Accepted publickey for analyst",
        "UNRELATED_SECRET": "must not be copied",
    }
    record.update(overrides)
    return record


def test_journal_parser_normalizes_numeric_string_microseconds_and_allowlists_fields() -> None:
    parsed = SystemdJournalParser().parse_line(json.dumps(_record()))

    assert parsed is not None
    assert parsed["timestamp"] == "2026-10-18T10:30:00.123456Z"
    assert parsed["event_type"] == "journal_entry"
    assert parsed["attributes"] == {
        "message": "Accepted publickey for analyst",
        "priority": "4",
        "systemd_unit": "sshd.service",
        "syslog_identifier": "sshd",
        "pid": "123",
        "uid": "1000",
        "gid": "1000",
        "comm": "sshd",
        "exe": "/usr/sbin/sshd",
        "hostname": "host-a",
        "boot_id": "boot-id",
        "journal_cursor": "s=abc;i=1;b=boot;m=10;t=20;x=cursor",
        "monotonic_timestamp_us": "123456789",
        "journal_realtime_timestamp_us": "1792319400123456",
    }
    assert "UNRELATED_SECRET" not in parsed["attributes"]


def test_journal_parser_accepts_integer_microseconds_without_float_conversion() -> None:
    parsed = SystemdJournalParser().parse_line(json.dumps(_record(__REALTIME_TIMESTAMP=1792319400123456)))
    assert parsed is not None
    assert parsed["timestamp"] == "2026-10-18T10:30:00.123456Z"


@pytest.mark.parametrize("raw", [None, "not-a-number", "-1", -1, "253402300800000000", 253402300800000000, True, 1.5])
def test_missing_malformed_negative_and_out_of_range_times_are_unresolved(raw) -> None:
    record = _record()
    if raw is None:
        record.pop("__REALTIME_TIMESTAMP")
    else:
        record["__REALTIME_TIMESTAMP"] = raw
    parsed = SystemdJournalParser().parse_line(json.dumps(record))
    assert parsed is not None
    assert parsed["timestamp"] is None


def test_non_string_messages_remain_explicitly_typed_and_bounded() -> None:
    parser = SystemdJournalParser()
    binary = parser.parse_line(json.dumps(_record(MESSAGE=[0, 127, 255])))
    unsupported = parser.parse_line(json.dumps(_record(MESSAGE={"text": "not plain message text"})))
    long_message = parser.parse_line(json.dumps(_record(MESSAGE="x" * 5000)))

    assert binary["attributes"]["message"] == {
        "encoding": "byte_array", "bytes": [0, 127, 255], "byte_length": 3, "truncated": False,
    }
    assert unsupported["attributes"]["message"] == {"encoding": "unsupported", "json_type": "dict"}
    assert long_message["attributes"]["message"]["truncated"] is True
    assert len(long_message["attributes"]["message"]["value"]) == 4096


def test_journal_detection_rejects_malformed_and_unrelated_json() -> None:
    parser = SystemdJournalParser()
    assert parser.parse_line("{") is None
    assert parser.parse_line('[]') is None
    assert parser.parse_line('{"timestamp":"2026-01-01T00:00:00Z","event_type":"login"}') is None
    assert not parser.can_parse(Path("events.jsonl"), ["{", '{"message":"ordinary application json"}'])
    assert parser.can_parse(Path("journal.json"), ["not json", json.dumps(_record())])
    assert any(isinstance(item, SystemdJournalParser) for item in get_parsers())
