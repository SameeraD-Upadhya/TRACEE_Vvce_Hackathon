from __future__ import annotations

import json
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

import pytest

from parsers.windows_event import (
    EVENT_NAMESPACE,
    WindowsEventParser,
    serialize_windows_event_xml,
)
from tracee.activity import ActivityLog
from tracee.verify import VerificationState
from tracee.windows_event_collector import (
    DEFAULT_MAX_BATCH_BYTES,
    DEFAULT_MAX_RECORDS,
    DEFAULT_MAX_RECORD_BYTES,
    MAX_BATCH_BYTES,
    MAX_RECORDS,
    MAX_RECORD_BYTES,
    WindowsCollectorError,
    WindowsEventLogCollector,
    _PyWin32EventLogApi,
    build_event_log_query,
)
import tracee.windows_event_collector as collector_module


def _event_xml(
    record_id: int | None,
    *,
    timestamp: str = "2026-10-18T10:30:00.0000000Z",
    channel: str = "Application",
    event_id: int = 1000,
    host: str = "SYNTHETIC-WIN",
    provider_name: str | None = "Synthetic-Provider",
    provider_guid: str | None = "{11111111-2222-3333-4444-555555555555}",
    data: str = "synthetic event data",
) -> str:
    n = EVENT_NAMESPACE
    attrs = ""
    if provider_name is not None:
        attrs += f' Name="{provider_name}"'
    if provider_guid is not None:
        attrs += f' Guid="{provider_guid}"'
    record_element = (
        f"<EventRecordID>{record_id}</EventRecordID>"
        if record_id is not None
        else ""
    )
    return (
        f'<Event xmlns="{n}"><System><Provider{attrs}/>'
        f"<EventID>{event_id}</EventID>{record_element}<TimeCreated SystemTime=\"{timestamp}\"/>"
        f"<Channel>{channel}</Channel><Computer>{host}</Computer></System>"
        f"<EventData><Data Name=\"Message\">{data}</Data></EventData></Event>"
    )


@dataclass
class _Handle:
    name: str
    xml: str = ""
    closed: bool = False


class FakeNativeEventLogApi:
    """Synthetic reverse-query API; never accesses the host's event logs."""

    def __init__(
        self,
        xml_records: list[str],
        *,
        render_error_at: int | None = None,
        next_error=None,
        native_record_ids: dict[int, int] | None = None,
    ):
        self.xml_records = xml_records
        self.render_error_at = render_error_at
        self.next_error = next_error
        self.native_record_ids = native_record_ids or {}
        self.query_handle: _Handle | None = None
        self.event_handles: list[_Handle] = []
        self.query_channel: str | None = None
        self.query_provider: str | None = None
        self.query_event_id: int | None = None
        self.requested_count: int | None = None
        self.render_calls = 0

    def open_query(
        self,
        channel: str,
        provider_name: str | None = None,
        event_id: int | None = None,
    ) -> _Handle:
        self.query_channel = channel
        self.query_provider = provider_name
        self.query_event_id = event_id
        self.query_handle = _Handle("query")
        return self.query_handle

    def next_events(self, query_handle: _Handle, count: int) -> tuple[_Handle, ...]:
        assert query_handle is self.query_handle
        self.requested_count = count
        if self.next_error is not None:
            raise self.next_error
        matching_records = []
        for index, xml in enumerate(self.xml_records):
            if self.query_provider is not None or self.query_event_id is not None:
                try:
                    _, envelope = serialize_windows_event_xml(xml)
                except (TypeError, ValueError):
                    # Preserve malformed input so the collector exercises its
                    # fail-closed validation instead of silently dropping it.
                    matching_records.append((index, xml))
                    continue
                if (
                    self.query_provider is not None
                    and envelope["provider"]["name"] != self.query_provider
                ) or (
                    self.query_event_id is not None
                    and envelope["event_id"] != self.query_event_id
                ):
                    continue
            matching_records.append((index, xml))
        self.event_handles = [
            _Handle(f"event-{index}", xml)
            for index, xml in matching_records[:count]
        ]
        return tuple(self.event_handles)

    def render_xml(self, event_handle: _Handle) -> str:
        index = int(event_handle.name.rsplit("-", 1)[1])
        self.render_calls += 1
        if index == self.render_error_at:
            raise RuntimeError("synthetic render failure")
        return event_handle.xml

    def close_handle(self, handle: _Handle) -> None:
        handle.closed = True

    def get_record_id(self, event_handle: _Handle) -> int | None:
        index = int(event_handle.name.rsplit("-", 1)[1])
        return self.native_record_ids.get(index)


def _collector(tmp_path: Path, api: FakeNativeEventLogApi, **limits):
    return WindowsEventLogCollector(tmp_path / "vault", native_api=api, **limits)


def test_one_shot_acquisition_is_bounded_chronological_and_verified(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    newest = _event_xml(102, timestamp="2026-10-18T10:30:02.0000000Z", event_id=1002)
    older = _event_xml(101, timestamp="2026-10-18T10:30:01.0000000Z", event_id=1001)
    api = FakeNativeEventLogApi([newest, older])
    collector = _collector(tmp_path, api, max_records=2)

    result = collector.collect("Application")

    assert api.query_channel == "Application"
    assert api.requested_count == 2
    assert api.query_handle.closed
    assert all(handle.closed for handle in api.event_handles)
    evidence = collector.service.vault.evidence_path(result.evidence_id).read_bytes()
    lines = evidence.decode("utf-8").splitlines()
    parsed = [WindowsEventParser().parse_line(line) for line in lines]
    envelopes = [json.loads(line) for line in lines]
    assert [record["event_id"] for record in envelopes] == [1001, 1002]
    assert all(record is not None for record in parsed)
    assert result.record_count == 2
    assert result.serialized_bytes == len(evidence)
    assert result.sha256 == collector.service.get_metadata(result.evidence_id)["sha256"]
    assert collector.service.verify(result.evidence_id).state is VerificationState.VALID
    assert len(collector.service.verify_chain()) == 1
    assert [path.name for path in tmp_path.iterdir()] == ["vault"]
    activities = ActivityLog(collector.service.vault_dir).recent(10)
    assert [event["event_type"] for event in activities] == [
        "evidence_acquired", "evidence_acquisition_started",
    ]
    assert all(event["actor"] == "local_cli" for event in activities)


def test_collector_preserves_xml_record_id_and_null_provider_guid_in_evidence(
    tmp_path: Path,
) -> None:
    api = FakeNativeEventLogApi([
        _event_xml(140313, provider_guid=None),
    ])
    collector = _collector(tmp_path, api)

    result = collector.collect("Application")

    evidence = collector.service.vault.evidence_path(result.evidence_id).read_bytes()
    envelope = json.loads(evidence.decode("utf-8").strip())
    parsed = WindowsEventParser().parse_line(evidence.decode("utf-8").strip())
    assert envelope["record_id"] == 140313
    assert envelope["provider"]["guid"] is None
    assert "<EventRecordID>140313</EventRecordID>" in envelope["event_xml"]
    assert parsed is not None
    assert parsed["attributes"]["record_id"] == 140313
    assert parsed["attributes"]["provider_guid"] is None


def test_native_record_id_is_used_when_xml_omits_it(tmp_path: Path) -> None:
    api = FakeNativeEventLogApi(
        [_event_xml(None)],
        native_record_ids={0: 140313},
    )
    collector = _collector(tmp_path, api)

    result = collector.collect("Application")

    evidence = collector.service.vault.evidence_path(result.evidence_id).read_bytes()
    envelope = json.loads(evidence.decode("utf-8").strip())
    assert envelope["record_id"] == 140313
    assert "<EventRecordID>" not in envelope["event_xml"]
    assert WindowsEventParser().parse_line(evidence.decode("utf-8").strip()) is not None


def test_conflicting_native_and_xml_record_ids_fail_closed(tmp_path: Path) -> None:
    api = FakeNativeEventLogApi(
        [_event_xml(140313)],
        native_record_ids={0: 140314},
    )
    collector = _collector(tmp_path, api)

    with pytest.raises(WindowsCollectorError) as caught:
        collector.collect("Application")

    assert caught.value.code == "invalid_event_record"
    assert api.query_handle is not None and api.query_handle.closed
    assert all(handle.closed for handle in api.event_handles)
    assert collector.service.vault.chain_path.read_bytes() == b""
    assert list(collector.service.vault.objects_dir.iterdir()) == []


@pytest.mark.parametrize(
    ("limits", "xml_records", "code"),
    [
        ({"max_records": 0}, [], "invalid_configuration"),
        ({"max_records": MAX_RECORDS + 1}, [], "invalid_configuration"),
        ({"max_record_bytes": 0}, [], "invalid_configuration"),
        ({"max_record_bytes": MAX_RECORD_BYTES + 1}, [], "invalid_configuration"),
        ({"max_batch_bytes": 0}, [], "invalid_configuration"),
        ({"max_batch_bytes": MAX_BATCH_BYTES + 1}, [], "invalid_configuration"),
        ({"max_record_bytes": 1}, [_event_xml(1)], "size_limit_exceeded"),
        ({"max_batch_bytes": 1}, [_event_xml(1)], "size_limit_exceeded"),
        ({}, [], "no_events"),
    ],
)
def test_configuration_empty_selection_and_size_limits_fail_without_acquisition(
    tmp_path: Path,
    limits: dict,
    xml_records: list[str],
    code: str,
) -> None:
    api = FakeNativeEventLogApi(xml_records)
    try:
        collector = _collector(tmp_path, api, **limits)
    except WindowsCollectorError as exc:
        assert exc.code == code
        assert api.query_channel is None
        return
    with pytest.raises(WindowsCollectorError) as caught:
        collector.collect("Application")
    assert caught.value.code == code
    assert collector.service.vault.chain_path.read_bytes() == b""
    activities = ActivityLog(collector.service.vault_dir).recent(10)
    assert [event["event_type"] for event in activities] == [
        "evidence_acquisition_failed", "evidence_acquisition_started",
    ]
    assert not any(event["event_type"] == "evidence_acquired" for event in activities)


@pytest.mark.parametrize(
    ("xml", "code"),
    [
        (_event_xml(2, timestamp="2026-10-18T10:30:00"), "invalid_event_timestamp"),
        (_event_xml(2, timestamp="invalid-time"), "invalid_event_timestamp"),
        (_event_xml(2, channel="System"), "invalid_event_record"),
        (_event_xml(2, event_id=70000), "invalid_event_record"),
        ("<Event", "invalid_event_record"),
    ],
)
def test_missing_invalid_or_inconsistent_source_fields_fail_closed(
    tmp_path: Path, xml: str, code: str,
) -> None:
    api = FakeNativeEventLogApi([xml])
    collector = _collector(tmp_path, api)
    with pytest.raises(WindowsCollectorError) as caught:
        collector.collect("Application")
    assert caught.value.code == code
    assert api.query_handle.closed
    assert all(handle.closed for handle in api.event_handles)
    assert collector.service.vault.chain_path.read_bytes() == b""
    activities = ActivityLog(collector.service.vault_dir).recent(10)
    assert activities[0]["event_type"] == "evidence_acquisition_failed"
    assert activities[0]["outcome"] == code
    assert not any(item["event_type"] == "evidence_acquired" for item in activities)


def test_unsupported_channel_is_rejected_before_query_or_vault_creation(tmp_path: Path) -> None:
    api = FakeNativeEventLogApi([_event_xml(1)])
    collector = _collector(tmp_path, api)
    with pytest.raises(WindowsCollectorError) as caught:
        collector.collect("Security")
    assert caught.value.code == "unsupported_channel"
    assert api.query_channel is None
    assert not collector.service.vault_dir.exists()


def test_unsupported_platform_does_not_import_pywin32_or_create_vault(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import tracee.windows_event_collector as collector_module

    monkeypatch.setattr(collector_module.sys, "platform", "linux")
    collector = WindowsEventLogCollector(tmp_path / "vault")
    with pytest.raises(WindowsCollectorError) as caught:
        collector.collect("System")
    assert caught.value.code == "unsupported_platform"
    assert not collector.service.vault_dir.exists()


def test_access_denied_is_safe_and_recorded_as_failed_collection(tmp_path: Path) -> None:
    class AccessDenied(Exception):
        winerror = 5

    api = FakeNativeEventLogApi([], next_error=AccessDenied("synthetic private detail"))
    collector = _collector(tmp_path, api)
    with pytest.raises(WindowsCollectorError) as caught:
        collector.collect("System")
    assert caught.value.code == "access_denied"
    assert "synthetic private detail" not in caught.value.message
    activities = ActivityLog(collector.service.vault_dir).recent(10)
    assert activities[0]["event_type"] == "evidence_acquisition_failed"
    assert activities[0]["outcome"] == "access_denied"
    assert not any(item["event_type"] == "evidence_acquired" for item in activities)


def _collector_with_ingestion_failure(tmp_path: Path):
    collector = _collector(tmp_path, FakeNativeEventLogApi([_event_xml(1)]))

    class SyntheticStorageError(OSError):
        def __init__(self) -> None:
            super().__init__(13, "Access is denied", str(tmp_path / "private-path"))
            self.winerror = 5

    def fail_ingest(_source_path):
        raise SyntheticStorageError()

    collector.service.ingest = fail_ingest
    return collector


def test_storage_failure_diagnostic_is_opt_in_and_identifies_ingestion_stage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog,
) -> None:
    monkeypatch.setenv("TRACEE_WINDOWS_COLLECTOR_DIAGNOSTICS", "1")
    collector = _collector_with_ingestion_failure(tmp_path)

    with pytest.raises(WindowsCollectorError) as caught:
        collector.collect("Application")

    assert caught.value.code == "storage_failure"
    diagnostic_records = [
        record.tracee_windows_collector_diagnostic
        for record in caplog.records
        if hasattr(record, "tracee_windows_collector_diagnostic")
    ]
    assert diagnostic_records == [{
        "stage": "evidence_ingestion",
        "exception_type": "SyntheticStorageError",
        "error_code": None,
        "exit_code": None,
        "errno": 13,
        "winerror": 5,
        "detail": "Access is denied.",
    }]
    assert str(tmp_path / "private-path") not in caplog.text


def test_storage_failure_without_diagnostics_keeps_generic_contract(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog,
) -> None:
    monkeypatch.delenv("TRACEE_WINDOWS_COLLECTOR_DIAGNOSTICS", raising=False)
    collector = _collector_with_ingestion_failure(tmp_path)

    with pytest.raises(WindowsCollectorError) as caught:
        collector.collect("Application")

    assert caught.value.code == "storage_failure"
    assert not any(
        hasattr(record, "tracee_windows_collector_diagnostic")
        for record in caplog.records
    )


def test_diagnostic_logger_failure_does_not_mask_storage_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TRACEE_WINDOWS_COLLECTOR_DIAGNOSTICS", "1")
    collector = _collector_with_ingestion_failure(tmp_path)

    def fail_logging(*_args, **_kwargs):
        raise RuntimeError("synthetic logger failure")

    monkeypatch.setattr(collector_module._logger, "error", fail_logging)

    with pytest.raises(WindowsCollectorError) as caught:
        collector.collect("Application")

    assert caught.value.code == "storage_failure"


@pytest.mark.parametrize("failure", ["next", "render"])
def test_native_query_and_event_handles_close_when_api_fails(tmp_path: Path, failure: str) -> None:
    api = FakeNativeEventLogApi(
        [_event_xml(2), _event_xml(1)],
        render_error_at=0 if failure == "render" else None,
        next_error=RuntimeError("synthetic query failure") if failure == "next" else None,
    )
    collector = _collector(tmp_path, api)
    with pytest.raises(WindowsCollectorError):
        collector.collect("Application")
    assert api.query_handle is not None and api.query_handle.closed
    assert all(handle.closed for handle in api.event_handles)
    assert collector.service.vault.chain_path.read_bytes() == b""
    activities = ActivityLog(collector.service.vault_dir).recent(10)
    assert activities[0]["event_type"] == "evidence_acquisition_failed"
    assert not any(item["event_type"] == "evidence_acquired" for item in activities)


def test_channel_count_bound_and_order_are_applied_before_native_query(tmp_path: Path) -> None:
    api = FakeNativeEventLogApi([_event_xml(5), _event_xml(4), _event_xml(3)])
    collector = _collector(tmp_path, api, max_records=2)
    result = collector.collect("Application")
    evidence = collector.service.vault.evidence_path(result.evidence_id).read_bytes()
    envelopes = [json.loads(line) for line in evidence.decode("utf-8").splitlines()]
    # The reverse query selected only records 5 and 4; output is chronological.
    assert [item["record_id"] for item in envelopes] == [4, 5]
    assert result.record_count == 2
    assert api.requested_count == 2
    assert api.query_handle.closed
    assert all(handle.closed for handle in api.event_handles)


def test_native_query_is_constructed_from_both_validated_filters(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = []
    native = SimpleNamespace(
        EvtQueryChannelPath=1,
        EvtQueryReverseDirection=2,
        EvtQuery=lambda channel, flags, query: calls.append((channel, flags, query)) or object(),
    )
    monkeypatch.setitem(sys.modules, "win32evtlog", native)

    _PyWin32EventLogApi().open_query("Application", "Synthetic-Provider", 1000)

    assert calls == [(
        "Application",
        3,
        "*[System[Provider[@Name='Synthetic-Provider'] and EventID=1000]]",
    )]
    assert build_event_log_query() == "*"
    assert build_event_log_query(event_id=42) == "*[System[EventID=42]]"
    assert build_event_log_query(provider_name="Provider Name") == (
        "*[System[Provider[@Name='Provider Name']]]"
    )


def test_provider_and_event_id_filters_exclude_nonmatching_records_and_keep_bounds(
    tmp_path: Path,
) -> None:
    api = FakeNativeEventLogApi([
        _event_xml(104, provider_name="Synthetic-Provider", event_id=1000),
        _event_xml(103, provider_name="Synthetic-Provider", event_id=1001),
        _event_xml(102, provider_name="Other-Provider", event_id=1000),
        _event_xml(101, provider_name="Synthetic-Provider", event_id=1000),
    ])
    collector = _collector(
        tmp_path,
        api,
        max_records=2,
        provider_name="Synthetic-Provider",
        event_id=1000,
    )

    result = collector.collect("Application")

    evidence = collector.service.vault.evidence_path(result.evidence_id).read_bytes()
    envelopes = [json.loads(line) for line in evidence.decode("utf-8").splitlines()]
    assert [item["record_id"] for item in envelopes] == [101, 104]
    assert all(item["provider"]["name"] == "Synthetic-Provider" for item in envelopes)
    assert all(item["event_id"] == 1000 for item in envelopes)
    assert api.query_provider == "Synthetic-Provider"
    assert api.query_event_id == 1000
    assert api.requested_count == 2
    assert api.query_handle is not None and api.query_handle.closed
    assert all(handle.closed for handle in api.event_handles)


@pytest.mark.parametrize("size_limit", ["max_record_bytes", "max_batch_bytes"])
def test_filters_still_enforce_serialized_size_limits(
    tmp_path: Path,
    size_limit: str,
) -> None:
    api = FakeNativeEventLogApi([
        _event_xml(2, provider_name="Synthetic-Provider", event_id=42),
        _event_xml(1, provider_name="Other-Provider", event_id=42),
    ])
    collector = _collector(
        tmp_path,
        api,
        provider_name="Synthetic-Provider",
        event_id=42,
        **{size_limit: 1},
    )

    with pytest.raises(WindowsCollectorError) as caught:
        collector.collect("Application")

    assert caught.value.code == "size_limit_exceeded"
    assert api.query_handle is not None and api.query_handle.closed
    assert all(handle.closed for handle in api.event_handles)
    assert collector.service.vault.chain_path.read_bytes() == b""


def test_no_matching_events_create_no_evidence_and_close_native_handles(
    tmp_path: Path,
) -> None:
    api = FakeNativeEventLogApi([
        _event_xml(1, provider_name="Other-Provider", event_id=1000),
    ])
    collector = _collector(
        tmp_path,
        api,
        provider_name="Synthetic-Provider",
        event_id=1000,
    )

    with pytest.raises(WindowsCollectorError) as caught:
        collector.collect("Application")

    assert caught.value.code == "no_matching_events"
    assert "No events matched" in caught.value.message
    assert api.query_handle is not None and api.query_handle.closed
    assert all(handle.closed for handle in api.event_handles)
    assert list(collector.service.vault.objects_dir.iterdir()) == []
    assert collector.service.vault.chain_path.read_bytes() == b""
    activities = ActivityLog(collector.service.vault_dir).recent(10)
    assert activities[0]["event_type"] == "evidence_acquisition_failed"
    assert activities[0]["outcome"] == "no_matching_events"
    assert not any(item["event_type"] == "evidence_acquired" for item in activities)


@pytest.mark.parametrize("provider", ["", " spaced ", "a'b", "bad\nname", "x" * 257])
def test_invalid_provider_filter_fails_before_query_or_vault_creation(
    tmp_path: Path,
    provider: str,
) -> None:
    api = FakeNativeEventLogApi([])
    with pytest.raises(WindowsCollectorError) as caught:
        _collector(tmp_path, api, provider_name=provider)
    assert caught.value.code == "invalid_filter"
    assert api.query_channel is None
    assert not (tmp_path / "vault").exists()


@pytest.mark.parametrize("event_id", [-1, 65536, True, "1000"])
def test_invalid_event_id_filter_fails_before_query_or_vault_creation(
    tmp_path: Path,
    event_id: object,
) -> None:
    api = FakeNativeEventLogApi([])
    with pytest.raises(WindowsCollectorError) as caught:
        _collector(tmp_path, api, event_id=event_id)
    assert caught.value.code == "invalid_filter"
    assert api.query_channel is None
    assert not (tmp_path / "vault").exists()
