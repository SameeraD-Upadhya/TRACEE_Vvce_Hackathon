from __future__ import annotations

import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi.responses import JSONResponse
from starlette.requests import Request

from tracee.activity import ActivityLog, ActivityLogError
from tracee.analysis import AnalysisError, EvidenceAnalysisService
from tracee.api import create_app
from tracee.services import TraceeService


def _ingest(tmp_path: Path, data: bytes) -> tuple[TraceeService, str]:
    source = tmp_path / "evidence.log"
    source.write_bytes(data)
    service = TraceeService(tmp_path / "vault")
    metadata, _ = service.ingest(source)
    return service, metadata.evidence_id


def _snapshot(service: TraceeService) -> dict[str, bytes]:
    root = service.vault_dir
    return {
        str(path.relative_to(root)): path.read_bytes()
        for base in ("objects", "records", "chain")
        for path in (root / base).rglob("*")
        if path.is_file()
    }


def _call_route(service: TraceeService, method: str, path: str, **kwargs):
    app = create_app(service.vault_dir)
    route = next(
        route for route in app.routes
        if getattr(route, "path", None) == path and method in getattr(route, "methods", set())
    )
    scope = {
        "type": "http", "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1", "method": method, "scheme": "http",
        "path": path, "raw_path": path.encode(), "query_string": b"",
        "headers": [], "client": ("127.0.0.1", 1234),
        "server": ("127.0.0.1", 8000), "root_path": "",
    }
    if "request" in route.endpoint.__annotations__:
        kwargs["request"] = Request(scope)
    return route.endpoint(**kwargs)


def _status(response) -> int:
    return response.status_code if isinstance(response, JSONResponse) else 200


def _json(response):
    return json.loads(response.body) if isinstance(response, JSONResponse) else response


def test_linux_auth_parser_normalizes_with_unknown_timezone_and_provenance(tmp_path: Path) -> None:
    data = (
        b"2026-10-18 09:00:00 sshd user=alice ip=192.0.2.4\n"
        b"not an auth record\n\n"
    )
    service, evidence_id = _ingest(tmp_path, data)
    before = _snapshot(service)

    summary = EvidenceAnalysisService(service).analyze(evidence_id, "linux_auth")
    result = EvidenceAnalysisService(service).get_analysis(
        evidence_id, summary["analysis_id"], offset=0, limit=25
    )

    assert summary["source_sha256"] == hashlib.sha256(data).hexdigest()
    assert summary["event_count"] == 1
    assert summary["diagnostics"]["blank_lines"] == 1
    assert summary["diagnostics"]["malformed_lines"] == 1
    assert result["events"][0]["event_type"] == "sshd"
    assert result["events"][0]["attributes"] == {"user": "alice", "ip": "192.0.2.4"}
    observation = result["observations"][0]
    assert observation["source_locator"] == "line:1"
    assert observation["evidence_id"] == evidence_id
    assert observation["timestamp"]["timezone_status"] == "unknown"
    assert observation["timestamp"]["normalized_extent"] == {
        "earliest_utc": None,
        "latest_utc": None,
    }
    assert _snapshot(service) == before


def test_json_event_timezone_offset_is_normalized_to_utc(tmp_path: Path) -> None:
    data = b'{"timestamp":"2026-10-18T10:30:00+02:00","event_type":"login","attributes":{"user":"bob"},"custom":"ignored by legacy parser"}\n'
    service, evidence_id = _ingest(tmp_path, data)
    analyzer = EvidenceAnalysisService(service)
    summary = analyzer.analyze(evidence_id, "json_event")
    result = analyzer.get_analysis(evidence_id, summary["analysis_id"], offset=0, limit=10)

    observation = result["observations"][0]
    assert observation["timestamp"]["timezone_status"] == "known"
    assert observation["timestamp"]["normalized_extent"]["earliest_utc"] == "2026-10-18T08:30:00Z"
    assert observation["attributes"] == {"user": "bob"}


def test_systemd_journal_analysis_preserves_verified_source_provenance(tmp_path: Path) -> None:
    raw = (
        b'{"__CURSOR":"s=cursor","__REALTIME_TIMESTAMP":"1792319400123456",'
        b'"__MONOTONIC_TIMESTAMP":"987654321","_BOOT_ID":"boot-a",'
        b'"_HOSTNAME":"host-a","_SYSTEMD_UNIT":"sshd.service",'
        b'"SYSLOG_IDENTIFIER":"sshd","PRIORITY":"4","_PID":"55",'
        b'"_UID":"0","_GID":"0","_COMM":"sshd",'
        b'"_EXE":"/usr/sbin/sshd","MESSAGE":"accepted key",'
        b'"UNRELATED":"ignored"}\n'
    )
    service, evidence_id = _ingest(tmp_path, raw)
    before = _snapshot(service)
    summary = EvidenceAnalysisService(service).analyze(evidence_id, "systemd_journal")
    result = EvidenceAnalysisService(service).get_analysis(
        evidence_id, summary["analysis_id"], offset=0, limit=25,
    )

    assert summary["parser"] == "systemd_journal"
    assert summary["source_sha256"] == hashlib.sha256(raw).hexdigest()
    assert result["events"][0]["event_type"] == "journal_entry"
    observation = result["observations"][0]
    assert observation["evidence_id"] == evidence_id
    assert observation["parser_name"] == "systemd_journal"
    assert observation["source_locator"] == "line:1"
    assert observation["timestamp"]["raw_value"] == "2026-10-18T10:30:00.123456Z"
    assert observation["timestamp"]["normalized_extent"]["earliest_utc"] == "2026-10-18T10:30:00.123456Z"
    assert observation["attributes"]["journal_realtime_timestamp_us"] == "1792319400123456"
    assert observation["attributes"]["journal_cursor"] == "s=cursor"
    assert "UNRELATED" not in observation["attributes"]
    api_result = _call_route(
        service, "POST", "/api/v1/evidence/{evidence_id}/analyze",
        evidence_id=evidence_id, payload={"parser": "systemd_journal"},
    )
    assert _status(api_result) == 201
    assert _json(api_result)["parser"] == "systemd_journal"
    assert _snapshot(service) == before


def test_systemd_journal_parser_mismatch_is_detected_for_other_json_and_auth_logs(tmp_path: Path) -> None:
    journal = b'{"__CURSOR":"cursor","__REALTIME_TIMESTAMP":"1792319400123456","MESSAGE":"hello"}\n'
    journal_root = tmp_path / "journal"
    journal_root.mkdir()
    service, evidence_id = _ingest(journal_root, journal)
    analyzer = EvidenceAnalysisService(service)
    for parser in ("json_event", "linux_auth"):
        with pytest.raises(AnalysisError) as caught:
            analyzer.analyze(evidence_id, parser)
        assert caught.value.code == "parser_mismatch"

    json_root = tmp_path / "json"
    json_root.mkdir()
    json_service, json_id = _ingest(json_root, b'{"timestamp":"2026-10-18T10:30:00Z","event_type":"login"}\n')
    with pytest.raises(AnalysisError) as caught:
        EvidenceAnalysisService(json_service).analyze(json_id, "systemd_journal")
    assert caught.value.code == "parser_mismatch"


@pytest.mark.parametrize("time_field", [None, "not-a-number", "-1", "253402300800000000"])
def test_systemd_journal_analysis_keeps_invalid_or_missing_time_unresolved(tmp_path: Path, time_field) -> None:
    record = {"__CURSOR": "cursor", "MESSAGE": "journal record"}
    if time_field is not None:
        record["__REALTIME_TIMESTAMP"] = time_field
    service, evidence_id = _ingest(tmp_path, (json.dumps(record) + "\n").encode())
    summary = EvidenceAnalysisService(service).analyze(evidence_id, "systemd_journal")
    result = EvidenceAnalysisService(service).get_analysis(evidence_id, summary["analysis_id"], offset=0, limit=25)
    timestamp = result["observations"][0]["timestamp"]
    assert timestamp["normalized_extent"] == {"earliest_utc": None, "latest_utc": None}
    assert result["events"][0]["temporal_extent"] == {"earliest_utc": None, "latest_utc": None}


@pytest.mark.parametrize(
    ("data", "parser"),
    [
        (b"", "linux_auth"),
        (b"malformed line\nsecond bad line\n", "linux_auth"),
        (b'{"timestamp":null,"event_type":"login","attributes":{}}\n', "json_event"),
    ],
)
def test_empty_malformed_and_missing_timestamps_are_diagnostic(
    tmp_path: Path, data: bytes, parser: str
) -> None:
    service, evidence_id = _ingest(tmp_path, data)
    summary = EvidenceAnalysisService(service).analyze(evidence_id, parser)
    assert summary["event_count"] == (1 if b'"event_type"' in data else 0)
    if data and b'"timestamp":null' not in data:
        assert summary["diagnostics"]["malformed_lines"] >= 1
    if b'"timestamp":null' in data:
        assert summary["diagnostics"]["partial_records"] == 1
    if b'"timestamp":null' in data:
        result = EvidenceAnalysisService(service).get_analysis(
            evidence_id, summary["analysis_id"], offset=0, limit=10
        )
        assert result["observations"][0]["timestamp"]["timezone_status"] == "not_present"
        assert result["observations"][0]["parse_errors"] == ["missing_timestamp"]


def test_unknown_and_mismatched_parser_are_rejected(tmp_path: Path) -> None:
    service, evidence_id = _ingest(
        tmp_path, b"2026-10-18 09:00:00 sshd user=alice ip=192.0.2.4\n"
    )
    analyzer = EvidenceAnalysisService(service)
    with pytest.raises(AnalysisError) as unsupported:
        analyzer.analyze(evidence_id, "no_such_parser")
    assert unsupported.value.code == "unsupported_parser"
    with pytest.raises(AnalysisError) as mismatch:
        analyzer.analyze(evidence_id, "json_event")
    assert mismatch.value.code == "parser_mismatch"


def test_missing_evidence_record_is_not_reported_as_vault_failure(tmp_path: Path) -> None:
    service = TraceeService(tmp_path / "vault")
    service.vault.initialize()
    with pytest.raises(AnalysisError) as missing:
        EvidenceAnalysisService(service).analyze("TRACE-EV-000099", "linux_auth")
    assert missing.value.code == "evidence_not_found"
    assert not (service.vault_dir / "analyses").exists()


def test_configurable_analysis_limits_fail_without_partial_results(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, evidence_id = _ingest(
        tmp_path,
        b'{"timestamp":"2026-10-18T10:00:00Z","event_type":"login"}\n',
    )
    monkeypatch.setenv("TRACEE_MAX_ANALYSIS_BYTES", "1")
    with pytest.raises(AnalysisError) as input_limit:
        EvidenceAnalysisService(service).analyze(evidence_id, "json_event")
    assert input_limit.value.code == "analysis_limit_exceeded"
    monkeypatch.setenv("TRACEE_MAX_ANALYSIS_BYTES", "invalid")
    with pytest.raises(AnalysisError) as configuration:
        EvidenceAnalysisService(service).analyze(evidence_id, "json_event")
    assert configuration.value.code == "analysis_configuration_invalid"
    monkeypatch.delenv("TRACEE_MAX_ANALYSIS_BYTES")
    monkeypatch.setenv("TRACEE_MAX_ANALYSIS_RESULT_BYTES", "1")
    with pytest.raises(AnalysisError) as result_limit:
        EvidenceAnalysisService(service).analyze(evidence_id, "json_event")
    assert result_limit.value.code == "analysis_limit_exceeded"
    assert not (service.vault_dir / "analyses").exists()


@pytest.mark.parametrize("damage", ["tampered", "missing"])
def test_integrity_failure_refuses_analysis_without_source_changes(
    tmp_path: Path, damage: str
) -> None:
    service, evidence_id = _ingest(
        tmp_path, b"2026-10-18 09:00:00 sshd user=alice ip=192.0.2.4\n"
    )
    object_path = service.vault.evidence_path(evidence_id)
    if damage == "tampered":
        object_path.chmod(0o600)
        object_path.write_bytes(b"changed after acquisition")
    else:
        object_path.chmod(0o600)
        object_path.unlink()
    with pytest.raises(AnalysisError) as failure:
        EvidenceAnalysisService(service).analyze(evidence_id, "linux_auth")
    assert failure.value.code == "integrity_verification_failed"
    assert failure.value.verification_state == ("TAMPERED" if damage == "tampered" else "MISSING")
    assert not (service.vault_dir / "analyses").exists()


def test_repeat_analysis_is_immutable_and_paginated(tmp_path: Path) -> None:
    lines = b"".join(
        f'{{"timestamp":"2026-10-18T10:00:{second:02d}Z","event_type":"login","attributes":{{}}}}\n'.encode()
        for second in range(3)
    )
    service, evidence_id = _ingest(tmp_path, lines)
    analyzer = EvidenceAnalysisService(service)
    first = analyzer.analyze(evidence_id, "json_event")
    second = analyzer.analyze(evidence_id, "json_event")
    assert first["analysis_id"] != second["analysis_id"]
    assert len(analyzer.list_analyses(evidence_id)[0]) == 2
    page = analyzer.get_analysis(evidence_id, first["analysis_id"], offset=1, limit=1)
    assert page["pagination"] == {"offset": 1, "limit": 1, "total_events": 3}
    assert len(page["events"]) == len(page["observations"]) == 1


def test_source_hash_binding_stale_record_and_malformed_record(tmp_path: Path) -> None:
    service, evidence_id = _ingest(
        tmp_path, b'{"timestamp":"2026-10-18T10:00:00Z","event_type":"login"}\n'
    )
    analyzer = EvidenceAnalysisService(service)
    summary = analyzer.analyze(evidence_id, "json_event")
    path = service.vault_dir / "analyses" / evidence_id / f"{summary['analysis_id']}.json"
    record = json.loads(path.read_text(encoding="utf-8"))
    record["source_sha256"] = "0" * 64
    path.write_text(json.dumps(record), encoding="utf-8")
    with pytest.raises(AnalysisError) as stale:
        analyzer.get_analysis(evidence_id, summary["analysis_id"], offset=0, limit=10)
    assert stale.value.code == "stale_analysis"

    path.write_text("{broken", encoding="utf-8")
    with pytest.raises(AnalysisError) as malformed:
        analyzer.get_analysis(evidence_id, summary["analysis_id"], offset=0, limit=10)
    assert malformed.value.code == "analysis_invalid"


def test_analysis_record_with_mismatched_evidence_binding_is_rejected(tmp_path: Path) -> None:
    service, evidence_id = _ingest(
        tmp_path, b'{"timestamp":"2026-10-18T10:00:00Z","event_type":"login"}\n'
    )
    analyzer = EvidenceAnalysisService(service)
    summary = analyzer.analyze(evidence_id, "json_event")
    path = service.vault_dir / "analyses" / evidence_id / f"{summary['analysis_id']}.json"
    record = json.loads(path.read_text(encoding="utf-8"))
    record["evidence_id"] = "TRACE-EV-000002"
    path.write_text(json.dumps(record), encoding="utf-8")
    with pytest.raises(AnalysisError) as mismatch:
        analyzer.list_analyses(evidence_id)
    assert mismatch.value.code == "analysis_invalid"


def test_analysis_api_contract_activity_and_source_preservation(tmp_path: Path) -> None:
    data = b'2026-10-18 09:00:00 sshd user=alice ip=192.0.2.4\n'
    service, evidence_id = _ingest(tmp_path, data)
    before = _snapshot(service)
    empty_listing = _call_route(
        service, "GET", "/api/v1/evidence/{evidence_id}/analyses",
        evidence_id=evidence_id, offset=0, limit=25,
    )
    assert _json(empty_listing) == {
        "evidence_id": evidence_id,
        "analyses": [],
        "pagination": {"offset": 0, "limit": 25, "total_analyses": 0},
    }
    assert not (service.vault_dir / "analyses").exists()
    created = _call_route(
        service, "POST", "/api/v1/evidence/{evidence_id}/analyze",
        evidence_id=evidence_id, payload={"parser": "linux_auth"},
    )
    assert _status(created) == 201
    summary = _json(created)
    assert summary["source_sha256"] == hashlib.sha256(data).hexdigest()
    listing = _call_route(
        service, "GET", "/api/v1/evidence/{evidence_id}/analyses",
        evidence_id=evidence_id, offset=0, limit=25,
    )
    assert _status(listing) == 200
    assert _json(listing) == {
        "evidence_id": evidence_id,
        "analyses": [summary],
        "pagination": {"offset": 0, "limit": 25, "total_analyses": 1},
    }
    detail = _call_route(
        service, "GET", "/api/v1/evidence/{evidence_id}/analyses/{analysis_id}",
        evidence_id=evidence_id, analysis_id=summary["analysis_id"], offset=0, limit=1,
    )
    assert _status(detail) == 200
    assert _json(detail)["pagination"]["total_events"] == 1
    invalid_analysis = _call_route(
        service, "GET", "/api/v1/evidence/{evidence_id}/analyses/{analysis_id}",
        evidence_id=evidence_id, analysis_id="not-valid", offset=0, limit=25,
    )
    assert _json(invalid_analysis)["error"]["code"] == "invalid_analysis_id"
    invalid_page = _call_route(
        service, "GET", "/api/v1/evidence/{evidence_id}/analyses/{analysis_id}",
        evidence_id=evidence_id, analysis_id=summary["analysis_id"], offset=0, limit=51,
    )
    assert _status(invalid_page) == 422
    assert _snapshot(service) == before

    events = ActivityLog(service.vault_dir).recent()
    assert [event["event_type"] for event in events[:2]] == [
        "evidence_analysis_completed", "evidence_analysis_started"
    ]
    assert all(event["actor"] == "local_api_token" for event in events[:2])
    assert events[0]["sha256"] == summary["source_sha256"]


def test_analysis_routes_and_json_contract_are_in_openapi() -> None:
    schema = create_app().openapi()
    post_operation = schema["paths"]["/api/v1/evidence/{evidence_id}/analyze"]["post"]
    request_schema = post_operation["requestBody"]["content"]["application/json"]["schema"]
    assert request_schema["required"] == ["parser"]
    assert request_schema["additionalProperties"] is False
    supported = ["linux_auth", "json_event", "systemd_journal", "windows_event"]
    assert request_schema["properties"]["parser"]["enum"] == supported
    post_response = post_operation["responses"]["201"]["content"]["application/json"]["schema"]
    assert post_response["required"] == [
        "analysis_id", "evidence_id", "source_sha256", "parser",
        "parser_version", "created_at", "event_count", "diagnostics",
    ]
    assert post_response["properties"]["parser"]["enum"] == supported
    assert "/api/v1/evidence/{evidence_id}/analyses" in schema["paths"]
    list_response = schema["paths"]["/api/v1/evidence/{evidence_id}/analyses"]["get"]["responses"]["200"]["content"]["application/json"]["schema"]
    assert list_response["required"] == ["evidence_id", "analyses", "pagination"]
    detail_get = schema["paths"]["/api/v1/evidence/{evidence_id}/analyses/{analysis_id}"]["get"]
    detail_response = detail_get["responses"]["200"]["content"]["application/json"]["schema"]
    assert {"events", "observations", "pagination"}.issubset(detail_response["required"])
    assert detail_response["properties"]["observations"]["items"]["properties"]["parser_name"]["enum"] == supported
    parameters = {parameter["name"]: parameter for parameter in detail_get["parameters"]}
    assert parameters["offset"]["schema"]["maximum"] == 1_000_000
    assert parameters["limit"]["schema"]["maximum"] == 50


def test_timeline_api_orders_normalized_utc_and_keeps_unresolved_times_visible(tmp_path: Path) -> None:
    records = [
        {"timestamp": "2026-10-18T10:00:00Z", "event_type": "late", "attributes": {"line": 1}},
        {"timestamp": "2026-10-18T08:00:00+02:00", "event_type": "early", "attributes": {"line": 2}},
        {"timestamp": "2026-10-18T06:00:00Z", "event_type": "tie", "attributes": {"line": 3}},
        {"timestamp": None, "event_type": "unknown", "attributes": {"line": 4}},
    ]
    data = ("\n".join(json.dumps(record) for record in records) + "\n").encode()
    service, evidence_id = _ingest(tmp_path, data)
    summary = EvidenceAnalysisService(service).analyze(evidence_id, "json_event")
    before = {
        str(path.relative_to(service.vault_dir)): path.read_bytes()
        for path in service.vault_dir.rglob("*") if path.is_file()
    }

    response = _call_route(
        service, "GET", "/api/v1/evidence/{evidence_id}/analyses/{analysis_id}/timeline",
        evidence_id=evidence_id, analysis_id=summary["analysis_id"], offset=0, limit=2,
    )
    assert _status(response) == 200
    first = _json(response)
    assert [item["event_type"] for item in first["entries"]] == ["early", "tie"]
    assert first["entries"][0]["temporal_extent"]["earliest_utc"] == "2026-10-18T06:00:00Z"
    assert first["entries"][0]["source_observations"][0]["source_locator"] == "line:2"
    assert first["entries"][0]["source_observations"][0]["timestamp"]["raw_value"] == "2026-10-18T08:00:00+02:00"
    assert first["entries"][0]["source_observations"][0]["timestamp"]["timezone_status"] == "known"
    assert first["counts"] == {"total": 4, "known_time": 3, "partially_bounded": 0, "unresolved_time": 1}
    second = _json(_call_route(
        service, "GET", "/api/v1/evidence/{evidence_id}/analyses/{analysis_id}/timeline",
        evidence_id=evidence_id, analysis_id=summary["analysis_id"], offset=2, limit=2,
    ))
    assert [item["event_type"] for item in second["entries"]] == ["late", "unknown"]
    assert second["entries"][-1]["time_status"] == "unresolved"
    after = {
        str(path.relative_to(service.vault_dir)): path.read_bytes()
        for path in service.vault_dir.rglob("*") if path.is_file()
    }
    assert after == before


def test_timeline_api_rejects_bad_ids_missing_and_stale_analyses(tmp_path: Path) -> None:
    service, evidence_id = _ingest(
        tmp_path, b'{"timestamp":"2026-10-18T10:00:00Z","event_type":"login"}\n'
    )
    summary = EvidenceAnalysisService(service).analyze(evidence_id, "json_event")
    route_path = "/api/v1/evidence/{evidence_id}/analyses/{analysis_id}/timeline"
    malformed = _call_route(service, "GET", route_path, evidence_id="bad", analysis_id=summary["analysis_id"], offset=0, limit=25)
    assert _status(malformed) == 400
    assert _json(malformed)["error"]["code"] == "invalid_evidence_id"
    invalid_analysis = _call_route(service, "GET", route_path, evidence_id=evidence_id, analysis_id="bad", offset=0, limit=25)
    assert _json(invalid_analysis)["error"]["code"] == "invalid_analysis_id"
    missing = _call_route(service, "GET", route_path, evidence_id=evidence_id, analysis_id="TRACE-AN-00000000000000000000000000000000", offset=0, limit=25)
    assert _status(missing) == 404
    assert _json(missing)["error"]["code"] == "analysis_not_found"

    analysis_path = service.vault_dir / "analyses" / evidence_id / f"{summary['analysis_id']}.json"
    stored = json.loads(analysis_path.read_text(encoding="utf-8"))
    stored["source_sha256"] = "0" * 64
    analysis_path.chmod(0o600)
    analysis_path.write_text(json.dumps(stored), encoding="utf-8")
    stale = _call_route(service, "GET", route_path, evidence_id=evidence_id, analysis_id=summary["analysis_id"], offset=0, limit=25)
    assert _status(stale) == 409
    assert _json(stale)["error"]["code"] == "stale_analysis"


@pytest.mark.parametrize("corruption", ["broken_reference", "wrong_evidence"])
def test_timeline_api_rejects_malformed_or_cross_evidence_provenance(tmp_path: Path, corruption: str) -> None:
    service, evidence_id = _ingest(
        tmp_path, b'{"timestamp":"2026-10-18T10:00:00Z","event_type":"login"}\n'
    )
    summary = EvidenceAnalysisService(service).analyze(evidence_id, "json_event")
    path = service.vault_dir / "analyses" / evidence_id / f"{summary['analysis_id']}.json"
    record = json.loads(path.read_text(encoding="utf-8"))
    if corruption == "broken_reference":
        record["events"][0]["source_observation_ids"] = ["missing-observation"]
    else:
        record["observations"][0]["evidence_id"] = "TRACE-EV-999999"
    path.chmod(0o600)
    path.write_text(json.dumps(record), encoding="utf-8")

    response = _call_route(
        service, "GET", "/api/v1/evidence/{evidence_id}/analyses/{analysis_id}/timeline",
        evidence_id=evidence_id, analysis_id=summary["analysis_id"], offset=0, limit=25,
    )
    assert _status(response) == 500
    assert _json(response)["error"]["code"] == "analysis_invalid"


def test_timeline_api_refuses_tampered_source_evidence(tmp_path: Path) -> None:
    service, evidence_id = _ingest(
        tmp_path, b'{"timestamp":"2026-10-18T10:00:00Z","event_type":"login"}\n'
    )
    summary = EvidenceAnalysisService(service).analyze(evidence_id, "json_event")
    object_path = service.vault.evidence_path(evidence_id)
    object_path.chmod(0o600)
    object_path.write_bytes(object_path.read_bytes() + b"changed")
    response = _call_route(
        service, "GET", "/api/v1/evidence/{evidence_id}/analyses/{analysis_id}/timeline",
        evidence_id=evidence_id, analysis_id=summary["analysis_id"], offset=0, limit=25,
    )
    assert _status(response) == 409
    assert _json(response)["error"]["code"] == "integrity_verification_failed"


def test_timeline_contract_is_documented_in_openapi() -> None:
    schema = create_app().openapi()
    operation = schema["paths"]["/api/v1/evidence/{evidence_id}/analyses/{analysis_id}/timeline"]["get"]
    response = operation["responses"]["200"]["content"]["application/json"]["schema"]
    assert response["required"] == ["evidence_id", "analysis_id", "source_sha256", "parser", "parser_version", "entries", "counts", "pagination"]
    assert response["properties"]["entries"]["items"]["properties"]["time_status"]["enum"] == ["bounded_utc", "partially_bounded", "unresolved"]


def test_analysis_api_sanitizes_invalid_and_failed_integrity_requests(tmp_path: Path) -> None:
    service, evidence_id = _ingest(
        tmp_path, b"2026-10-18 09:00:00 sshd user=alice ip=192.0.2.4\n"
    )
    invalid = _call_route(
        service, "POST", "/api/v1/evidence/{evidence_id}/analyze",
        evidence_id="bad", payload={"parser": "linux_auth"},
    )
    assert _status(invalid) == 400
    assert _json(invalid)["error"]["code"] == "invalid_evidence_id"
    malformed_request = _call_route(
        service, "POST", "/api/v1/evidence/{evidence_id}/analyze",
        evidence_id=evidence_id,
        payload={"parser": "linux_auth", "source_path": "C:\\private\\source"},
    )
    assert _status(malformed_request) == 422
    assert _json(malformed_request)["error"]["code"] == "invalid_request"
    unsupported = _call_route(
        service, "POST", "/api/v1/evidence/{evidence_id}/analyze",
        evidence_id=evidence_id, payload={"parser": "unknown"},
    )
    assert _status(unsupported) == 422
    assert _json(unsupported)["error"]["code"] == "unsupported_parser"
    assert str(service.vault_dir) not in unsupported.body.decode()

    object_path = service.vault.evidence_path(evidence_id)
    object_path.chmod(0o600)
    object_path.write_bytes(b"tampered")
    failed = _call_route(
        service, "POST", "/api/v1/evidence/{evidence_id}/analyze",
        evidence_id=evidence_id, payload={"parser": "linux_auth"},
    )
    assert _status(failed) == 409
    assert _json(failed)["verification"]["state"] == "TAMPERED"


def test_analysis_api_sanitizes_malformed_metadata_and_vault_errors(tmp_path: Path) -> None:
    service, evidence_id = _ingest(
        tmp_path, b"2026-10-18 09:00:00 sshd user=alice ip=192.0.2.4\n"
    )
    metadata_path = service.vault.record_path(evidence_id)
    metadata_path.write_text(
        f"not valid JSON; internal path {service.vault_dir}", encoding="utf-8"
    )
    malformed = _call_route(
        service, "POST", "/api/v1/evidence/{evidence_id}/analyze",
        evidence_id=evidence_id, payload={"parser": "linux_auth"},
    )
    assert _status(malformed) == 500
    assert _json(malformed)["error"]["code"] == "unreadable_metadata"
    assert str(service.vault_dir) not in malformed.body.decode()
    assert "JSON" not in malformed.body.decode()

    unavailable_app = create_app(tmp_path / "missing-vault")
    route = next(
        route for route in unavailable_app.routes
        if getattr(route, "path", None) == "/api/v1/evidence/{evidence_id}/analyses"
    )
    unavailable = route.endpoint(evidence_id="TRACE-EV-000001", offset=0, limit=25)
    assert _status(unavailable) == 503
    assert _json(unavailable)["error"]["code"] == "vault_unavailable"
    assert not (tmp_path / "missing-vault").exists()


def test_analysis_audit_completion_failure_reports_persisted_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, evidence_id = _ingest(
        tmp_path, b"2026-10-18 09:00:00 sshd user=alice ip=192.0.2.4\n"
    )
    original = ActivityLog.append

    def fail_completion(self, **kwargs):
        if kwargs.get("event_type") == "evidence_analysis_completed":
            raise ActivityLogError("test audit write failed")
        return original(self, **kwargs)

    monkeypatch.setattr(ActivityLog, "append", fail_completion)
    response = _call_route(
        service, "POST", "/api/v1/evidence/{evidence_id}/analyze",
        evidence_id=evidence_id, payload={"parser": "linux_auth"},
    )
    assert _status(response) == 503
    assert _json(response)["operation"]["completed"] is True
    assert _json(response)["audit"]["recorded"] is False
    assert list((service.vault_dir / "analyses").rglob("TRACE-AN-*.json"))


def test_analysis_activity_event_types_validate_and_chain(tmp_path: Path) -> None:
    service, evidence_id = _ingest(tmp_path, b"data")
    log = ActivityLog(service.vault_dir)
    started = log.append(
        event_type="evidence_analysis_started",
        actor="unauthenticated_local_client",
        outcome="accepted",
        evidence_id=evidence_id,
    )
    completed = log.append(
        event_type="evidence_analysis_completed",
        actor="unauthenticated_local_client",
        outcome="success",
        evidence_id=evidence_id,
        sha256="a" * 64,
    )
    assert completed["previous_hash"] == started["record_hash"]
    assert [item["event_type"] for item in log.recent()] == [
        "evidence_analysis_completed", "evidence_analysis_started"
    ]


def test_concurrent_analysis_storage_keeps_unique_immutable_results(tmp_path: Path) -> None:
    data = b'{"timestamp":"2026-10-18T10:00:00Z","event_type":"login"}\n'
    service, evidence_id = _ingest(tmp_path, data)

    def analyze(_: int) -> str:
        return EvidenceAnalysisService(service).analyze(evidence_id, "json_event")["analysis_id"]

    with ThreadPoolExecutor(max_workers=4) as pool:
        analysis_ids = list(pool.map(analyze, range(4)))
    assert len(set(analysis_ids)) == 4
    assert len(EvidenceAnalysisService(service).list_analyses(evidence_id)[0]) == 4
    assert not list((service.vault_dir / "analyses").rglob("*.tmp"))


def test_timezone_offsets_are_reported_as_utc(tmp_path: Path) -> None:
    service, evidence_id = _ingest(
        tmp_path, b'{"timestamp":"2026-10-18T10:00:00-05:00","event_type":"login"}\n'
    )
    summary = EvidenceAnalysisService(service).analyze(evidence_id, "json_event")
    observation = EvidenceAnalysisService(service).get_analysis(
        evidence_id, summary["analysis_id"], offset=0, limit=1
    )["observations"][0]
    normalized = datetime.fromisoformat(
        observation["timestamp"]["normalized_extent"]["earliest_utc"].replace("Z", "+00:00")
    )
    assert normalized.tzinfo is not None
    assert normalized.utcoffset() == timezone.utc.utcoffset(normalized)
