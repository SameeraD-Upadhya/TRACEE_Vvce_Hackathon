from __future__ import annotations

import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from fastapi.responses import JSONResponse
from starlette.requests import Request

from tracee.activity import ActivityLog, ActivityLogIntegrityError
from tracee.analysis import AnalysisError, EvidenceAnalysisService
from tracee.api import create_app
from tracee.reconstruction_rules import BUILTIN_RULES, EVENT_TYPE_ATTRIBUTE, rules_for_source
from tracee.reconstruction_service import ReconstructionError, ReconstructionService
from tracee.services import TraceeService


def _ingest(tmp_path: Path, data: bytes) -> tuple[TraceeService, str]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    source = tmp_path / "source.jsonl"
    source.write_bytes(data)
    service = TraceeService(tmp_path / "vault")
    metadata, _ = service.ingest(source)
    return service, metadata.evidence_id


def _analysis(service: TraceeService, evidence_id: str, data: bytes | None = None) -> str:
    parser = "json_event" if data is None or data.lstrip().startswith(b"{") else "linux_auth"
    return EvidenceAnalysisService(service).analyze(evidence_id, parser)["analysis_id"]


def _json_events(*, timestamps=("2026-10-18T10:00:00Z", "2026-10-18T10:02:00Z"), users=("alice", "alice"), types=("login", "login")) -> bytes:
    return b"".join(
        json.dumps({"timestamp": timestamp, "event_type": event_type, "attributes": {"user": user}}).encode() + b"\n"
        for timestamp, user, event_type in zip(timestamps, users, types)
    )


def _snapshot(service: TraceeService) -> dict[str, bytes]:
    root = service.vault_dir
    return {
        str(path.relative_to(root)): path.read_bytes()
        for base in ("objects", "records", "chain")
        for path in (root / base).rglob("*") if path.is_file()
    }


def _route(app, method: str, path: str):
    return next(route.endpoint for route in app.routes if getattr(route, "path", None) == path and method in getattr(route, "methods", set()))


def _run_ready_coroutine(coroutine):
    """Run the endpoint's immediate async body without Windows loop setup."""
    try:
        coroutine.send(None)
    except StopIteration as completed:
        return completed.value
    raise AssertionError("The endpoint unexpectedly suspended on asynchronous I/O")


def test_builtin_rules_are_stable_parser_specific_and_conservative() -> None:
    assert [item.rule.rule_id for item in BUILTIN_RULES] == ["same-user-event-linux_auth", "same-user-event-json_event"]
    assert {item.rule.version for item in BUILTIN_RULES} == {"1.0.0"}
    assert all(item.rule.minimum_supporting_observations == 2 for item in BUILTIN_RULES)
    assert len(rules_for_source("unsupported")) == 0
    assert [item.supported_source_types for item in rules_for_source("linux_auth")] == [("linux_auth",)]
    assert EVENT_TYPE_ATTRIBUTE == "event_type"


def test_systemd_journal_analysis_has_no_unsupported_builtin_reconstruction(tmp_path: Path) -> None:
    raw = b'{"__CURSOR":"cursor","__REALTIME_TIMESTAMP":"1792319400123456","MESSAGE":"journal record"}\n'
    service, evidence_id = _ingest(tmp_path, raw)
    analysis_id = EvidenceAnalysisService(service).analyze(evidence_id, "systemd_journal")["analysis_id"]

    with pytest.raises(ReconstructionError) as unsupported:
        ReconstructionService(service).reconstruct(evidence_id, analysis_id, 300)
    assert unsupported.value.code == "unsupported_source_type"
    assert not (service.vault_dir / "reconstructions").exists()


def test_reconstruction_projects_validated_event_type_and_preserves_provenance(tmp_path: Path) -> None:
    raw = _json_events()
    service, evidence_id = _ingest(tmp_path, raw)
    analysis_id = _analysis(service, evidence_id, raw)
    before = _snapshot(service)
    analysis_path = service.vault_dir / "analyses" / evidence_id / f"{analysis_id}.json"
    analysis_before = analysis_path.read_bytes()
    summary = ReconstructionService(service).reconstruct(evidence_id, analysis_id, 300)
    detail = ReconstructionService(service).get_reconstruction(
        evidence_id, summary["reconstruction_id"], hypothesis_offset=0,
        hypothesis_limit=25, skipped_offset=0, skipped_limit=25,
    )
    hypothesis = detail["hypotheses"][0]
    assert summary["hypothesis_count"] == 1
    assert hypothesis["event_type"] == "same_user_event_cluster"
    assert hypothesis["attributes"] == {"user": "alice", "event_type": "login"}
    assert len(hypothesis["supporting_observation_ids"]) == 2
    assert hypothesis["input_observation_ids"] == hypothesis["supporting_observation_ids"]
    assert "causality" in " ".join(hypothesis["limitations"])
    assert detail["analysis_id"] == analysis_id
    assert detail["source_sha256"] == hashlib.sha256(raw).hexdigest()
    assert _snapshot(service) == before
    assert analysis_path.read_bytes() == analysis_before


def test_minimum_support_identity_window_and_unresolved_time(tmp_path: Path) -> None:
    raw = _json_events(users=("alice", "bob"))
    service, evidence_id = _ingest(tmp_path, raw)
    analysis_id = _analysis(service, evidence_id, raw)
    result = ReconstructionService(service).reconstruct(evidence_id, analysis_id, 300)
    detail = ReconstructionService(service).get_reconstruction(
        evidence_id, result["reconstruction_id"], hypothesis_offset=0,
        hypothesis_limit=25, skipped_offset=0, skipped_limit=25,
    )
    assert all(item["interpretation"] == "insufficient_input" for item in detail["hypotheses"])
    assert {item["attributes"]["user"] for item in detail["hypotheses"]} == {"alice", "bob"}

    outside, outside_id = _ingest(tmp_path / "outside", _json_events(timestamps=("2026-10-18T10:00:00Z", "2026-10-18T10:20:00Z")))
    outside_analysis = _analysis(outside, outside_id)
    outside_run = ReconstructionService(outside).reconstruct(outside_id, outside_analysis, 60)
    assert outside_run["hypothesis_count"] == 2

    unknown_raw = b'{"timestamp":null,"event_type":"login","attributes":{"user":"alice"}}\n{"timestamp":null,"event_type":"login","attributes":{"user":"alice"}}\n'
    unknown, unknown_id = _ingest(tmp_path / "unknown", unknown_raw)
    unknown_analysis = _analysis(unknown, unknown_id)
    unknown_run = ReconstructionService(unknown).reconstruct(unknown_id, unknown_analysis, 300)
    unknown_detail = ReconstructionService(unknown).get_reconstruction(
        unknown_id, unknown_run["reconstruction_id"], hypothesis_offset=0,
        hypothesis_limit=25, skipped_offset=0, skipped_limit=25,
    )
    assert unknown_run["hypothesis_count"] == 2
    assert all(item["interpretation"] == "insufficient_input" for item in unknown_detail["hypotheses"])


def test_missing_identity_and_reserved_collision_are_explicit(tmp_path: Path) -> None:
    raw = _json_events()
    service, evidence_id = _ingest(tmp_path, raw)
    analysis_id = _analysis(service, evidence_id, raw)
    analysis_path = service.vault_dir / "analyses" / evidence_id / f"{analysis_id}.json"
    record = json.loads(analysis_path.read_text(encoding="utf-8"))
    for observation in record["observations"]:
        observation["attributes"].pop("user")
    for event in record["events"]:
        event["attributes"] = {}
    # Rehashing the stored analysis is intentionally not available as a production operation.
    # Direct structural mutation must be rejected by the analysis validator before reconstruction.
    analysis_path.write_text(json.dumps(record), encoding="utf-8")
    result = ReconstructionService(service).reconstruct(evidence_id, analysis_id, 300)
    detail = ReconstructionService(service).get_reconstruction(
        evidence_id, result["reconstruction_id"], hypothesis_offset=0,
        hypothesis_limit=25, skipped_offset=0, skipped_limit=25,
    )
    assert result["hypothesis_count"] == 0
    assert result["skipped_input_count"] == 2

    collision_raw = b'{"timestamp":"2026-10-18T10:00:00Z","event_type":"login","attributes":{"user":"alice","event_type":"spoofed"}}\n'
    collision, collision_id = _ingest(tmp_path / "collision", collision_raw)
    collision_analysis = _analysis(collision, collision_id)
    with pytest.raises(ReconstructionError) as caught:
        ReconstructionService(collision).reconstruct(collision_id, collision_analysis, 300)
    assert caught.value.code == "analysis_invalid"


def test_stale_evidence_mismatch_and_immutable_repeated_runs(tmp_path: Path) -> None:
    raw = _json_events()
    service, evidence_id = _ingest(tmp_path, raw)
    analysis_id = _analysis(service, evidence_id, raw)
    reconstructor = ReconstructionService(service)
    first = reconstructor.reconstruct(evidence_id, analysis_id, 300)
    second = reconstructor.reconstruct(evidence_id, analysis_id, 300)
    assert first["reconstruction_id"] != second["reconstruction_id"]
    assert len(list((service.vault_dir / "reconstructions" / evidence_id).glob("*.json"))) == 2

    # Changing source object content invalidates source verification before any run is served.
    service.vault.evidence_path(evidence_id).chmod(0o600)
    service.vault.evidence_path(evidence_id).write_bytes(b"changed")
    with pytest.raises(ReconstructionError) as stale_result:
        reconstructor.get_reconstruction(evidence_id, first["reconstruction_id"], hypothesis_offset=0, hypothesis_limit=25, skipped_offset=0, skipped_limit=25)
    assert stale_result.value.code == "stale_reconstruction"


def test_stale_source_prevents_new_reconstruction_and_malformed_analysis_is_rejected(tmp_path: Path) -> None:
    raw = _json_events()
    service, evidence_id = _ingest(tmp_path, raw)
    analysis_id = _analysis(service, evidence_id, raw)
    object_path = service.vault.evidence_path(evidence_id)
    object_path.chmod(0o600)
    object_path.write_bytes(b"changed before reconstruction")
    with pytest.raises(AnalysisError) as stale:
        ReconstructionService(service).reconstruct(evidence_id, analysis_id, 300)
    assert stale.value.code == "integrity_verification_failed"

    other, other_id = _ingest(tmp_path / "other", raw)
    other_analysis_id = _analysis(other, other_id, raw)
    path = other.vault_dir / "analyses" / other_id / f"{other_analysis_id}.json"
    path.write_text("{not-json", encoding="utf-8")
    with pytest.raises(AnalysisError) as malformed:
        ReconstructionService(other).reconstruct(other_id, other_analysis_id, 300)
    assert malformed.value.code == "analysis_invalid"


def test_reconstruction_digest_tamper_pagination_and_concurrent_writes(tmp_path: Path) -> None:
    raw = _json_events()
    service, evidence_id = _ingest(tmp_path, raw)
    analysis_id = _analysis(service, evidence_id, raw)
    reconstructor = ReconstructionService(service)
    with ThreadPoolExecutor(max_workers=4) as pool:
        summaries = list(pool.map(lambda _: reconstructor.reconstruct(evidence_id, analysis_id, 300), range(4)))
    assert len({item["reconstruction_id"] for item in summaries}) == 4
    listed, total = reconstructor.list_reconstructions(evidence_id, offset=1, limit=2)
    assert total == 4 and len(listed) == 2
    detail = reconstructor.get_reconstruction(evidence_id, summaries[0]["reconstruction_id"], hypothesis_offset=0, hypothesis_limit=1, skipped_offset=0, skipped_limit=1)
    assert detail["pagination"]["hypotheses"]["limit"] == 1
    path = service.vault_dir / "reconstructions" / evidence_id / f"{summaries[0]['reconstruction_id']}.json"
    record = json.loads(path.read_text(encoding="utf-8"))
    record["result_status"] = "modified"
    path.write_text(json.dumps(record), encoding="utf-8")
    with pytest.raises(ReconstructionError) as caught:
        reconstructor.get_reconstruction(evidence_id, summaries[0]["reconstruction_id"], hypothesis_offset=0, hypothesis_limit=25, skipped_offset=0, skipped_limit=25)
    assert caught.value.code == "reconstruction_invalid"


def test_reconstruction_api_routes_validation_and_audit(tmp_path: Path) -> None:
    raw = _json_events()
    service, evidence_id = _ingest(tmp_path, raw)
    analysis_id = _analysis(service, evidence_id, raw)
    app = create_app(service.vault_dir)
    route = _route(app, "POST", "/api/v1/evidence/{evidence_id}/analyses/{analysis_id}/reconstruct")

    async def call(payload: bytes):
        async def receive():
            return {"type": "http.request", "body": payload, "more_body": False}
        scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": "POST", "scheme": "http", "path": "/", "raw_path": b"/", "query_string": b"", "headers": [(b"content-type", b"application/json")], "client": ("127.0.0.1", 1234), "server": ("127.0.0.1", 8000), "root_path": ""}
        return await route(evidence_id, analysis_id, Request(scope, receive))

    invalid = _run_ready_coroutine(call(b'{"candidate_window_seconds":true}'))
    assert invalid.status_code == 422
    response = _run_ready_coroutine(call(b'{"candidate_window_seconds":300}'))
    assert response.status_code == 201
    summary = json.loads(response.body)
    entries = ActivityLog(service.vault_dir).recent()
    assert [entry["event_type"] for entry in entries[:2]] == ["evidence_reconstruction_completed", "evidence_reconstruction_started"]
    assert entries[0]["evidence_id"] == evidence_id
    schema = create_app().openapi()
    assert "/api/v1/reconstruction/rules" in schema["paths"]
    assert "/api/v1/evidence/{evidence_id}/reconstructions/{reconstruction_id}" in schema["paths"]
    result = _route(app, "GET", "/api/v1/evidence/{evidence_id}/reconstructions/{reconstruction_id}")(
        evidence_id, summary["reconstruction_id"], 0, 25, 0, 25,
    )
    assert result["reconstruction_id"] == summary["reconstruction_id"]
    assert isinstance(result["hypotheses"], list)
    assert result["pagination"]["hypotheses"]["total"] == summary["hypothesis_count"]
    assert result["pagination"]["hypotheses"]["total"] == len(result["hypotheses"])
    assert result["pagination"]["skipped_inputs"]["total"] == summary["skipped_input_count"]
    assert result["pagination"]["skipped_inputs"]["total"] == len(result["skipped_inputs"])
    assert result["evidence_id"] == evidence_id
    assert len(result["hypotheses"]) == 1
    hypothesis = result["hypotheses"][0]
    assert hypothesis["interpretation"] == "corroborated"
    assert len(hypothesis["supporting_observation_ids"]) == 2
    assert hypothesis["inference_rule_id"] == result["rule_versions"][0]["rule_id"]
    analysis_detail = EvidenceAnalysisService(service).get_analysis(
        evidence_id, analysis_id, offset=0, limit=25,
    )
    assert {item["evidence_id"] for item in analysis_detail["observations"]} == {evidence_id}
    listed = _route(app, "GET", "/api/v1/evidence/{evidence_id}/reconstructions")(
        evidence_id, 0, 25,
    )
    assert listed["pagination"]["total_reconstructions"] == 1
    assert listed["reconstructions"][0]["reconstruction_id"] == summary["reconstruction_id"]
    invalid = _route(app, "GET", "/api/v1/evidence/{evidence_id}/reconstructions/{reconstruction_id}")(
        evidence_id, "bad", 0, 25, 0, 25,
    )
    assert isinstance(invalid, JSONResponse) and invalid.status_code == 400


def test_rule_listing_does_not_write_activity_and_activity_chain_validates(tmp_path: Path) -> None:
    vault = tmp_path / "vault"
    vault.mkdir()
    log = ActivityLog(vault)
    app = create_app()
    result = _route(app, "GET", "/api/v1/reconstruction/rules")()
    assert len(result["rules"]) == 2
    assert not log.path.exists()
    log.append(event_type="evidence_reconstruction_started", actor="unauthenticated_local_client", outcome="accepted", evidence_id="TRACE-EV-000001")
    assert log.recent()[0]["event_type"] == "evidence_reconstruction_started"


@pytest.mark.parametrize("value", [True, -1, 1.0, "300", 86401])
def test_candidate_window_rejects_non_integer_or_out_of_range_values(value) -> None:
    with pytest.raises(ReconstructionError) as caught:
        ReconstructionService.validate_window(value)
    assert caught.value.code == "invalid_request"


def test_completion_audit_failure_truthfully_reports_persisted_run(tmp_path: Path, monkeypatch) -> None:
    raw = _json_events()
    service, evidence_id = _ingest(tmp_path, raw)
    analysis_id = _analysis(service, evidence_id, raw)
    original = ActivityLog.append

    def fail_completion(log, **kwargs):
        if kwargs.get("event_type") == "evidence_reconstruction_completed":
            raise ActivityLogIntegrityError("simulated audit integrity failure")
        return original(log, **kwargs)

    monkeypatch.setattr(ActivityLog, "append", fail_completion)
    endpoint = _route(create_app(service.vault_dir), "POST", "/api/v1/evidence/{evidence_id}/analyses/{analysis_id}/reconstruct")

    async def call():
        async def receive():
            return {"type": "http.request", "body": b'{"candidate_window_seconds":300}', "more_body": False}
        scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": "POST", "scheme": "http", "path": "/", "raw_path": b"/", "query_string": b"", "headers": [(b"content-type", b"application/json")], "client": ("127.0.0.1", 1234), "server": ("127.0.0.1", 8000), "root_path": ""}
        return await endpoint(evidence_id, analysis_id, Request(scope, receive))

    response = _run_ready_coroutine(call())
    body = json.loads(response.body)
    assert response.status_code == 500
    assert body["operation"]["completed"] is True
    assert body["operation"]["type"] == "evidence_reconstruction"
    assert body["audit"]["recorded"] is False
    assert len(list((service.vault_dir / "reconstructions" / evidence_id).glob("*.json"))) == 1
