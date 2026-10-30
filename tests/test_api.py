from __future__ import annotations

import json
import hashlib
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from tracee.activity import ActivityLog, ActivityLogError
from tracee.api import create_app
from tracee.services import TraceeService
from tracee.vault import FilesystemVaultStore

API_TEST_TOKEN = "test-api-access-token-" + "a" * 48


@pytest.fixture(autouse=True)
def configured_api_credential(monkeypatch):
    monkeypatch.setenv("TRACEE_API_TOKEN", API_TEST_TOKEN)


def client_for(vault: Path | None, *, token: str = API_TEST_TOKEN) -> TestClient:
    return TestClient(
        create_app(vault),
        headers={"Authorization": f"Bearer {token}"},
    )


def unauthenticated_client_for(vault: Path | None) -> TestClient:
    return TestClient(create_app(vault))


def evidence_snapshot(vault: Path) -> dict[str, bytes]:
    return {
        str(path.relative_to(vault)): path.read_bytes()
        for directory in ("objects", "records", "chain")
        for path in (vault / directory).rglob("*")
        if path.is_file()
    }


def initialized_vault(vault: Path) -> None:
    FilesystemVaultStore(vault).initialize()


def upload_client(vault: Path, monkeypatch, *, token: str = "t" * 40) -> TestClient:
    monkeypatch.setenv("TRACEE_API_TOKEN", token)
    monkeypatch.setenv("TRACEE_UPLOAD_TOKEN", token)
    return client_for(vault, token=token)


def test_health_does_not_create_vault(tmp_path: Path) -> None:
    vault = tmp_path / "not-created"
    response = unauthenticated_client_for(vault).get("/health")
    assert response.status_code == 200
    assert response.json() == {"service": "TRACEE", "status": "ok"}
    assert not vault.exists()


def test_sensitive_api_route_categories_require_valid_bearer_on_populated_vault(
    tmp_path: Path,
    monkeypatch,
    caplog,
) -> None:
    vault = tmp_path / "populated-vault"
    source = tmp_path / "synthetic-events.jsonl"
    source.write_text(
        '{"timestamp":"2026-10-18T10:00:00Z","event_type":"login","attributes":{"user":"synthetic-user"}}\n'
        '{"timestamp":"2026-10-18T10:02:00Z","event_type":"login","attributes":{"user":"synthetic-user"}}\n',
        encoding="utf-8",
    )
    metadata, _ = TraceeService(vault).ingest(source)
    authorized = client_for(vault)
    unauthorized = unauthenticated_client_for(vault)
    invalid_token_sentinel = "not-the-configured-api-secret"
    invalid = client_for(vault, token=invalid_token_sentinel)

    analysis = authorized.post(
        f"/api/v1/evidence/{metadata.evidence_id}/analyze",
        json={"parser": "json_event"},
    ).json()
    analysis_id = analysis["analysis_id"]
    reconstruction = authorized.post(
        f"/api/v1/evidence/{metadata.evidence_id}/analyses/{analysis_id}/reconstruct",
        json={"candidate_window_seconds": 300},
    ).json()
    reconstruction_id = reconstruction["reconstruction_id"]
    monkeypatch.setenv("TRACEE_UPLOAD_TOKEN", API_TEST_TOKEN)

    routes = [
        ("GET", "/api/v1/evidence", {}, 200),
        ("GET", f"/api/v1/evidence/{metadata.evidence_id}", {}, 200),
        ("GET", f"/api/v1/evidence/{metadata.evidence_id}/verify", {}, 200),
        ("POST", f"/api/v1/evidence/{metadata.evidence_id}/analyze", {"json": {"parser": "json_event"}}, 201),
        ("GET", f"/api/v1/evidence/{metadata.evidence_id}/analyses", {}, 200),
        ("GET", f"/api/v1/evidence/{metadata.evidence_id}/analyses/{analysis_id}?offset=0&limit=10", {}, 200),
        ("GET", f"/api/v1/evidence/{metadata.evidence_id}/analyses/{analysis_id}/timeline?offset=0&limit=10", {}, 200),
        ("GET", "/api/v1/reconstruction/rules", {}, 200),
        ("POST", f"/api/v1/evidence/{metadata.evidence_id}/analyses/{analysis_id}/reconstruct", {"json": {"candidate_window_seconds": 300}}, 201),
        ("GET", f"/api/v1/evidence/{metadata.evidence_id}/reconstructions", {}, 200),
        ("GET", f"/api/v1/evidence/{metadata.evidence_id}/reconstructions/{reconstruction_id}", {}, 200),
        ("GET", "/api/v1/activity", {}, 200),
        ("POST", "/api/v1/evidence", {"files": {"file": ("new-synthetic.log", b"new synthetic bytes")}}, 201),
    ]
    for method, path, kwargs, expected_status in routes:
        missing = unauthorized.request(method, path, **kwargs)
        bad = invalid.request(method, path, **kwargs)
        assert missing.status_code == 401, (method, path, missing.text)
        assert bad.status_code == 401, (method, path, bad.text)
        assert missing.json()["error"]["code"] == "unauthorized"
        assert bad.json()["error"]["code"] == "unauthorized"
        assert API_TEST_TOKEN not in missing.text
        assert invalid_token_sentinel not in bad.text

        accepted = authorized.request(method, path, **kwargs)
        assert accepted.status_code == expected_status, (method, path, accepted.text)

    assert invalid_token_sentinel not in caplog.text
    assert API_TEST_TOKEN not in caplog.text


def test_health_remains_public_and_api_auth_configuration_fails_closed(
    tmp_path: Path,
    monkeypatch,
    caplog,
) -> None:
    vault = tmp_path / "vault"
    initialized_vault(vault)
    monkeypatch.delenv("TRACEE_API_TOKEN", raising=False)
    client = unauthenticated_client_for(vault)

    health = client.get("/health")
    protected = client.get("/api/v1/evidence")
    assert health.status_code == 200
    assert health.json() == {"service": "TRACEE", "status": "ok"}
    assert protected.status_code == 503
    assert protected.json()["error"]["code"] == "api_auth_not_configured"
    assert API_TEST_TOKEN not in protected.text

    weak_token_sentinel = "short-secret-sentinel"
    monkeypatch.setenv("TRACEE_API_TOKEN", weak_token_sentinel)
    protected = client.get("/api/v1/evidence")
    assert protected.status_code == 503
    assert protected.json()["error"]["code"] == "api_auth_misconfigured"
    assert weak_token_sentinel not in protected.text
    assert weak_token_sentinel not in caplog.text


def test_openapi_and_interactive_docs_are_configurable(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("TRACEE_API_DOCS_ENABLED", raising=False)
    disabled = client_for(tmp_path / "vault")
    assert disabled.get("/openapi.json").status_code == 404
    assert disabled.get("/docs").status_code == 404
    assert disabled.get("/redoc").status_code == 404

    monkeypatch.setenv("TRACEE_API_DOCS_ENABLED", "1")
    enabled = client_for(tmp_path / "vault")
    assert enabled.get("/openapi.json").status_code == 200
    assert enabled.get("/docs").status_code == 200
    assert enabled.get("/redoc").status_code == 200


def test_local_ui_is_served_by_the_api_app(tmp_path: Path) -> None:
    client = client_for(tmp_path / "uncreated")
    response = client.get("/")
    assert response.status_code == 200
    assert "TRACEE | Evidence Workspace" in response.text
    assert client.get("/styles.css").status_code == 200
    assert client.get("/app.js").status_code == 200
    assert not (tmp_path / "uncreated").exists()


def test_unconfigured_and_unavailable_vault(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("TRACEE_API_VAULT_DIR", raising=False)
    response = client_for(None).get("/api/v1/evidence")
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "vault_not_configured"

    response = client_for(tmp_path / "missing").get("/api/v1/evidence")
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "vault_unavailable"
    assert str(tmp_path) not in response.text
    assert not (tmp_path / "missing").exists()

    initialized = tmp_path / "no-records-directory"
    initialized.mkdir()
    response = client_for(initialized).get("/api/v1/evidence")
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "vault_unavailable"
    assert str(tmp_path) not in response.text


def test_empty_inventory(tmp_path: Path) -> None:
    vault = tmp_path / "vault"
    FilesystemVaultStore(vault).initialize()
    response = client_for(vault).get("/api/v1/evidence")
    assert response.status_code == 200
    assert response.json() == {"evidence": []}


def _evidence(tmp_path: Path) -> Path:
    source = tmp_path / "sample.log"
    source.write_text("real evidence\n", encoding="utf-8")
    return source


def test_list_retrieve_verify_and_evidence_read_only(tmp_path: Path) -> None:
    vault = tmp_path / "vault"
    service = TraceeService(vault)
    metadata, _ = service.ingest(_evidence(tmp_path))
    client = client_for(vault)
    before = evidence_snapshot(vault)

    listed = client.get("/api/v1/evidence")
    assert listed.status_code == 200
    assert listed.json() == {"evidence": [metadata.to_dict()]}
    retrieved = client.get(f"/api/v1/evidence/{metadata.evidence_id}")
    assert retrieved.status_code == 200
    assert retrieved.json() == metadata.to_dict()
    verified = client.get(f"/api/v1/evidence/{metadata.evidence_id}/verify")
    assert verified.status_code == 200
    assert verified.json() == {"state": "VALID", "evidence_id": metadata.evidence_id, "message": "Evidence, metadata, and chain verification successful."}
    assert evidence_snapshot(vault) == before
    activity = client.get("/api/v1/activity")
    assert activity.status_code == 200
    events = activity.json()["activity"]
    assert [event["event_type"] for event in events] == [
        "integrity_verification",
        "evidence_viewed",
    ]
    assert events[0]["outcome"] == "VALID"
    assert all(event["actor"] == "local_api_token" for event in events)
    for event in events:
        stamp = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
        assert stamp.tzinfo is not None
        assert stamp.utcoffset() == timezone.utc.utcoffset(stamp)
        assert event["previous_hash"]
        assert len(event["record_hash"]) == 64
    assert evidence_snapshot(vault) == before


def test_missing_and_malformed_ids(tmp_path: Path) -> None:
    vault = tmp_path / "vault"
    TraceeService(vault).ingest(_evidence(tmp_path))
    client = client_for(vault)
    for route in ("/api/v1/evidence/not-an-id", "/api/v1/evidence/not-an-id/verify"):
        response = client.get(route)
        assert response.status_code == 400
        assert response.json()["error"]["code"] == "invalid_evidence_id"
    response = client.get("/api/v1/evidence/TRACE-EV-000099")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "evidence_not_found"


def test_verify_tampered_and_missing_evidence(tmp_path: Path) -> None:
    vault = tmp_path / "vault"
    service = TraceeService(vault)
    metadata, _ = service.ingest(_evidence(tmp_path))
    object_path = service.vault.evidence_path(metadata.evidence_id)
    object_path.chmod(0o600)
    object_path.write_bytes(b"changed evidence")
    response = client_for(vault).get(f"/api/v1/evidence/{metadata.evidence_id}/verify")
    assert response.json()["state"] == "TAMPERED"

    object_path.unlink()
    response = client_for(vault).get(f"/api/v1/evidence/{metadata.evidence_id}/verify")
    assert response.json()["state"] == "MISSING"
    activity = client_for(vault).get("/api/v1/activity").json()["activity"]
    assert [event["outcome"] for event in activity[:2]] == ["MISSING", "TAMPERED"]


def test_inventory_reports_malformed_or_unreadable_metadata(tmp_path: Path) -> None:
    vault = tmp_path / "vault"
    TraceeService(vault).ingest(_evidence(tmp_path))
    record = vault / "records" / "TRACE-EV-000001.json"
    record.write_text("{invalid", encoding="utf-8")
    response = client_for(vault).get("/api/v1/evidence")
    assert response.status_code == 500
    assert response.json()["error"]["code"] == "unreadable_metadata"
    assert str(vault) not in response.text
    assert "JSON" not in response.text

    record.unlink()
    (vault / "records" / "bad.json").write_text("{}", encoding="utf-8")
    response = client_for(vault).get("/api/v1/evidence")
    assert response.status_code == 500
    assert response.json()["error"]["code"] == "malformed_metadata"
    assert str(vault) not in response.text

def test_unexpected_api_exception_has_stable_sanitized_response(
    tmp_path: Path, monkeypatch
) -> None:
    vault = tmp_path / "vault"
    FilesystemVaultStore(vault).initialize()

    def raise_unexpected_service_error(_root):
        raise RuntimeError("private parser detail at C:\\internal\\vault")

    monkeypatch.setattr(
        "tracee.api.TraceeService",
        raise_unexpected_service_error,
    )

    client = TestClient(
        create_app(vault),
        headers={"Authorization": f"Bearer {API_TEST_TOKEN}"},
        raise_server_exceptions=False,
    )
    response = client.get("/api/v1/evidence")

    assert response.status_code == 500
    assert response.json() == {
        "error": {
            "code": "internal_error",
            "message": "An unexpected internal error occurred.",
        }
    }
    assert "private parser detail" not in response.text
    assert "C:\\internal\\vault" not in response.text


def test_activity_empty_read_does_not_create_audit_directory(tmp_path: Path) -> None:
    vault = tmp_path / "vault"
    initialized_vault(vault)
    response = client_for(vault).get("/api/v1/activity")
    assert response.status_code == 200
    assert response.json() == {"activity": [], "limit": 50}
    assert not (vault / "audit").exists()


def test_upload_is_disabled_without_token_and_rejects_weak_or_bad_tokens(
    tmp_path: Path, monkeypatch
) -> None:
    vault = tmp_path / "vault"
    initialized_vault(vault)
    before = evidence_snapshot(vault)
    monkeypatch.delenv("TRACEE_UPLOAD_TOKEN", raising=False)
    response = client_for(vault).post(
        "/api/v1/evidence", files={"file": ("sample.log", b"bytes")}
    )
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "upload_disabled"
    assert evidence_snapshot(vault) == before
    assert not (vault / "audit").exists()

    monkeypatch.setenv("TRACEE_UPLOAD_TOKEN", "weak")
    response = client_for(vault).post(
        "/api/v1/evidence",
        files={"file": ("sample.log", b"bytes")},
        headers={"Authorization": f"Bearer {API_TEST_TOKEN}"},
    )
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "upload_token_misconfigured"

    monkeypatch.setenv("TRACEE_API_TOKEN", "a" * 40)
    monkeypatch.setenv("TRACEE_UPLOAD_TOKEN", "b" * 40)
    response = client_for(vault, token="a" * 40).post(
        "/api/v1/evidence", files={"file": ("sample.log", b"bytes")}
    )
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "upload_token_misconfigured"
    assert "a" * 40 not in response.text
    assert "b" * 40 not in response.text

    client = upload_client(vault, monkeypatch)
    for authorization in ("", "Bearer " + "x" * 40):
        headers = {"Authorization": authorization}
        response = client.post(
            "/api/v1/evidence", files={"file": ("sample.log", b"bytes")}, headers=headers
        )
        assert response.status_code == 401
        assert response.json()["error"]["code"] == "unauthorized"
        assert "t" * 40 not in response.text
    assert evidence_snapshot(vault) == before
    assert not (vault / "audit").exists()


def test_upload_rejects_cross_origin_and_does_not_ingest(
    tmp_path: Path, monkeypatch
) -> None:
    vault = tmp_path / "vault"
    initialized_vault(vault)
    before = evidence_snapshot(vault)
    client = upload_client(vault, monkeypatch)
    response = client.post(
        "/api/v1/evidence",
        files={"file": ("sample.log", b"bytes")},
        headers={"Authorization": "Bearer " + "t" * 40, "Origin": "https://attacker.example"},
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "invalid_origin"
    assert evidence_snapshot(vault) == before
    assert not (vault / "audit").exists()


def test_upload_uses_real_ingestion_preserves_bytes_and_audits(
    tmp_path: Path, monkeypatch
) -> None:
    vault = tmp_path / "vault"
    initialized_vault(vault)
    client = upload_client(vault, monkeypatch)
    payload = b"\x00raw\r\nbytes\xff"
    response = client.post(
        "/api/v1/evidence",
        files={"file": (r"C:\\operator\\capture.log", payload, "application/octet-stream")},
        headers={"Authorization": "Bearer " + "t" * 40},
    )
    assert response.status_code == 201
    body = response.json()
    evidence_id = body["evidence_id"]
    assert evidence_id == "TRACE-EV-000001"
    assert body["metadata"]["evidence_id"] == evidence_id
    assert body["metadata"]["original_filename"] == "capture.log"
    assert body["metadata"]["size_bytes"] == len(payload)
    assert body["metadata"]["sha256"] == hashlib.sha256(payload).hexdigest()
    assert body["chain_sequence"] == 1
    object_path = vault / "objects" / evidence_id / "evidence.bin"
    assert object_path.read_bytes() == payload
    verify = client.get(f"/api/v1/evidence/{evidence_id}/verify")
    assert verify.status_code == 200
    assert verify.json()["state"] == "VALID"
    events = client.get("/api/v1/activity").json()["activity"]
    assert [event["event_type"] for event in events] == [
        "integrity_verification", "evidence_acquired", "evidence_acquisition_started"
    ]
    acquired = events[1]
    assert acquired["actor"] == "local_upload_token"
    assert acquired["outcome"] == "success"
    assert acquired["filename"] == "capture.log"
    assert acquired["sha256"] == hashlib.sha256(payload).hexdigest()
    assert "t" * 40 not in response.text
    assert str(vault) not in response.text


def test_synthetic_demo_workflow_through_real_api(
    tmp_path: Path, monkeypatch
) -> None:
    """Exercise the complete synthetic local demo using the real API app."""
    vault = tmp_path / "demo-vault"
    initialized_vault(vault)
    client = upload_client(vault, monkeypatch)

    health = client.get("/health")
    assert health.status_code == 200
    assert health.json() == {"service": "TRACEE", "status": "ok"}

    empty_inventory = client.get("/api/v1/evidence")
    assert empty_inventory.status_code == 200
    assert empty_inventory.json() == {"evidence": []}

    source = (
        b'{"timestamp":"2026-10-18T10:00:00Z","event_type":"login",'
        b'"attributes":{"user":"synthetic-user"}}\n'
        b'{"timestamp":"2026-10-18T10:02:00Z","event_type":"login",'
        b'"attributes":{"user":"synthetic-user"}}\n'
    )
    upload = client.post(
        "/api/v1/evidence",
        files={"file": ("synthetic-login-events.jsonl", source, "application/jsonl")},
        headers={"Authorization": "Bearer " + "t" * 40},
    )
    assert upload.status_code == 201
    uploaded = upload.json()
    evidence_id = uploaded["evidence_id"]
    assert uploaded["metadata"]["evidence_id"] == evidence_id
    assert uploaded["metadata"]["original_filename"] == "synthetic-login-events.jsonl"
    assert uploaded["metadata"]["size_bytes"] == len(source)
    assert uploaded["metadata"]["sha256"] == hashlib.sha256(source).hexdigest()
    assert uploaded["chain_sequence"] == 1

    inventory = client.get("/api/v1/evidence")
    assert inventory.status_code == 200
    assert inventory.json()["evidence"] == [uploaded["metadata"]]
    metadata = client.get(f"/api/v1/evidence/{evidence_id}")
    assert metadata.status_code == 200
    assert metadata.json() == uploaded["metadata"]

    verification = client.get(f"/api/v1/evidence/{evidence_id}/verify")
    assert verification.status_code == 200
    assert verification.json()["state"] == "VALID"
    assert verification.json()["evidence_id"] == evidence_id

    analysis_response = client.post(
        f"/api/v1/evidence/{evidence_id}/analyze", json={"parser": "json_event"}
    )
    assert analysis_response.status_code == 201
    analysis = analysis_response.json()
    analysis_id = analysis["analysis_id"]
    assert analysis["evidence_id"] == evidence_id
    assert analysis["event_count"] == 2
    assert analysis["source_sha256"] == uploaded["metadata"]["sha256"]

    first_page = client.get(
        f"/api/v1/evidence/{evidence_id}/analyses/{analysis_id}?offset=0&limit=1"
    )
    second_page = client.get(
        f"/api/v1/evidence/{evidence_id}/analyses/{analysis_id}?offset=1&limit=1"
    )
    assert first_page.status_code == second_page.status_code == 200
    first_detail, second_detail = first_page.json(), second_page.json()
    assert first_detail["pagination"]["total_events"] == 2
    assert first_detail["pagination"]["offset"] == 0
    assert second_detail["pagination"]["offset"] == 1
    events = first_detail["events"] + second_detail["events"]
    observations = first_detail["observations"] + second_detail["observations"]
    assert [event["temporal_extent"]["earliest_utc"] for event in events] == [
        "2026-10-18T10:00:00Z", "2026-10-18T10:02:00Z"
    ]
    assert len(observations) == 2
    assert all(item["evidence_id"] == evidence_id for item in observations)
    assert [item["source_locator"] for item in observations] == ["line:1", "line:2"]
    assert all(
        observation["observation_id"] in event["source_observation_ids"]
        for event, observation in zip(events, observations)
    )

    reconstruction_response = client.post(
        f"/api/v1/evidence/{evidence_id}/analyses/{analysis_id}/reconstruct",
        json={"candidate_window_seconds": 300},
    )
    assert reconstruction_response.status_code == 201
    reconstruction = reconstruction_response.json()
    reconstruction_id = reconstruction["reconstruction_id"]
    assert reconstruction["evidence_id"] == evidence_id
    assert reconstruction["analysis_id"] == analysis_id
    assert reconstruction["hypothesis_count"] == 1

    reconstruction_list = client.get(f"/api/v1/evidence/{evidence_id}/reconstructions")
    assert reconstruction_list.status_code == 200
    listed_runs = reconstruction_list.json()
    assert listed_runs["pagination"]["total_reconstructions"] == 1
    assert listed_runs["reconstructions"][0]["reconstruction_id"] == reconstruction_id

    reconstruction_detail = client.get(
        f"/api/v1/evidence/{evidence_id}/reconstructions/{reconstruction_id}"
        "?hypothesis_offset=0&hypothesis_limit=1&skipped_offset=0&skipped_limit=1"
    )
    assert reconstruction_detail.status_code == 200
    detail = reconstruction_detail.json()
    assert detail["hypothesis_count"] == 1
    assert detail["pagination"]["hypotheses"]["total"] == detail["hypothesis_count"]
    assert detail["pagination"]["skipped_inputs"]["total"] == detail["skipped_input_count"]
    hypothesis = detail["hypotheses"][0]
    assert hypothesis["interpretation"] == "corroborated"
    assert len(hypothesis["supporting_observation_ids"]) == 2
    assert set(hypothesis["supporting_observation_ids"]) == {
        item["observation_id"] for item in observations
    }
    # Both observations trace to this one evidence record; this test does not
    # treat a rule-threshold match as independent corroboration or causation.
    assert {item["evidence_id"] for item in observations} == {evidence_id}

    timeline_first = client.get(
        f"/api/v1/evidence/{evidence_id}/analyses/{analysis_id}/timeline?offset=0&limit=1"
    )
    timeline_second = client.get(
        f"/api/v1/evidence/{evidence_id}/analyses/{analysis_id}/timeline?offset=1&limit=1"
    )
    assert timeline_first.status_code == timeline_second.status_code == 200
    first_timeline, second_timeline = timeline_first.json(), timeline_second.json()
    assert first_timeline["pagination"]["total"] == 2
    timeline_entries = first_timeline["entries"] + second_timeline["entries"]
    assert [item["temporal_extent"]["earliest_utc"] for item in timeline_entries] == [
        "2026-10-18T10:00:00Z", "2026-10-18T10:02:00Z"
    ]
    assert all(
        item["source_observations"][0]["evidence_id"] == evidence_id
        and item["source_observation_ids"] == [item["source_observations"][0]["observation_id"]]
        for item in timeline_entries
    )

    final_verification = client.get(f"/api/v1/evidence/{evidence_id}/verify")
    assert final_verification.status_code == 200
    assert final_verification.json()["state"] == "VALID"
    chain = TraceeService(vault).verify_chain()
    assert len(chain) == 1
    assert chain[0].evidence_id == evidence_id
    assert chain[0].sequence == uploaded["chain_sequence"]

    activity_response = client.get("/api/v1/activity")
    assert activity_response.status_code == 200
    activity = activity_response.json()["activity"]
    activity_types = {item["event_type"] for item in activity}
    assert {
        "evidence_acquired",
        "integrity_verification",
        "evidence_analysis_completed",
        "evidence_reconstruction_completed",
    } <= activity_types
    assert any(
        item["event_type"] == "evidence_acquired"
        and item["evidence_id"] == evidence_id
        and item["outcome"] == "success"
        for item in activity
    )
    assert sum(
        item["event_type"] == "integrity_verification"
        and item["evidence_id"] == evidence_id
        and item["outcome"] == "VALID"
        for item in activity
    ) >= 2


def test_upload_validation_size_duplicate_and_temp_cleanup(
    tmp_path: Path, monkeypatch
) -> None:
    vault = tmp_path / "vault"
    initialized_vault(vault)
    temporary = tmp_path / "temp"
    temporary.mkdir()
    monkeypatch.setattr("tracee.api.tempfile.tempdir", str(temporary))
    client = upload_client(vault, monkeypatch)
    headers = {"Authorization": "Bearer " + "t" * 40}

    malformed = client.post(
        "/api/v1/evidence", files={"other": ("wrong.bin", b"x")}, headers=headers
    )
    assert malformed.status_code == 400
    assert malformed.json()["error"]["code"] == "unexpected_form_field"

    multiple = client.post(
        "/api/v1/evidence",
        files=[("file", ("one.bin", b"one")), ("file", ("two.bin", b"two"))],
        headers=headers,
    )
    assert multiple.status_code == 400
    assert multiple.json()["error"]["code"] == "invalid_upload"

    empty = client.post(
        "/api/v1/evidence", files={"file": ("empty.bin", b"")}, headers=headers
    )
    assert empty.status_code == 400
    assert empty.json()["error"]["code"] == "empty_file"

    monkeypatch.setenv("TRACEE_MAX_UPLOAD_BYTES", "4")
    oversized = client.post(
        "/api/v1/evidence", files={"file": ("large.bin", b"12345")}, headers=headers
    )
    assert oversized.status_code == 413
    assert oversized.json()["error"]["code"] == "upload_too_large"
    monkeypatch.setenv("TRACEE_MAX_UPLOAD_BYTES", "not-a-size")
    invalid_limit = client.post(
        "/api/v1/evidence", files={"file": ("small.bin", b"x")}, headers=headers
    )
    assert invalid_limit.status_code == 503
    assert invalid_limit.json()["error"]["code"] == "upload_configuration_invalid"
    assert list(temporary.iterdir()) == []
    monkeypatch.delenv("TRACEE_MAX_UPLOAD_BYTES")

    success = client.post(
        "/api/v1/evidence", files={"file": ("same.bin", b"same bytes")}, headers=headers
    )
    assert success.status_code == 201
    duplicate = client.post(
        "/api/v1/evidence", files={"file": ("renamed.bin", b"same bytes")}, headers=headers
    )
    assert duplicate.status_code == 409
    assert duplicate.json()["error"]["code"] == "duplicate_evidence"
    events = client.get("/api/v1/activity").json()["activity"]
    assert any(
        event["event_type"] == "evidence_acquisition_failed"
        and event["outcome"] == "duplicate_evidence"
        for event in events
    )
    assert list(temporary.iterdir()) == []


def test_upload_rejects_missing_or_malformed_vault_without_initializing(
    tmp_path: Path, monkeypatch
) -> None:
    missing = tmp_path / "missing-vault"
    client = upload_client(missing, monkeypatch)
    response = client.post(
        "/api/v1/evidence",
        files={"file": ("evidence.bin", b"bytes")},
        headers={"Authorization": "Bearer " + "t" * 40},
    )
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "vault_unavailable"
    assert not missing.exists()
    assert str(tmp_path) not in response.text

    malformed = tmp_path / "malformed-vault"
    malformed.mkdir()
    client = upload_client(malformed, monkeypatch)
    response = client.post(
        "/api/v1/evidence",
        files={"file": ("evidence.bin", b"bytes")},
        headers={"Authorization": "Bearer " + "t" * 40},
    )
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "vault_unavailable"
    assert set(path.name for path in malformed.iterdir()) == set()

    monkeypatch.delenv("TRACEE_API_VAULT_DIR", raising=False)
    unconfigured_client = client_for(None, token="t" * 40)
    response = unconfigured_client.post(
        "/api/v1/evidence",
        files={"file": ("evidence.bin", b"bytes")},
        headers={"Authorization": "Bearer " + "t" * 40},
    )
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "vault_not_configured"


def test_upload_storage_failure_records_failure_and_cleans_temp(
    tmp_path: Path, monkeypatch
) -> None:
    vault = tmp_path / "vault"
    initialized_vault(vault)
    (vault / "chain" / "chain.jsonl").write_text("malformed chain\n", encoding="utf-8")
    temporary = tmp_path / "temp"
    temporary.mkdir()
    monkeypatch.setattr("tracee.api.tempfile.tempdir", str(temporary))
    client = upload_client(vault, monkeypatch)
    response = client.post(
        "/api/v1/evidence",
        files={"file": ("evidence.bin", b"bytes")},
        headers={"Authorization": "Bearer " + "t" * 40},
    )
    assert response.status_code == 500
    assert response.json()["error"]["code"] == "storage_failure"
    assert str(vault) not in response.text
    events = client.get("/api/v1/activity").json()["activity"]
    assert events[0]["event_type"] == "evidence_acquisition_failed"
    assert events[0]["outcome"] == "storage_failure"
    assert list(temporary.iterdir()) == []
    assert list((vault / "records").glob("*.json")) == []


def test_upload_does_not_accept_a_server_path(tmp_path: Path, monkeypatch) -> None:
    vault = tmp_path / "vault"
    initialized_vault(vault)
    before = evidence_snapshot(vault)
    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"secret source")
    client = upload_client(vault, monkeypatch)
    response = client.post(
        "/api/v1/evidence",
        json={"source_path": str(outside)},
        headers={"Authorization": "Bearer " + "t" * 40},
    )
    assert response.status_code == 415
    assert response.json()["error"]["code"] == "unsupported_media_type"
    assert evidence_snapshot(vault) == before

    response = client.post(
        "/api/v1/evidence",
        files={"file": (None, str(outside))},
        headers={"Authorization": "Bearer " + "t" * 40},
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "missing_file"
    assert str(outside) not in response.text


def test_upload_rejects_unusable_filename(tmp_path: Path, monkeypatch) -> None:
    vault = tmp_path / "vault"
    initialized_vault(vault)
    before = evidence_snapshot(vault)
    client = upload_client(vault, monkeypatch)
    response = client.post(
        "/api/v1/evidence",
        files={"file": ("..", b"bytes")},
        headers={"Authorization": "Bearer " + "t" * 40},
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_filename"
    assert evidence_snapshot(vault) == before


def test_failed_completion_audit_reports_stored_operation_honestly(
    tmp_path: Path, monkeypatch
) -> None:
    vault = tmp_path / "vault"
    initialized_vault(vault)
    client = upload_client(vault, monkeypatch)
    real_append = ActivityLog.append

    def corrupt_before_completion(self, **kwargs):
        if kwargs.get("event_type") == "evidence_acquired":
            path = self.path
            entries = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
            entries[0]["outcome"] = "changed"
            path.write_text(
                "".join(json.dumps(entry) + "\n" for entry in entries),
                encoding="utf-8",
            )
        return real_append(self, **kwargs)

    monkeypatch.setattr(ActivityLog, "append", corrupt_before_completion)
    response = client.post(
        "/api/v1/evidence",
        files={"file": ("evidence.bin", b"real bytes")},
        headers={"Authorization": "Bearer " + "t" * 40},
    )
    assert response.status_code == 500
    body = response.json()
    assert body["error"]["code"] == "activity_log_invalid"
    assert body["operation"]["completed"] is True
    assert body["operation"]["evidence_stored"] is True
    assert body["operation"]["evidence_id"] == "TRACE-EV-000001"
    assert body["audit"]["recorded"] is False
    assert (vault / "objects" / "TRACE-EV-000001" / "evidence.bin").read_bytes() == b"real bytes"
    assert "changed" not in response.text


def test_activity_integrity_detects_tampering_reordering_and_malformed_data(
    tmp_path: Path,
) -> None:
    vault = tmp_path / "vault"
    initialized_vault(vault)
    log = ActivityLog(vault)
    log.append(
        event_type="evidence_viewed",
        actor="unauthenticated_local_client",
        outcome="success",
        evidence_id="TRACE-EV-000001",
    )
    log.append(
        event_type="evidence_viewed",
        actor="unauthenticated_local_client",
        outcome="success",
        evidence_id="TRACE-EV-000002",
    )
    path = vault / "audit" / "activity.jsonl"
    lines = path.read_text(encoding="utf-8").splitlines()

    lines[0], lines[1] = lines[1], lines[0]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with pytest.raises(ActivityLogError):
        log.recent()

    path.write_text("not-json\n", encoding="utf-8")
    with pytest.raises(ActivityLogError):
        log.recent()


def test_activity_api_returns_sanitized_tamper_error(tmp_path: Path) -> None:
    vault = tmp_path / "vault"
    initialized_vault(vault)
    log = ActivityLog(vault)
    log.append(
        event_type="evidence_viewed",
        actor="unauthenticated_local_client",
        outcome="success",
        evidence_id="TRACE-EV-000001",
    )
    log.path.write_text("secret parser error at " + str(vault) + "\n", encoding="utf-8")
    response = client_for(vault).get("/api/v1/activity")
    assert response.status_code == 500
    assert response.json()["error"]["code"] == "activity_log_invalid"
    assert str(vault) not in response.text
    assert "secret parser error" not in response.text


def test_activity_concurrent_appends_preserve_a_valid_chain(tmp_path: Path) -> None:
    vault = tmp_path / "vault"
    initialized_vault(vault)
    log = ActivityLog(vault)
    barrier = threading.Barrier(12)

    def append_one(index: int) -> None:
        barrier.wait()
        log.append(
            event_type="evidence_viewed",
            actor="unauthenticated_local_client",
            outcome="success",
            evidence_id=f"TRACE-EV-{index + 1:06d}",
        )

    with ThreadPoolExecutor(max_workers=12) as pool:
        list(pool.map(append_one, range(12)))
    entries = log.recent(200)
    assert len(entries) == 12
    assert len({entry["event_id"] for entry in entries}) == 12
    assert entries[0]["previous_hash"] == entries[1]["record_hash"]


def test_activity_reads_and_appends_do_not_modify_evidence_or_chain(
    tmp_path: Path,
) -> None:
    vault = tmp_path / "vault"
    service = TraceeService(vault)
    metadata, _ = service.ingest(_evidence(tmp_path))
    before = evidence_snapshot(vault)
    client = client_for(vault)
    client.get(f"/api/v1/evidence/{metadata.evidence_id}")
    client.get(f"/api/v1/evidence/{metadata.evidence_id}/verify")
    audit_before = (vault / "audit" / "activity.jsonl").read_bytes()
    activity = client.get("/api/v1/activity")
    audit_after = (vault / "audit" / "activity.jsonl").read_bytes()
    assert activity.status_code == 200
    assert audit_after == audit_before
    assert evidence_snapshot(vault) == before
