"""Comprehensive tests for the One-Hour Hackathon Integration Master components.

Covers:
1. Dataset auto-discovery, validation, streaming replay, ground-truth firewall.
2. Adaptive mTLS 6-hop simulation, profiles, mismatch injection, loopback calibration, telemetry export.
3. Content-addressed Recovery Vault, SHA-256 copy verification, quarantine, atomic restore.
4. Explainable Event Classification, cross-source correlation graph, and 0-100 incident risk scoring.
5. Integration API endpoints.
"""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from starlette.testclient import TestClient

from tracee.api import create_app
from tracee.dataset_replay import discover_dataset, validate_dataset_corpus, DatasetReplayController
from tracee.mtls_lab import MtlsSimulator
from tracee.recovery import RecoveryStore
from tracee.classifier import EventClassifier, CorrelationEngine, IncidentRiskEngine
from tracee.vault import FilesystemVaultStore
from tracee.services import TraceeService

TEST_TOKEN = "test_token_string_must_be_32_characters_minimum"


def setup_module():
    os.environ["TRACEE_API_TOKEN"] = TEST_TOKEN
    os.environ["TRACEE_UPLOAD_TOKEN"] = TEST_TOKEN


def test_dataset_discovery_and_firewall(tmp_path: Path):
    root = Path(".")
    ds_dir = discover_dataset(root)
    assert ds_dir is not None
    res = validate_dataset_corpus(ds_dir)
    assert res["valid"] is True
    assert res["total_declared_records"] == 750000
    assert len(res["sources"]) == 10
    # Ground truth firewall check
    for src in res["sources"]:
        assert "ground_truth" not in src["csv_path"]


def test_mtls_six_hop_and_profiles():
    sim = MtlsSimulator()
    # 1. Churn
    res_churn = sim.run_simulation("churn", risk_score=10, seed=101)
    assert len(res_churn.hops) == 6
    assert res_churn.status == "SUCCESS"
    assert res_churn.hops[0].source_service == "Client"
    assert res_churn.hops[-1].destination_service == "Payment Service"
    assert all(h.auth_path == "full_mtls" for h in res_churn.hops)

    # 2. Persistent
    res_persist = sim.run_simulation("persistent", risk_score=10, seed=101)
    assert len(res_persist.hops) == 6
    assert res_persist.hops[0].auth_path == "full_mtls_connect"
    assert all(h.auth_path == "persistent_pool" for h in res_persist.hops[1:])

    # 3. Adaptive GREEN
    res_adapt = sim.run_simulation("adaptive", risk_score=10, seed=101)
    assert len(res_adapt.hops) == 6
    assert res_adapt.hops[0].auth_path == "full_mtls_handshake"
    assert all(h.auth_path == "hmac_fastpath" for h in res_adapt.hops[1:])

    # 4. Hop 4 Mismatch Rejection
    res_mismatch = sim.run_simulation("adaptive", risk_score=10, inject_cert_mismatch=True, seed=101)
    assert res_mismatch.status == "REJECTED_AT_HOP_4"
    assert len(res_mismatch.hops) in (4, 6)
    assert res_mismatch.hops[3].decision == "REJECT"
    assert res_mismatch.hops[3].cert_mismatch is True
    assert res_mismatch.context_evicted is True

    # 5. Profile Comparison
    comp = sim.run_profile_comparison(risk_score=15, seed=101)
    assert "churn" in comp["comparison"]
    assert "persistent" in comp["comparison"]
    assert "adaptive" in comp["comparison"]

    # 6. Local Socket Calibration
    cal = sim.run_local_tls_calibration()
    assert cal["status"] == "SUCCESS"
    assert cal["measured_latency_ms"] >= 0.0


def test_recovery_vault_end_to_end(tmp_path: Path):
    vault_dir = tmp_path / "recovery_test_vault"
    FilesystemVaultStore(vault_dir).initialize()
    service = TraceeService(vault_dir)

    # Ingest test evidence
    test_file = tmp_path / "sample.log"
    test_file.write_bytes(b'{"log": "initial test evidence"}\n')
    meta, _ = service.ingest(test_file)
    eid = meta.evidence_id

    rec_store = RecoveryStore(vault_dir)
    # Create recovery copy
    ok, msg = rec_store.create_recovery_copy(eid)
    assert ok is True

    status_1 = rec_store.get_recovery_status()
    assert status_1["primary_valid_count"] == 1
    assert status_1["total_recovery_copies"] == 1

    # Simulate deletion -> MISSING
    from tracee.recovery import _make_writable
    primary_bin = vault_dir / "objects" / eid / "evidence.bin"
    _make_writable(primary_bin)
    primary_bin.unlink()
    status_2 = rec_store.get_recovery_status()
    assert status_2["primary_missing_count"] == 1

    # Restore from recovery copy
    rest_res = rec_store.restore_evidence(eid)
    assert rest_res["status"] == "RESTORED_VERIFIED"
    assert rest_res["verification_state"] == "VALID"
    assert primary_bin.is_file()

    # Re-verify vault status is back to valid
    status_3 = rec_store.get_recovery_status()
    assert status_3["primary_valid_count"] == 1
    assert status_3["primary_missing_count"] == 0


def test_event_classification_and_risk_scoring():
    classifier = EventClassifier()
    correlator = CorrelationEngine()
    risk_engine = IncidentRiskEngine()

    ev1 = {
        "event_type": "failed_password",
        "timestamp": "2026-10-31T05:00:00Z",
        "attributes": {"user": "analyst", "source_ip": "10.0.0.1", "host": "db-srv"},
    }
    f1 = classifier.classify_event(ev1)
    assert f1.category == "authentication"
    assert f1.assessment == "suspicious_indicator"

    ev2 = {
        "event_type": "audit_log_cleared",
        "timestamp": "2026-10-31T05:01:00Z",
        "attributes": {"event_code": "1102", "host": "db-srv"},
    }
    f2 = classifier.classify_event(ev2)
    assert f2.category == "privilege_activity"
    assert f2.assessment == "high_risk_indicator"

    report = risk_engine.evaluate_incident([ev1, ev2])
    assert 0 <= report.score <= 100
    assert report.risk_band in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
    assert "severity_weight" in report.factors

    graph = correlator.build_correlation_graph([ev1, ev2])
    assert len(graph["nodes"]) > 0
    assert "disclaimer" in graph


def test_integration_api_endpoints(tmp_path: Path):
    vault_dir = tmp_path / "api_test_vault"
    FilesystemVaultStore(vault_dir).initialize()
    app = create_app(vault_dir)
    client = TestClient(app)
    headers = {"Authorization": f"Bearer {TEST_TOKEN}"}

    # 1. Dataset Info
    resp = client.get("/api/v1/dataset/info", headers=headers)
    assert resp.status_code == 200
    assert "sources" in resp.json()

    # 2. Replay Status
    resp = client.get("/api/v1/dataset/replay/status", headers=headers)
    assert resp.status_code == 200
    assert "status" in resp.json()

    # 3. mTLS Simulation
    resp = client.post("/api/v1/mtls/simulate", json={"profile": "adaptive", "risk_score": 20}, headers=headers)
    assert resp.status_code == 200
    assert resp.json()["status"] == "SUCCESS"
    assert len(resp.json()["hops"]) == 6

    # 4. mTLS Compare
    resp = client.get("/api/v1/mtls/compare?risk_score=20&seed=42", headers=headers)
    assert resp.status_code == 200
    assert "comparison" in resp.json()

    # 5. mTLS Calibrate
    resp = client.post("/api/v1/mtls/calibrate", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["status"] == "SUCCESS"

    # 6. mTLS Export to Evidence
    resp = client.post("/api/v1/mtls/export-evidence", json={"profile": "adaptive", "risk_score": 25}, headers=headers)
    assert resp.status_code == 200
    assert "evidence_id" in resp.json()
    assert resp.json()["evidence_id"].startswith("TRACE-EV-")

    # 7. Recovery Status & Bootstrap
    resp = client.get("/api/v1/recovery/status", headers=headers)
    assert resp.status_code == 200
    assert "primary_valid_count" in resp.json()

    resp = client.post("/api/v1/recovery/bootstrap", headers=headers)
    assert resp.status_code == 200

    # 8. Disposable Vault Demo
    resp = client.post("/api/v1/recovery/demo-disposable", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["final_state"] == "VALID"

    # 9. Investigation Risk Score & Correlation Graph
    resp = client.get("/api/v1/investigation/risk-score", headers=headers)
    assert resp.status_code == 200
    assert "score" in resp.json()

    resp = client.get("/api/v1/investigation/correlation-graph", headers=headers)
    assert resp.status_code == 200
    assert "nodes" in resp.json()
