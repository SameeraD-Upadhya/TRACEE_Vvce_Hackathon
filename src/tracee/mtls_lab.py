"""Adaptive mTLS Performance Lab and Zero-Trust Mesh Simulator.

Provides:
1. Six-hop service-mesh simulation with High Churn, Persistent, and Risk-Adaptive profiles.
2. Cryptographic HMAC-SHA256 context token binding with constant-time verification.
3. Risk policy enforcement (GREEN: 120s TTL, YELLOW: 15s TTL, RED: full mTLS).
4. Hop 4 certificate mismatch injection with downstream cutoff and context eviction.
5. Local loopback TLS/socket calibration probe.
6. Deterministic JSONL forensic telemetry export to TRACEE's evidence vault.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import random
import socket
import ssl
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("tracee.mtls_lab")

# Fixed six-hop topology definition
SERVICES = [
    "Client",
    "API Gateway",
    "Identity Service",
    "Policy Engine",
    "Order Service",
    "Inventory Service",
    "Payment Service",
]

HOPS = [
    (1, "Client", "API Gateway"),
    (2, "API Gateway", "Identity Service"),
    (3, "Identity Service", "Policy Engine"),
    (4, "Policy Engine", "Order Service"),
    (5, "Order Service", "Inventory Service"),
    (6, "Inventory Service", "Payment Service"),
]

# Shared secret for local HMAC context token simulation
SIMULATED_HMAC_SECRET = b"tracee_mtls_lab_hmac_secret_key_32bytes"


@dataclass
class HopResult:
    hop_number: int
    source_service: str
    destination_service: str
    auth_path: str  # "full_mtls", "persistent_pool", "hmac_fastpath", "revalidated_hmac"
    risk_score: int
    risk_band: str  # "GREEN", "YELLOW", "RED"
    latency_ms: float
    cumulative_latency_ms: float
    decision: str  # "ALLOW", "REJECT"
    rejection_reason: Optional[str] = None
    cert_mismatch: bool = False
    context_token_used: bool = False


@dataclass
class SimulationRunResult:
    run_id: str
    profile: str  # "churn", "persistent", "adaptive"
    timestamp: str
    seed: int
    client_id: str
    session_id: str
    inject_cert_mismatch: bool
    risk_score: int
    risk_band: str
    hops: List[HopResult]
    total_latency_ms: float
    status: str  # "SUCCESS", "REJECTED_AT_HOP_4"
    context_evicted: bool
    summary: Dict[str, Any]


class MtlsSimulator:
    """Deterministic six-hop service mesh mTLS simulator."""

    def __init__(self):
        # In-memory context cache: session_id -> {token, client_id, cert_fingerprint, risk_band, expiry, issued_at}
        self._context_cache: Dict[str, Dict[str, Any]] = {}

    def clear_cache(self) -> None:
        self._context_cache.clear()

    @staticmethod
    def compute_risk_band(score: int) -> str:
        if score < 30:
            return "GREEN"
        elif score < 60:
            return "YELLOW"
        return "RED"

    @staticmethod
    def generate_hmac_token(
        client_id: str,
        session_id: str,
        cert_fingerprint: str,
        risk_band: str,
        expiry: float,
    ) -> str:
        payload = f"{client_id}:{session_id}:{cert_fingerprint}:{risk_band}:{expiry:.2f}"
        signature = hmac.new(SIMULATED_HMAC_SECRET, payload.encode("utf-8"), hashlib.sha256).hexdigest()
        raw = f"{payload}:{signature}"
        return base64.urlsafe_b64encode(raw.encode("utf-8")).decode("utf-8")

    @staticmethod
    def verify_hmac_token(
        token_str: str,
        expected_client: str,
        expected_session: str,
        expected_cert_fp: str,
        current_time: float,
    ) -> Tuple[bool, Optional[str]]:
        try:
            raw = base64.urlsafe_b64decode(token_str.encode("utf-8")).decode("utf-8")
            parts = raw.split(":")
            if len(parts) != 6:
                return False, "Malformed token structure"
            client_id, session_id, cert_fp, risk_band, expiry_str, signature = parts
            expiry = float(expiry_str)

            # Constant time payload recalculation
            payload = f"{client_id}:{session_id}:{cert_fp}:{risk_band}:{expiry_str}"
            expected_sig = hmac.new(SIMULATED_HMAC_SECRET, payload.encode("utf-8"), hashlib.sha256).hexdigest()

            if not hmac.compare_digest(signature, expected_sig):
                return False, "HMAC signature mismatch"

            if current_time > expiry:
                return False, "Context token expired"

            if not hmac.compare_digest(client_id, expected_client):
                return False, "Client identity mismatch"

            if not hmac.compare_digest(session_id, expected_session):
                return False, "Session identity mismatch"

            if not hmac.compare_digest(cert_fp, expected_cert_fp):
                return False, "Certificate fingerprint mismatch"

            return True, None
        except Exception as exc:
            return False, f"Token validation exception: {exc}"

    def run_simulation(
        self,
        profile: str = "adaptive",
        risk_score: int = 15,
        inject_cert_mismatch: bool = False,
        seed: int = 42,
        client_id: str = "client-service-mesh-01",
        session_id: Optional[str] = None,
    ) -> SimulationRunResult:
        rng = random.Random(seed)
        now = time.time()
        sid = session_id or f"sess_{int(now)}_{rng.randint(1000, 9999)}"
        run_id = f"mtls_{profile}_{int(now)}_{rng.randint(100, 999)}"
        risk_band = self.compute_risk_band(risk_score)

        client_cert_fp = hashlib.sha256(f"cert_{client_id}".encode()).hexdigest()[:32]
        hops_result: List[HopResult] = []
        cumulative_latency = 0.0
        context_evicted = False
        status = "SUCCESS"

        # Model base latencies with small jitter based on profile
        # Churn: 8.5ms - 13.0ms per hop (Full handshake: asymmetric crypto, X.509 validation)
        # Persistent: 3.2ms - 5.5ms per hop (reused TCP/TLS channel, symmetric encryption only)
        # Adaptive: 1.2ms - 2.8ms per hop on HMAC fastpath; initial Hop 1 does full mTLS

        for hop_num, src, dst in HOPS:
            # Check for Hop 4 mismatch injection
            mismatch_here = (hop_num == 4 and inject_cert_mismatch)
            effective_cert_fp = "corrupted_or_stolen_fingerprint" if mismatch_here else client_cert_fp

            auth_path = "full_mtls"
            latency = 0.0
            decision = "ALLOW"
            rejection_reason = None
            token_used = False

            if mismatch_here:
                # Security boundary: Certificate mismatch detected!
                decision = "REJECT"
                rejection_reason = "Certificate fingerprint mismatch at Hop 4 (Policy Engine -> Order Service)"
                status = "REJECTED_AT_HOP_4"
                context_evicted = True
                self._context_cache.pop(sid, None)
                latency = round(rng.uniform(4.0, 7.5), 2)
                cumulative_latency += latency
                hops_result.append(
                    HopResult(
                        hop_number=hop_num,
                        source_service=src,
                        destination_service=dst,
                        auth_path="mismatch_rejected",
                        risk_score=risk_score,
                        risk_band=risk_band,
                        latency_ms=latency,
                        cumulative_latency_ms=round(cumulative_latency, 2),
                        decision=decision,
                        rejection_reason=rejection_reason,
                        cert_mismatch=True,
                        context_token_used=False,
                    )
                )
                # Security policy: Explicitly record downstream hops (5-6) as BLOCKED / NOT_EXECUTED
                for blk_hop, blk_src, blk_dst in HOPS[hop_num:]:
                    hops_result.append(
                        HopResult(
                            hop_number=blk_hop,
                            source_service=blk_src,
                            destination_service=blk_dst,
                            auth_path="not_executed",
                            risk_score=risk_score,
                            risk_band=risk_band,
                            latency_ms=0.0,
                            cumulative_latency_ms=round(cumulative_latency, 2),
                            decision="BLOCKED",
                            rejection_reason="Downstream execution blocked: Hop 4 policy violation",
                            cert_mismatch=False,
                            context_token_used=False,
                        )
                    )
                break

            if profile == "churn":
                auth_path = "full_mtls"
                latency = round(rng.uniform(8.5, 12.8), 2)
            elif profile == "persistent":
                if hop_num == 1:
                    auth_path = "full_mtls_connect"
                    latency = round(rng.uniform(8.0, 11.5), 2)
                else:
                    auth_path = "persistent_pool"
                    latency = round(rng.uniform(3.0, 4.8), 2)
            elif profile == "adaptive":
                if risk_band == "RED":
                    # RED risk forces full mTLS at every hop, invalidates context
                    auth_path = "full_mtls_red_policy"
                    latency = round(rng.uniform(8.5, 12.5), 2)
                    context_evicted = True
                    self._context_cache.pop(sid, None)
                else:
                    # Hop 1 establishes session with full mTLS, issues HMAC context token
                    if hop_num == 1:
                        auth_path = "full_mtls_handshake"
                        latency = round(rng.uniform(7.8, 11.2), 2)
                        ttl = 120.0 if risk_band == "GREEN" else 15.0
                        token = self.generate_hmac_token(client_id, sid, client_cert_fp, risk_band, now + ttl)
                        self._context_cache[sid] = {
                            "token": token,
                            "client_id": client_id,
                            "cert_fp": client_cert_fp,
                            "risk_band": risk_band,
                            "expiry": now + ttl,
                            "issued_at": now,
                        }
                    else:
                        cached = self._context_cache.get(sid)
                        if cached and now <= cached["expiry"]:
                            token_used = True
                            if risk_band == "GREEN":
                                auth_path = "hmac_fastpath"
                                latency = round(rng.uniform(1.2, 2.4), 2)
                            else:  # YELLOW: lightweight revalidation
                                auth_path = "revalidated_hmac"
                                latency = round(rng.uniform(2.5, 4.2), 2)
                        else:
                            auth_path = "full_mtls_fallback"
                            latency = round(rng.uniform(7.5, 10.5), 2)

            cumulative_latency += latency
            hops_result.append(
                HopResult(
                    hop_number=hop_num,
                    source_service=src,
                    destination_service=dst,
                    auth_path=auth_path,
                    risk_score=risk_score,
                    risk_band=risk_band,
                    latency_ms=latency,
                    cumulative_latency_ms=round(cumulative_latency, 2),
                    decision=decision,
                    rejection_reason=rejection_reason,
                    cert_mismatch=False,
                    context_token_used=token_used,
                )
            )

        total_latency = round(cumulative_latency, 2)
        summary = {
            "total_hops_executed": len(hops_result),
            "total_hops_defined": len(HOPS),
            "profile": profile,
            "risk_band": risk_band,
            "risk_score": risk_score,
            "fastpath_hops_count": sum(1 for h in hops_result if h.context_token_used),
            "total_latency_ms": total_latency,
            "mean_hop_latency_ms": round(total_latency / max(1, len(hops_result)), 2),
        }

        return SimulationRunResult(
            run_id=run_id,
            profile=profile,
            timestamp=datetime.now(timezone.utc).isoformat(),
            seed=seed,
            client_id=client_id,
            session_id=sid,
            inject_cert_mismatch=inject_cert_mismatch,
            risk_score=risk_score,
            risk_band=risk_band,
            hops=hops_result,
            total_latency_ms=total_latency,
            status=status,
            context_evicted=context_evicted,
            summary=summary,
        )

    def run_profile_comparison(
        self,
        risk_score: int = 15,
        seed: int = 42,
    ) -> Dict[str, Any]:
        """Runs all three profiles with the same seed to produce comparable latency metrics."""
        churn_res = self.run_simulation("churn", risk_score, False, seed)
        persist_res = self.run_simulation("persistent", risk_score, False, seed)
        adapt_res = self.run_simulation("adaptive", risk_score, False, seed)

        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "seed": seed,
            "risk_score": risk_score,
            "risk_band": self.compute_risk_band(risk_score),
            "comparison": {
                "churn": {
                    "name": "High Churn mTLS",
                    "total_latency_ms": churn_res.total_latency_ms,
                    "mean_hop_ms": churn_res.summary["mean_hop_latency_ms"],
                    "hops_completed": len(churn_res.hops),
                },
                "persistent": {
                    "name": "Persistent Baseline",
                    "total_latency_ms": persist_res.total_latency_ms,
                    "mean_hop_ms": persist_res.summary["mean_hop_latency_ms"],
                    "hops_completed": len(persist_res.hops),
                },
                "adaptive": {
                    "name": "Risk-Adaptive mTLS",
                    "total_latency_ms": adapt_res.total_latency_ms,
                    "mean_hop_ms": adapt_res.summary["mean_hop_latency_ms"],
                    "hops_completed": len(adapt_res.hops),
                    "fastpath_hops": adapt_res.summary["fastpath_hops_count"],
                },
            },
            "disclaimer": (
                "Simulation latency is modelled under configurable assumptions; "
                "a loopback probe is a host-local measurement and is not a production service-mesh benchmark."
            ),
        }

    @staticmethod
    def run_local_tls_calibration(port: int = 18443) -> Dict[str, Any]:
        """Measure actual host-local loopback socket round-trip latency on 127.0.0.1 with finite timeouts."""
        t0 = time.perf_counter()
        probe_successful = False
        measured_latency_ms = 0.0
        details = {}

        try:
            # Measure local loopback socket roundtrip
            s_listen = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s_listen.bind(("127.0.0.1", 0))
            s_listen.listen(1)
            actual_port = s_listen.getsockname()[1]
            s_listen.settimeout(1.5)

            s_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s_client.settimeout(1.5)

            t_conn_start = time.perf_counter()
            s_client.connect(("127.0.0.1", actual_port))
            conn, _ = s_listen.accept()

            # Exchange ping-pong
            conn.settimeout(1.5)
            s_client.sendall(b"CALIBRATE_MTLS_PING")
            data = conn.recv(64)
            conn.sendall(b"CALIBRATE_MTLS_PONG")
            resp = s_client.recv(64)
            t_conn_end = time.perf_counter()

            measured_latency_ms = round((t_conn_end - t_conn_start) * 1000.0, 3)
            probe_successful = (resp == b"CALIBRATE_MTLS_PONG")

            s_client.close()
            conn.close()
            s_listen.close()

            details = {
                "loopback_ip": "127.0.0.1",
                "ephemeral_port": actual_port,
                "bytes_transferred": len(data) + len(resp),
                "rtt_ms": measured_latency_ms,
            }
        except Exception as exc:
            measured_latency_ms = round((time.perf_counter() - t0) * 1000.0, 3)
            details = {"error": str(exc)}

        return {
            "status": "SUCCESS" if probe_successful else "FAILED",
            "measured_latency_ms": measured_latency_ms,
            "measurement_type": "actual_host_loopback_socket_rtt",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "details": details,
            "disclaimer": (
                "Host-local loopback measurement on 127.0.0.1. "
                "Separated from simulated multi-hop service mesh timings."
            ),
        }

    @staticmethod
    def export_telemetry_to_jsonl(run_result: SimulationRunResult) -> str:
        """Serializes simulation hops into TRACEE json_event compatible lines."""
        lines = []
        for hop in run_result.hops:
            record = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event_type": "mtls_hop_evaluation",
                "attributes": {
                    "simulation_only": True,
                    "synthetic": True,
                    "mtls_run_id": run_result.run_id,
                    "profile": run_result.profile,
                    "seed": run_result.seed,
                    "client_id": run_result.client_id,
                    "session_id": run_result.session_id,
                    "hop_number": hop.hop_number,
                    "source_service": hop.source_service,
                    "destination_service": hop.destination_service,
                    "auth_path": hop.auth_path,
                    "risk_score": hop.risk_score,
                    "risk_band": hop.risk_band,
                    "latency_ms": hop.latency_ms,
                    "cumulative_latency_ms": hop.cumulative_latency_ms,
                    "decision": hop.decision,
                    "cert_mismatch": hop.cert_mismatch,
                    "rejection_reason": hop.rejection_reason or "none",
                },
            }
            lines.append(json.dumps(record, separators=(",", ":")))
        return "\n".join(lines) + "\n"

