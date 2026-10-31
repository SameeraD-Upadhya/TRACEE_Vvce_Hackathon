"""Explainable Event Classifier, Cross-Source Correlation, and Incident Risk Engine.

Provides:
1. Deterministic classification of multi-source forensic events across 10 categories.
2. Cross-source correlation across IPs, users, hosts, processes, domains, and scenarios.
3. Incident-level risk prioritization scoring (0-100) with transparent factor breakdowns.
"""
from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("tracee.classifier")

CATEGORIES = [
    "authentication",
    "process_execution",
    "network_connection",
    "dns",
    "filesystem",
    "service_persistence",
    "privilege_activity",
    "web_application",
    "mtls_authentication",
    "system",
]

ASSESSMENTS = [
    "benign_context",
    "suspicious_indicator",
    "high_risk_indicator",
    "requires_investigation",
    "insufficient_data",
]


@dataclass
class ClassificationFinding:
    rule_id: str
    rule_version: str
    category: str
    assessment: str
    explanation: str
    source_evidence_id: str
    event_timestamp: str
    attributes: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CorrelationEdge:
    source_node: str
    target_node: str
    reason: str  # e.g., "same_user", "same_host", "dns_lookup", "network_flow"
    source_events: List[str] = field(default_factory=list)


@dataclass
class IncidentRiskReport:
    incident_id: str
    score: int  # 0 - 100 triage prioritization index
    risk_band: str  # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    factors: Dict[str, int]
    factor_explanations: Dict[str, str]
    total_events_analyzed: int
    total_findings_count: int
    findings: List[ClassificationFinding]
    correlated_entities: Dict[str, List[str]]
    timestamp: str
    disclaimer: str = (
        "Prioritization index for investigative triage. Does not assert certainty, "
        "causation, or automated attribution."
    )


class EventClassifier:
    """Deterministic, explainable rule-based classification engine."""

    def classify_event(self, event: Dict[str, Any], evidence_id: str = "") -> ClassificationFinding:
        raw_type = str(event.get("event_type", "")).lower()
        attrs = event.get("attributes", {})
        ts = event.get("timestamp", datetime.now(timezone.utc).isoformat())

        # 1. mTLS Simulation events
        if "mtls" in raw_type or attrs.get("simulation_only"):
            cert_mismatch = attrs.get("cert_mismatch", False)
            if cert_mismatch:
                return ClassificationFinding(
                    rule_id="RULE-MTLS-002",
                    rule_version="1.0",
                    category="mtls_authentication",
                    assessment="high_risk_indicator",
                    explanation="Observed certificate fingerprint mismatch during service hop evaluation.",
                    source_evidence_id=evidence_id,
                    event_timestamp=ts,
                    attributes=attrs,
                )
            return ClassificationFinding(
                rule_id="RULE-MTLS-001",
                rule_version="1.0",
                category="mtls_authentication",
                assessment="benign_context",
                explanation="Observed normal service mesh hop authentication.",
                source_evidence_id=evidence_id,
                event_timestamp=ts,
                attributes=attrs,
            )

        # 2. Authentication events
        if any(w in raw_type for w in ("auth", "login", "logon", "failed_password")):
            outcome = str(attrs.get("outcome", "")).lower()
            if "fail" in raw_type or outcome == "failure":
                return ClassificationFinding(
                    rule_id="RULE-AUTH-002",
                    rule_version="1.0",
                    category="authentication",
                    assessment="suspicious_indicator",
                    explanation="Authentication failure recorded.",
                    source_evidence_id=evidence_id,
                    event_timestamp=ts,
                    attributes=attrs,
                )
            return ClassificationFinding(
                rule_id="RULE-AUTH-001",
                rule_version="1.0",
                category="authentication",
                assessment="benign_context",
                explanation="Successful authentication event recorded.",
                source_evidence_id=evidence_id,
                event_timestamp=ts,
                attributes=attrs,
            )

        # 3. Privilege & Security Clearing
        event_code = str(attrs.get("event_code", ""))
        if event_code == "1102" or "audit_log_cleared" in raw_type:
            return ClassificationFinding(
                rule_id="RULE-PRIV-001",
                rule_version="1.0",
                category="privilege_activity",
                assessment="high_risk_indicator",
                explanation="Security audit log clearing event (Event ID 1102) observed.",
                source_evidence_id=evidence_id,
                event_timestamp=ts,
                attributes=attrs,
            )

        # 4. Process execution
        if any(w in raw_type for w in ("process", "exec", "spawn", "cmd")):
            proc = str(attrs.get("process_name", "")).lower()
            cmd = str(attrs.get("command_line", "")).lower()
            suspicious_bins = ("powershell", "cmd.exe", "whoami", "certutil", "net.exe", "vssadmin", "mimikatz")
            if any(sb in proc or sb in cmd for sb in suspicious_bins):
                return ClassificationFinding(
                    rule_id="RULE-PROC-002",
                    rule_version="1.0",
                    category="process_execution",
                    assessment="suspicious_indicator",
                    explanation=f"Process execution of dual-use or administrative utility: {proc or cmd[:40]}",
                    source_evidence_id=evidence_id,
                    event_timestamp=ts,
                    attributes=attrs,
                )
            return ClassificationFinding(
                rule_id="RULE-PROC-001",
                rule_version="1.0",
                category="process_execution",
                assessment="benign_context",
                explanation="Standard process execution observed.",
                source_evidence_id=evidence_id,
                event_timestamp=ts,
                attributes=attrs,
            )

        # 5. Network / Flow
        if any(w in raw_type for w in ("network", "flow", "connect", "egress")):
            dst_port = str(attrs.get("destination_port", ""))
            if dst_port in ("4444", "8888", "1337", "445", "3389"):
                return ClassificationFinding(
                    rule_id="RULE-NET-002",
                    rule_version="1.0",
                    category="network_connection",
                    assessment="suspicious_indicator",
                    explanation=f"Network connection to monitored administrative port {dst_port}.",
                    source_evidence_id=evidence_id,
                    event_timestamp=ts,
                    attributes=attrs,
                )
            return ClassificationFinding(
                rule_id="RULE-NET-001",
                rule_version="1.0",
                category="network_connection",
                assessment="benign_context",
                explanation="Network connection record logged.",
                source_evidence_id=evidence_id,
                event_timestamp=ts,
                attributes=attrs,
            )

        # 6. DNS
        if "dns" in raw_type or attrs.get("dns_query_type"):
            domain = str(attrs.get("domain", "")).lower()
            if any(tld in domain for tld in (".xyz", ".top", ".cc", ".onion", ".su")):
                return ClassificationFinding(
                    rule_id="RULE-DNS-002",
                    rule_version="1.0",
                    category="dns",
                    assessment="suspicious_indicator",
                    explanation=f"DNS query for non-standard TLD: {domain}",
                    source_evidence_id=evidence_id,
                    event_timestamp=ts,
                    attributes=attrs,
                )
            return ClassificationFinding(
                rule_id="RULE-DNS-001",
                rule_version="1.0",
                category="dns",
                assessment="benign_context",
                explanation=f"DNS query resolved: {domain}",
                source_evidence_id=evidence_id,
                event_timestamp=ts,
                attributes=attrs,
            )

        # 7. Persistence / Service
        if any(w in raw_type for w in ("service", "persistence", "registry", "scheduled_task")):
            return ClassificationFinding(
                rule_id="RULE-PERSIST-001",
                rule_version="1.0",
                category="service_persistence",
                assessment="requires_investigation",
                explanation="System service or persistence modification recorded.",
                source_evidence_id=evidence_id,
                event_timestamp=ts,
                attributes=attrs,
            )

        # 8. Web application
        if any(w in raw_type for w in ("http", "web", "url")):
            status = str(attrs.get("http_status", ""))
            if status in ("401", "403", "500"):
                return ClassificationFinding(
                    rule_id="RULE-WEB-002",
                    rule_version="1.0",
                    category="web_application",
                    assessment="suspicious_indicator",
                    explanation=f"Web application error or authorization response {status}.",
                    source_evidence_id=evidence_id,
                    event_timestamp=ts,
                    attributes=attrs,
                )
            return ClassificationFinding(
                rule_id="RULE-WEB-001",
                rule_version="1.0",
                category="web_application",
                assessment="benign_context",
                explanation="Web access request recorded.",
                source_evidence_id=evidence_id,
                event_timestamp=ts,
                attributes=attrs,
            )

        # Fallback System
        return ClassificationFinding(
            rule_id="RULE-SYS-001",
            rule_version="1.0",
            category="system",
            assessment="benign_context",
            explanation=f"System event observed: {raw_type or 'general_telemetry'}",
            source_evidence_id=evidence_id,
            event_timestamp=ts,
            attributes=attrs,
        )


class CorrelationEngine:
    """Extracts co-observed entity relationships without unsupported causal claims."""

    def build_correlation_graph(
        self,
        events: List[Dict[str, Any]],
        max_nodes: int = 12,
    ) -> Dict[str, Any]:
        nodes_dict: Dict[str, Dict[str, Any]] = {}
        edges: List[CorrelationEdge] = []

        def add_node(node_id: str, label: str, node_type: str) -> None:
            if node_id not in nodes_dict:
                nodes_dict[node_id] = {
                    "id": node_id,
                    "label": label,
                    "type": node_type,
                    "event_count": 0,
                }
            nodes_dict[node_id]["event_count"] += 1

        for ev in events:
            attrs = ev.get("attributes", {})
            host = attrs.get("host")
            user = attrs.get("user")
            src_ip = attrs.get("source_ip")
            dst_ip = attrs.get("destination_ip")
            proc = attrs.get("process_name")
            domain = attrs.get("domain")

            if host:
                add_node(f"host:{host}", str(host), "host")
            if user:
                add_node(f"user:{user}", str(user), "user")
            if src_ip:
                add_node(f"ip:{src_ip}", str(src_ip), "ip")
            if dst_ip:
                add_node(f"ip:{dst_ip}", str(dst_ip), "ip")
            if proc:
                add_node(f"proc:{proc}", str(proc), "process")
            if domain:
                add_node(f"domain:{domain}", str(domain), "domain")

            # Correlate user -> host
            if user and host:
                edges.append(CorrelationEdge(f"user:{user}", f"host:{host}", "co_observed_user_on_host"))
            # Correlate IP -> host
            if src_ip and host:
                edges.append(CorrelationEdge(f"ip:{src_ip}", f"host:{host}", "co_observed_network_endpoint"))
            # Correlate IP -> domain
            if dst_ip and domain:
                edges.append(CorrelationEdge(f"domain:{domain}", f"ip:{dst_ip}", "dns_resolution_binding"))
            # Correlate proc -> user
            if proc and user:
                edges.append(CorrelationEdge(f"user:{user}", f"proc:{proc}", "process_execution_context"))

        # Deduplicate edges
        dedup_edges: Dict[Tuple[str, str, str], int] = defaultdict(int)
        for e in edges:
            dedup_edges[(e.source_node, e.target_node, e.reason)] += 1

        # Select top nodes by occurrence to keep graph readable (max 10-12 nodes)
        sorted_nodes = sorted(nodes_dict.values(), key=lambda n: n["event_count"], reverse=True)
        selected_nodes = sorted_nodes[:max_nodes]
        selected_ids = {n["id"] for n in selected_nodes}

        final_edges = []
        for (src, dst, rsn), count in dedup_edges.items():
            if src in selected_ids and dst in selected_ids:
                final_edges.append({
                    "source": src,
                    "target": dst,
                    "reason": rsn,
                    "occurrence_count": count,
                })

        return {
            "nodes": selected_nodes,
            "edges": final_edges,
            "total_entities_discovered": len(nodes_dict),
            "disclaimer": "Edges denote observed co-occurrence in event telemetry; they do not imply causation.",
        }


class IncidentRiskEngine:
    """Computes a deterministic 0-100 triage prioritization score."""

    def __init__(self):
        self.classifier = EventClassifier()
        self.correlator = CorrelationEngine()

    def evaluate_incident(
        self,
        events: List[Dict[str, Any]],
        incident_id: str = "INC-CURRENT-WORKSPACE",
    ) -> IncidentRiskReport:
        findings: List[ClassificationFinding] = []
        for ev in events:
            f = self.classifier.classify_event(ev, evidence_id=ev.get("evidence_id", ""))
            findings.append(f)

        # 1. Severity weight factor (0 - 30 pts)
        high_risk_count = sum(1 for f in findings if f.assessment == "high_risk_indicator")
        suspicious_count = sum(1 for f in findings if f.assessment == "suspicious_indicator")
        severity_factor = min(30, (high_risk_count * 15) + (suspicious_count * 5))

        # 2. Suspicious indicator volume factor (0 - 25 pts)
        volume_factor = min(25, suspicious_count * 4)

        # 3. Cross-source corroboration factor (0 - 20 pts)
        categories_seen = {f.category for f in findings if f.assessment in ("suspicious_indicator", "high_risk_indicator")}
        corroboration_factor = min(20, len(categories_seen) * 7)

        # 4. Privilege / Persistence indicator factor (0 - 15 pts)
        priv_pers_count = sum(1 for f in findings if f.category in ("privilege_activity", "service_persistence"))
        privilege_factor = min(15, priv_pers_count * 8)

        # 5. Sequence support factor (0 - 10 pts)
        seq_factor = 10 if (high_risk_count > 0 and suspicious_count > 0) else min(10, len(findings) // 10)

        total_score = min(100, severity_factor + volume_factor + corroboration_factor + privilege_factor + seq_factor)

        if total_score >= 70:
            risk_band = "CRITICAL"
        elif total_score >= 45:
            risk_band = "HIGH"
        elif total_score >= 20:
            risk_band = "MEDIUM"
        else:
            risk_band = "LOW"

        factors = {
            "severity_weight": severity_factor,
            "suspicious_patterns": volume_factor,
            "cross_source_corroboration": corroboration_factor,
            "privilege_persistence_indicators": privilege_factor,
            "sequence_support": seq_factor,
        }

        explanations = {
            "severity_weight": f"{high_risk_count} high-risk findings and {suspicious_count} suspicious indicators.",
            "suspicious_patterns": f"Pattern count scored at {volume_factor}/25 based on indicator frequency.",
            "cross_source_corroboration": f"Corroborated across {len(categories_seen)} distinct event categories.",
            "privilege_persistence_indicators": f"{priv_pers_count} privilege/persistence records identified.",
            "sequence_support": "Multi-stage sequence continuity supports triage prioritization.",
        }

        # Correlated entities
        entities: Dict[str, Set[str]] = defaultdict(set)
        for ev in events:
            attrs = ev.get("attributes", {})
            for key in ("host", "user", "source_ip", "destination_ip", "domain", "process_name"):
                val = attrs.get(key)
                if val:
                    entities[key].add(str(val))

        clean_entities = {k: sorted(list(v))[:10] for k, v in entities.items()}

        return IncidentRiskReport(
            incident_id=incident_id,
            score=total_score,
            risk_band=risk_band,
            factors=factors,
            factor_explanations=explanations,
            total_events_analyzed=len(events),
            total_findings_count=len(findings),
            findings=findings[:30],  # Return up to 30 most recent findings
            correlated_entities=clean_entities,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

