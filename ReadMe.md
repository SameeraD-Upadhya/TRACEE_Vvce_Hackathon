# TRACEE

**Threat Reconstruction & Cyber Evidence Engine**

TRACEE is a forensic evidence preservation and incident investigation platform designed to collect, seal, correlate, and reconstruct multi-source digital evidence into deterministic timelines and co-observation relationship graphs.

Built around an **integrity-first architecture**, TRACEE ensures that every ingested forensic artifact is cryptographically bound into an append-only hash chain before analysis begins.

---

## Project Status

- **Stage:** V0.2 Prototype & Forensic Foundation
- **Test Suite Status:** 764 tests passed (745 Phase 1 core + 19 Phase 2 RBAC/checkpoints), 0 failures.
- **Architectural Principle:** *Integrity before analysis.* Evidence payloads, metadata, and custody chains are strictly read-only after ingestion. Derived analytical outputs are stored as distinct immutable records with full provenance links.
- **Deployment Model:** Loopback-only by default (`127.0.0.1`), zero cloud telemetry, minimal dependencies (standard library + FastAPI/uvicorn).

---

## Quickstart

Get TRACEE running locally in 3 commands:

```bash
# 1. Clone the repository
git clone https://github.com/your-org/tracee.git && cd TRACEE

# 2. Install dependencies (Python 3.10+ required)
pip install -e .

# 3. Launch the automated demonstration environment
python -m tracee.demo
```

Alternatively, to run the dual-port demonstration server directly:

```bash
python scratch/launch_server.py
```

Open your browser to:
- **Primary Workspace:** [http://127.0.0.1:8000/](http://127.0.0.1:8000/)
- **Alternative Port:** [http://127.0.0.1:8080/](http://127.0.0.1:8080/)
- **Demo Session API Key:** `trc_demo_analyst_credential_32chars`

---

## Visual Walkthrough & Interface Gallery

The web interface is lightweight, dependency-free (vanilla ECMAScript and CSS), and operates fully offline without CDN calls.

### 1. Custody Chain & Tamper Detection
![Custody Chain & Tamper Detection](docs/screenshots/tamper-detected.png)
*TRACEE continuously verifies evidence integrity across four layers: payload SHA-256 match, metadata consistency, chain binding, and sequence continuity. When an object is altered, TRACEE pinpoints the exact failing layer and displays expected versus actual digest prefixes.*

### 2. Timeline Continuity & Gap Assessment
![Coverage and Gaps](docs/screenshots/coverage-and-gaps.png)
*Continuity analysis maps event frequency across time, highlighting unobserved windows, sequence gaps, and suspicious audit-clearing records (such as Windows Security Event ID 1102).*

### 3. Entity Co-Observation Topology
![Relationship Graph](docs/screenshots/relationship-graph.png)
*Deterministic entity correlation maps co-occurring IP addresses, user accounts, and system processes across disparate evidence sources. Graph edges denote observed co-occurrence, avoiding unsubstantiated causal assumptions.*

### 4. Forensic Reporting & Cryptographic Verification
![Reports Management](docs/screenshots/reports-ui.png)
*Case reports are exported as standalone, self-contained HTML/JSON dossiers with deterministic formatting and SHA-256 manifest verification.*

---

## Core Capabilities

```text
Evidence Sources (Logs, Journals, Events, Network Data)
                        │
                        ▼
            Cryptographic Ingestion Engine
           (SHA-256, Metadata & Chain Anchor)
                        │
                        ▼
              Append-Only Evidence Vault
         (Read-Only Objects, Merkle-Linked Chain)
                        │
          ┌─────────────┴─────────────┐
          ▼                           ▼
 Multi-Source Parsers        Integrity Verification
(Auth, Journal, WinEvents)   (Layered Tamper Detection)
          │                           │
          └─────────────┬─────────────┘
                        ▼
       Deterministic Event Normalization
                        │
          ┌─────────────┴─────────────┐
          ▼                           ▼
Timeline Reconstruction      Entity Co-Observation Graph
(Continuity & Gap Analysis)  (IPs, Users, Processes)
          │                           │
          └─────────────┬─────────────┘
                        ▼
         Candidate Hypothesis Evaluation
                        │
                        ▼
         Immutable Forensic Case Dossier
          (With Verified SHA-256 Manifest)
```

1. **Cryptographic Chain of Custody**: Every evidence item receives an immutable SHA-256 hash and a sequential record in `chain.jsonl` linking back to `GENESIS`.
2. **Layered Verification Engine**: Evaluates evidence across four distinct operational states:
   - `VALID`: Payload hash, metadata, and chain records match completely.
   - `TAMPERED`: Payload byte alterations detected via SHA-256 mismatch.
   - `INVALID`: Unchained or malformed metadata detected.
   - `MISSING`: Referenced evidence payload binary absent from disk.
3. **Deterministic Normalization**: Identical inputs yield byte-identical timestamps, event IDs, and graph representations across test runs.
4. **Conservative Gap Detection**: Highlights unobserved temporal windows and identifies explicit audit log clearing events without assuming deletion motives.
5. **Role-Based Access Control (RBAC)**: Enforces table-driven permissions (`viewer`, `analyst`, `admin`) using PBKDF2/scrypt slow-hashed credentials and token revocation.

---

## Claims vs. Evidence

In accordance with strict forensic evaluation discipline, every capability claim is tied to an automated test and operational limitation:

| Capability Claim | Verification Evidence | Evidence Type | Status | Forensic Limitation & Boundary |
|---|---|---|---|---|
| **Append-Only Vault Integrity** | `tests/test_chain.py`, `tests/test_vault.py` | Executable Unit Tests | Verified | Cryptographic hashing confirms data has not altered after ingestion; does not attest to source authenticity prior to capture. |
| **Tamper & Mismatch Detection** | `tests/test_verify.py`, `tests/test_api.py` | Integration & API Tests | Verified | Detects payload byte alterations and unlinked chain records; does not prevent physical storage medium deletion without OS-level protections. |
| **Multi-Source Event Parsing** | `tests/test_analysis.py`, `tests/test_journal_collector.py`, `tests/test_windows_event_collector.py` | Integration Tests | Verified | Normalizes structured schema entries for Linux auth, systemd journal, JSON, and Windows events; unstructured free-text requires tailored patterns. |
| **Deterministic Timeline & Gaps** | `tests/test_gaps.py`, `tests/test_reconstruction.py` | Scenario Tests | Verified | Identifies unobserved windows and sequence skips; absence is an investigative lead, never conclusive proof of deliberate deletion. |
| **Entity Co-Observation Topology** | `tests/test_relationships.py`, `tests/test_relationship_service.py` | Component Tests | Verified | Graph edges represent observed co-occurrence in the same temporal or session context, never causal linkage or automated attribution. |
| **Case Reporting & Manifests** | `tests/test_reporting.py`, `tests/test_report_service.py` | Full Flow Tests | Verified | Verifies SHA-256 manifest checksums of exported reports; does not replace external legal chain-of-custody documentation. |
| **Table-Driven RBAC & Local Auth** | `tests/test_principals.py`, `tests/test_rbac.py` | Security Tests | Verified | Enforces principal authorization for local investigative workstations; does not federate with enterprise identity systems. |

---

## What TRACEE Does Not Do

To maintain scientific objectivity and evidentiary rigor, TRACEE adheres to explicit operational boundaries:

- **No Automated Attribution**: TRACEE correlates observed network addresses, hostnames, and user identities. It does not claim to uniquely identify human individuals or threat actors.
- **No Causal Assumptions**: Graph relationships denote observed co-occurrence in shared events, not causal certainty.
- **Absence Is Not Proof of Deletion**: Missing log sequences indicate unobserved windows in available evidence; TRACEE flags these as gaps rather than asserting deliberate destruction.
- **Post-Incident Analysis Scope**: TRACEE is an investigative and reconstruction engine for post-incident triage, not an inline intrusion prevention or live stream filtering system.
- **Local Loopback Boundary**: TRACEE runs locally without transmitting customer evidence or telemetry to third-party cloud services.

---

## Command Line Interface (CLI)

The `tracee` CLI provides headless access to evidence management and verification:

```bash
# Ingest an evidence source
tracee ingest --vault ./my_vault --source /var/log/auth.log --label "edge-router-auth"

# Verify complete vault integrity
tracee verify-chain --vault ./my_vault

# Verify an individual evidence object
tracee verify --vault ./my_vault --id TRACE-EV-000001

# Inspect evidence metadata record
tracee metadata --vault ./my_vault --id TRACE-EV-000001

# Manage investigator principals (admin role required)
tracee principals add --username analyst1 --role analyst
tracee principals list
tracee principals revoke --principal-id <id>
```

---

## Hackathon Demonstration Modules

TRACEE integrates an end-to-end vertical slice combining digital forensics evidence verification, an Adaptive mTLS Performance Lab, 750,000 synthetic multi-source telemetry corpus replay, and an automated SHA-256 Recovery Vault.

```text
       ┌─────────────────────────────────────────────────────────────┐
       │             TRACEE INTEGRATED FORENSIC ARCHITECTURE         │
       └──────────────────────────────┬──────────────────────────────┘
                                      │
            ┌─────────────────────────┼─────────────────────────┐
            ▼                         ▼                         ▼
   ┌───────────────────┐    ┌───────────────────┐    ┌───────────────────┐
   │ 750K SYNTHETIC    │    │ ADAPTIVE mTLS LAB │    │ PRIMARY VAULT &   │
   │ SECURITY CORPUS   │    │ 6-Hop Microservice│    │ RECOVERY STORE    │
   │ 10 Sources (CSVs) │    │ Churn / Persistent│    │ SHA-256 Content-  │
   │ Deterministic Seed│    │ / Risk-Adaptive   │    │ Addressed Backup  │
   │ Ground Truth FW   │    │ Hop 4 Cert Mismatch    Quarantine & Restore│
   └────────┬──────────┘    └────────┬──────────┘    └─────────┬─────────┘
            │                        │                         │
            └────────────────────────┼─────────────────────────┘
                                     ▼
                      ┌─────────────────────────────┐
                      │    CROSS-SOURCE CORRELATION │
                      │  10 Classification Categories│
                      │  0-100 Incident Risk Score  │
                      │  Co-Observation Node Graph  │
                      └─────────────────────────────┘
```

---

### 1. Adaptive mTLS Performance Lab (§4)

The Adaptive mTLS Performance Lab evaluates the trade-off between strict per-hop mutual TLS handshakes and low-latency microservice communication across a **six-hop distributed service mesh**:

```text
Client ──[Hop 1]──► API Gateway ──[Hop 2]──► Identity Svc ──[Hop 3]──► Policy Engine
                                                                            │
Payment Svc ◄──[Hop 6]── Inventory Svc ◄──[Hop 5]── Order Svc ◄──[Hop 4]────┘
```

- **Connection Profiles**:
  - `High Churn mTLS`: Fresh full TLS handshake on every hop (highest cryptographic isolation, ~60ms round-trip).
  - `Persistent Baseline`: Reuses TLS session tickets across persistent HTTP/2 connections (~28ms round-trip).
  - `Risk-Adaptive mTLS`: Bounded HMAC-SHA256 context tokens validated via constant-time comparison (~18ms round-trip).
- **Dynamic Risk-Adaptive Policy**:
  - `GREEN` (Risk < 30): Context token valid for 120s TTL; fastpath hops authenticated via HMAC-SHA256 digest.
  - `YELLOW` (30 ≤ Risk ≤ 70): Context freshness restricted to 15s; intermediate full mTLS re-evaluations required.
  - `RED` (Risk > 70): Context token evicted; immediate full mutual TLS handshake enforced on every service hop.
- **Hop 4 Certificate Mismatch Injection**:
  - Injects an untrusted/expired intermediate certificate between Policy Engine and Order Service.
  - Immediately terminates downstream execution (Hops 5 and 6 remain unexecuted).
  - Purges and evicts cached HMAC context tokens, recording outcome as `REJECTED`.
- **Host-Local Loopback Probe**:
  - Measures real TCP connect and TLS handshake latencies against `127.0.0.1` (clearly labelled host-local measurement, not a production cluster benchmark).
- **Forensic Telemetry Export**:
  - Exports complete hop simulation traces as JSONL evidence into the primary vault with `simulation_only: true` provenance.

---

### 2. 750,000-Record Synthetic Security Dataset Replay (§3)

TRACEE includes automated discovery, manifest validation, and reproducible streaming replay of the **TRACEE Synthetic Multi-Source Security Telemetry Corpus v1.0.0** (750,000 total declared records):

| Telemetry Source | Records | Parser ID | Format & Telemetry Description |
|---|---|---|---|
| `linux_auth.csv` | 90,000 | `linux_auth` | SSH/sudo authentication events (timestamp, host, user, outcome) |
| `systemd_journal.csv` | 75,000 | `systemd_journal` | Systemd service unit lifecycle & process states |
| `windows_security.csv` | 95,000 | `windows_event` | Windows Event Log envelopes (Logon 4624, Audit Clear 1102) |
| `windows_sysmon.csv` | 100,000 | `windows_event` | Sysmon Process Creation (1), Network Connect (3), File Create (11) |
| `process_activity.csv` | 70,000 | `json_event` | Process launch, PID lineage, execution flags |
| `network_flow.csv` | 75,000 | `json_event` | Flow summaries: src/dst IPs, ports, bytes, protocol |
| `dns.csv` | 55,000 | `json_event` | Domain lookup queries, query types, resolved response IPs |
| `filesystem.csv` | 60,000 | `json_event` | File creation, modification, permissions, path tracking |
| `service_persistence.csv`| 55,000 | `json_event` | Registry Run keys, systemd services, scheduled tasks |
| `web_application.csv` | 75,000 | `json_event` | HTTP access logs, route paths, status codes, user-agent |

- **Ground Truth Firewall**: The evaluation ground truth file (`ground_truth/ground_truth_positive_only.csv`) is strictly isolated and never accessed by runtime ingestion, classification, or live investigation APIs.
- **Bounded Streaming Replay**: Streams bounded record batches (default 1,000 records) without reading entire multi-megabyte CSVs into memory.
- **Deterministic Random Seed**: Configurable seed (e.g. `42`) guarantees exact reproducibility across demo runs.
- **Provenance Safeguards**: Every replayed batch records `simulation_only: true`, original CSV hash, replay batch ID, and seed. Descriptive command-line strings are never executed.

---

### 3. SHA-256 Content-Addressed Recovery Vault (§6)

TRACEE supplements the primary hash-addressed evidence vault with an independent, SHA-256 content-addressed **Recovery Vault**:

- **Content-Addressed Tree**: Stored under `vault/recovery/objects/sha256/<prefix>/<sha256>/evidence.bin` with manifest `recovery_manifest.jsonl`.
- **Atomic Restoration**: Restores corrupted or missing primary evidence payloads via staging files with safe write permissions handling on Windows (`stat.S_IWRITE`).
- **Quarantine Safeguard**: Any corrupted evidence payload found in the primary vault is moved to `vault/recovery/quarantine/<timestamp>_<evidence_id>_corrupted.bin` before restoration.
- **One-Click Disposable Sandbox Demo**: A dedicated demo (`POST /api/v1/recovery/demo-disposable`) executes a complete 4-stage simulation (Ingest -> Backup -> Deletion -> Restore -> Byte Tampering -> Quarantine -> Restore) in a temporary disposable vault without modifying active evidence.

---

### 4. Cross-Source Correlation & Explainable Incident Risk Scoring (§5)

- **Explainable Classification**: Maps parsed security events across 10 deterministic categories (`authentication`, `process_execution`, `network_connection`, `dns_resolution`, `file_modification`, `persistence_mechanism`, `privilege_escalation`, `audit_tamper`, `web_access`, `system_event`) and 5 forensic assessments.
- **Incident Risk Triage Index (0-100)**: Evaluates overall incident risk via a 5-factor breakdown:
  1. *Severity Weight*: Base severity of observed events.
  2. *Suspicious Patterns*: High-risk event types (failed auth, privilege changes, log clear).
  3. *Cross-Source Corroboration*: Multi-source corroborate signals (e.g. DNS + NetFlow + Sysmon).
  4. *Privilege & Persistence Indicators*: Sudo elevation, cron/service persistence, user modifications.
  5. *Sequence Support*: Temporal alignment and logical progression across events.
- **Entity Co-Observation Graph**: Bounded SVG graph (max 10-12 nodes) linking co-observed IP addresses, hostnames, and user accounts with explicit edge reasons (`same_user`, `same_host`, `dns_resolution`, `network_flow`).

---

## 3-Minute Hackathon Demonstration Script

Follow this step-by-step walkthrough during the hackathon evaluation:

1. **Launch & Authorize (0:00 - 0:30)**:
   - Run server: `python scratch/launch_server.py`
   - Open browser: `http://127.0.0.1:8000/`
   - Click "Authorize API", enter token `trc_demo_analyst_credential_32chars`, click "Authorize". Note the TRACEE logo and connected status dot.
2. **Integrity & Disposable Recovery Demo (0:30 - 1:15)**:
   - Navigate to **Integrity & Recovery** (◎ in sidebar).
   - Click **Run Disposable Tamper & Recovery Demo**.
   - Watch the live log execute the 4-stage sequence: Clean Valid -> Snapshot -> Deletion Detected (MISSING) -> Restored -> Byte Corruption Detected (TAMPERED) -> Quarantined -> Restored (VALID).
   - In the evidence select dropdown, choose any record and run verification to observe immediate green/red/amber state pills and detailed diagnostics.
3. **Adaptive mTLS Performance Lab (1:15 - 2:00)**:
   - Navigate to **Adaptive mTLS Lab** (⚡ in sidebar).
   - Select **Risk-Adaptive mTLS** profile with Risk Score `15` (GREEN) and click **Run Simulation**. Notice the 6-hop topology in green (~18ms latency).
   - Check **Inject Certificate Mismatch at Hop 4** and click **Run Simulation**. Observe Hop 4 turn red (REJECTED), Hops 5-6 dimmed, and context tokens evicted.
   - Click **Run Loopback Calibration (127.0.0.1)** to see local TLS handshake timing.
   - Click **Export Telemetry to Vault** to seal simulation results into the evidence store.
4. **Dataset Replay & Incident Risk Triage (2:00 - 3:00)**:
   - Navigate to **Dataset Replay** (↺ in sidebar).
   - Verify corpus status shows `CORPUS VALID (v1.0.0)` with 750,000 records across 10 sources. Note the Ground Truth Firewall banner.
   - Set Record Cap to `1000`, click **Start Replay**, and watch streaming progress, batches, and parser metrics increment live.
   - Navigate to **Timeline & Correlation** (↗ in sidebar).
   - Inspect the **Incident Risk Triage (0-100)** score and 5-factor breakdown.
   - Click any node on the **Entity Correlation Graph** to inspect the co-observed identity, host, and event attributes.

---

## Testing & Verification

Run the comprehensive test suite locally:

```bash
# Execute complete test suite (760+ passing checks)
python -m pytest -q

# Verify UI JavaScript syntax
node --check ui/app.js

# Test specific verification layers
python -m pytest tests/test_verify.py tests/test_chain.py -v
```

---

## License

This project is licensed under the Apache 2.0 License. See [LICENSE](LICENSE) for details.
