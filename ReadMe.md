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
