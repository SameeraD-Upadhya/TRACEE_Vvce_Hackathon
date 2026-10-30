import os
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent

RUN_ID = os.environ.get(
    "TRACEE_RUN_ID",
    "UNKNOWN-RUN"
)

EVIDENCE_INPUT_DIR = BASE_DIR / "evidence"

RUN_ROOT = Path(
    os.environ.get(
        "TRACEE_INVESTIGATION_DIR",
        BASE_DIR / "investigations" / RUN_ID
    )
)

VAULT_RUN_DIR = Path(
    os.environ.get(
        "TRACEE_VAULT_RUN_DIR",
        BASE_DIR / "vault" / RUN_ID
    )
)

VAULT_EVIDENCE_DIR = VAULT_RUN_DIR / "evidence"
METADATA_DIR = VAULT_RUN_DIR / "metadata"

QUARANTINE_RUN_DIR = Path(
    os.environ.get(
        "TRACEE_QUARANTINE_RUN_DIR",
        BASE_DIR / "quarantine" / RUN_ID
    )
)

MANIFEST_FILE = RUN_ROOT / "manifest.json"
CUSTODY_FILE = RUN_ROOT / "chain_of_custody.jsonl"
TRUSTED_EVIDENCE_FILE = RUN_ROOT / "trusted_evidence.json"

NORMALIZED_EVENTS_FILE = (
    RUN_ROOT / "normalized_events.jsonl"
)

ENTITIES_FILE = RUN_ROOT / "entities.jsonl"

CORRELATED_EVENTS_FILE = (
    RUN_ROOT / "correlated_events.jsonl"
)

TIMELINE_FILE = (
    RUN_ROOT / "incident_timeline.json"
)

GRAPH_FILE = (
    RUN_ROOT / "investigation_graph.json"
)

CORRELATION_WINDOW_SECONDS = int(
    os.environ.get(
        "TRACEE_CORRELATION_WINDOW_SECONDS",
        "300"
    )
)
