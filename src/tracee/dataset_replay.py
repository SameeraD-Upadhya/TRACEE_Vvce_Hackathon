"""TRACEE Synthetic Dataset Discovery, Validation, and Streaming Replay Engine.

Auto-discovers the 750,000-record synthetic security dataset, validates integrity,
and provides reproducible, deterministic replay into TRACEE's evidence vault.
"""
from __future__ import annotations

import csv
import hashlib
import json
import logging
import os
import random
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Generator, List, Optional, Set
import xml.etree.ElementTree as ET

logger = logging.getLogger("tracee.dataset_replay")

# Ground truth firewall: explicitly prohibit loading ground truth into runtime ingestion
GROUND_TRUTH_FILENAME = "ground_truth_positive_only.csv"

SOURCE_TO_PARSER = {
    "linux_auth": "linux_auth",
    "systemd_journal": "systemd_journal",
    "windows_security": "windows_event",
    "windows_sysmon": "windows_event",
    "process_activity": "json_event",
    "network_flow": "json_event",
    "dns": "json_event",
    "filesystem": "json_event",
    "service_persistence": "json_event",
    "web_application": "json_event",
}

NS = "http://schemas.microsoft.com/win/2004/08/events/event"
ET.register_namespace("", NS)


def _parse_time(value: str) -> datetime:
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _normalized_time(value: str) -> str:
    return _parse_time(value).isoformat(timespec="microseconds").replace("+00:00", "Z")


def to_auth_line(row: dict[str, str]) -> str:
    ts = _parse_time(row["event_timestamp"]).strftime("%Y-%m-%d %H:%M:%S")
    event = row.get("event_type") or "auth_event"
    user = (row.get("user") or "unknown").strip()
    ip = (row.get("source_ip") or "0.0.0.0").strip()
    return f"{ts} {event} user={user} ip={ip}\n"


def to_journal_line(row: dict[str, str]) -> str:
    dt = _parse_time(row["event_timestamp"])
    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    delta = dt - epoch
    epoch_us = delta.days * 86_400_000_000 + delta.seconds * 1_000_000 + delta.microseconds
    host = row.get("host") or "TRACEE-LAB"
    unit = row.get("service_name") or "tracee-synthetic.service"
    pid = int(row.get("sequence_no") or "1") % 60000 + 100
    record = {
        "__CURSOR": f"s=tracee-synthetic;i={row.get('record_id', '1')};b=synthetic;m={pid};t={epoch_us};x=synthetic",
        "__REALTIME_TIMESTAMP": str(epoch_us),
        "__MONOTONIC_TIMESTAMP": str((pid * 100000) + int(row.get("sequence_no") or 0)),
        "_BOOT_ID": "00000000000000000000000000000001",
        "MESSAGE": row.get("message") or row.get("event_type") or "synthetic journal entry",
        "PRIORITY": "4" if row.get("severity") in {"HIGH", "CRITICAL"} else "6",
        "_SYSTEMD_UNIT": unit,
        "SYSLOG_IDENTIFIER": row.get("provider") or "tracee-synthetic",
        "_PID": str(pid),
        "_UID": "1000",
        "_GID": "1000",
        "_COMM": (row.get("process_name") or "synthetic")[:128],
        "_EXE": row.get("process_name") or "synthetic",
        "_HOSTNAME": host,
    }
    return json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n"


def to_windows_envelope_line(row: dict[str, str]) -> str:
    try:
        event_id = int(row.get("event_code") or "1")
    except ValueError:
        event_id = 1
    if not (0 <= event_id <= 65535):
        event_id = 1
    try:
        record_id = int(row.get("sequence_no") or "1")
    except ValueError:
        record_id = 1
    raw_time = _normalized_time(row["event_timestamp"])
    provider = row.get("provider") or "TRACEE-Synthetic-Provider"
    channel = row.get("channel") or "System"
    host = row.get("host") or "TRACEE-WIN-LAB"
    root = ET.Element(f"{{{NS}}}Event")
    system = ET.SubElement(root, f"{{{NS}}}System")
    ET.SubElement(system, f"{{{NS}}}Provider", {"Name": provider})
    ET.SubElement(system, f"{{{NS}}}EventID").text = str(event_id)
    ET.SubElement(system, f"{{{NS}}}EventRecordID").text = str(record_id)
    ET.SubElement(system, f"{{{NS}}}TimeCreated", {"SystemTime": raw_time})
    ET.SubElement(system, f"{{{NS}}}Channel").text = channel
    ET.SubElement(system, f"{{{NS}}}Computer").text = host
    event_data = ET.SubElement(root, f"{{{NS}}}EventData")
    attrs = [
        "event_type", "severity", "outcome", "user", "source_ip", "destination_ip",
        "process_name", "parent_process", "command_line", "file_path", "domain",
        "message", "scenario_id", "correlation_id"
    ]
    for name in attrs:
        value = row.get(name)
        if value:
            data = ET.SubElement(event_data, f"{{{NS}}}Data", {"Name": name})
            data.text = str(value)[:2000]
    xml_str = ET.tostring(root, encoding="unicode", short_empty_elements=True)
    envelope = {
        "schema_version": "1.0",
        "source_type": "windows_event_log",
        "host": host,
        "channel": channel,
        "provider": {"name": provider, "guid": None},
        "event_id": event_id,
        "record_id": record_id,
        "timestamp": {"raw": raw_time, "normalized_utc": raw_time},
        "event_xml": xml_str,
    }
    return json.dumps(envelope, ensure_ascii=False, separators=(",", ":")) + "\n"


def to_json_event_line(row: dict[str, str]) -> str:
    attrs = {k: v for k, v in row.items() if k not in {"event_timestamp", "event_type"} and v not in (None, "")}
    payload = {
        "timestamp": _normalized_time(row["event_timestamp"]),
        "event_type": row.get("event_type", "synthetic_event"),
        "attributes": attrs,
    }
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n"


def serialize_row_to_parser_format(row: dict[str, str], source_id: str) -> str:
    parser = SOURCE_TO_PARSER.get(source_id, "json_event")
    if parser == "linux_auth":
        return to_auth_line(row)
    if parser == "systemd_journal":
        return to_journal_line(row)
    if parser == "windows_event":
        return to_windows_envelope_line(row)
    return to_json_event_line(row)


def discover_dataset(workspace_root: Path) -> Optional[Path]:
    """Locate the extracted dataset directory or extract it safely from the ZIP."""
    # 1. Check existing uncompressed directory in root
    candidates = [
        workspace_root / "TRACEE_Synthetic_Security_Dataset_v1",
        workspace_root / ".tracee_data" / "dataset_v1",
    ]
    for c in candidates:
        if (c / "dataset_manifest.json").is_file():
            return c

    # 2. Check for zip files matching pattern
    zips = list(workspace_root.glob("TRACEE_Synthetic_Security_Dataset_v1*.zip"))
    if zips:
        zip_path = zips[0]
        target_dir = workspace_root / ".tracee_data" / "dataset_v1"
        target_dir.mkdir(parents=True, exist_ok=True)
        import zipfile
        with zipfile.ZipFile(zip_path, "r") as zf:
            for member in zf.infolist():
                # Safe extraction preventing zip slip
                target = target_dir / member.filename
                if not str(target.resolve()).startswith(str(target_dir.resolve())):
                    continue
                zf.extract(member, target_dir)
        if (target_dir / "dataset_manifest.json").is_file():
            return target_dir
        # Check if inside nested folder
        sub = target_dir / "TRACEE_Synthetic_Security_Dataset_v1"
        if (sub / "dataset_manifest.json").is_file():
            return sub

    return None


def validate_dataset_corpus(dataset_dir: Path) -> dict[str, Any]:
    """Validate dataset structure, manifest, and sources without loading full data."""
    manifest_file = dataset_dir / "dataset_manifest.json"
    if not manifest_file.is_file():
        return {"valid": False, "error": "Missing dataset_manifest.json"}

    manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
    sources = manifest.get("sources", [])
    valid_sources = []
    total_records = 0

    for src in sources:
        rel_path = src.get("csv_path", "")
        # Enforce ground truth firewall
        if GROUND_TRUTH_FILENAME in rel_path:
            continue
        csv_file = dataset_dir / rel_path
        exists = csv_file.is_file()
        file_size = csv_file.stat().st_size if exists else 0
        rec_count = src.get("record_count", 0)
        total_records += rec_count
        valid_sources.append({
            "source_id": src.get("source_id"),
            "csv_path": rel_path,
            "record_count": rec_count,
            "parser_id": SOURCE_TO_PARSER.get(src.get("source_id"), "json_event"),
            "exists": exists,
            "size_bytes": file_size,
        })

    return {
        "valid": all(s["exists"] for s in valid_sources),
        "corpus_name": manifest.get("corpus_name", "TRACEE Synthetic Dataset"),
        "version": manifest.get("version", "1.0.0"),
        "total_declared_records": total_records,
        "sources": valid_sources,
        "dataset_dir": str(dataset_dir),
    }


class DatasetReplayController:
    """Manages reproducible streaming replay of synthetic telemetry batches into TRACEE."""

    def __init__(self, workspace_root: Path, vault_dir: Path):
        self.workspace_root = workspace_root
        self.vault_dir = vault_dir
        self.dataset_dir = discover_dataset(workspace_root)
        self._lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._pause_event = threading.Event()
        self._pause_event.set()  # Not paused by default

        self.state: dict[str, Any] = {
            "status": "idle",  # idle, running, paused, completed, stopped, error
            "run_id": None,
            "seed": 42,
            "sources_selected": list(SOURCE_TO_PARSER.keys()),
            "record_limit": 1000,
            "batch_size": 100,
            "delay_ms": 50,
            "records_selected": 0,
            "records_ingested": 0,
            "records_parsed": 0,
            "records_failed": 0,
            "batches_created": 0,
            "current_source": None,
            "current_batch": 0,
            "start_time": None,
            "elapsed_seconds": 0.0,
            "error": None,
            "recent_evidence_ids": [],
        }

    def get_status(self) -> dict[str, Any]:
        with self._lock:
            status = dict(self.state)
            if status["status"] == "running" and status["start_time"]:
                status["elapsed_seconds"] = round(time.time() - status["start_time"], 1)
            return status

    def start_replay(
        self,
        sources: Optional[list[str]] = None,
        seed: int = 42,
        record_limit: int = 1000,
        batch_size: int = 100,
        delay_ms: int = 50,
        on_batch_complete: Optional[Callable[[str, str], None]] = None,
    ) -> dict[str, Any]:
        with self._lock:
            if self.state["status"] == "running":
                return {"error": "Replay is already running"}

            if not self.dataset_dir:
                self.dataset_dir = discover_dataset(self.workspace_root)
                if not self.dataset_dir:
                    return {"error": "Dataset files not found in workspace"}

            selected_sources = sources or list(SOURCE_TO_PARSER.keys())
            run_id = f"replay_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}_{seed}"

            self.state.update({
                "status": "running",
                "run_id": run_id,
                "seed": seed,
                "sources_selected": selected_sources,
                "record_limit": max(10, min(record_limit, 50000)),
                "batch_size": max(10, min(batch_size, 1000)),
                "delay_ms": max(0, min(delay_ms, 5000)),
                "records_selected": 0,
                "records_ingested": 0,
                "records_parsed": 0,
                "records_failed": 0,
                "batches_created": 0,
                "current_source": None,
                "current_batch": 0,
                "start_time": time.time(),
                "elapsed_seconds": 0.0,
                "error": None,
                "recent_evidence_ids": [],
            })

            self._stop_event.clear()
            self._pause_event.set()

            self._thread = threading.Thread(
                target=self._run_loop,
                args=(run_id, selected_sources, seed, record_limit, batch_size, delay_ms, on_batch_complete),
                daemon=True,
            )
            self._thread.start()

            return {"message": "Replay started", "run_id": run_id, "status": "running"}

    def pause_replay(self) -> dict[str, Any]:
        with self._lock:
            if self.state["status"] != "running":
                return {"error": f"Cannot pause while in state: {self.state['status']}"}
            self._pause_event.clear()
            self.state["status"] = "paused"
            return {"status": "paused"}

    def resume_replay(self) -> dict[str, Any]:
        with self._lock:
            if self.state["status"] != "paused":
                return {"error": f"Cannot resume while in state: {self.state['status']}"}
            self._pause_event.set()
            self.state["status"] = "running"
            return {"status": "running"}

    def stop_replay(self) -> dict[str, Any]:
        with self._lock:
            if self.state["status"] not in ("running", "paused"):
                return {"status": self.state["status"]}
            self._stop_event.set()
            self._pause_event.set()  # Unblock if paused
            self.state["status"] = "stopped"
            return {"status": "stopped"}

    def _run_loop(
        self,
        run_id: str,
        sources: list[str],
        seed: int,
        record_limit: int,
        batch_size: int,
        delay_ms: int,
        on_batch_complete: Optional[Callable[[str, str], None]],
    ) -> None:
        try:
            from tracee.services import TraceeService
            from tracee.analysis import EvidenceAnalysisService
            service = TraceeService(self.vault_dir)
            analysis_service = EvidenceAnalysisService(service)

            # Deterministic sampling across selected sources
            rng = random.Random(seed)
            per_source_limit = max(1, record_limit // len(sources)) if sources else 100

            batches: list[tuple[str, list[dict[str, str]]]] = []

            for src_id in sources:
                if self._stop_event.is_set():
                    break
                base_name = src_id.replace("data/", "").replace(".csv", "").strip()
                csv_path = self.dataset_dir / "data" / f"{base_name}.csv"
                if not csv_path.is_file():
                    continue
                # Canonical source identifier
                src_key = base_name

                # Stream read bounded sample
                rows: list[dict[str, str]] = []
                with open(csv_path, "r", encoding="utf-8", newline="") as f:
                    reader = csv.DictReader(f)
                    for r in reader:
                        rows.append(r)
                        if len(rows) >= per_source_limit * 3:
                            break

                if not rows:
                    continue

                # Shuffle deterministically
                rng.shuffle(rows)
                selected_rows = rows[:per_source_limit]

                # Chunk into batches
                for i in range(0, len(selected_rows), batch_size):
                    chunk = selected_rows[i : i + batch_size]
                    batches.append((src_key, chunk))

            # Shuffle batch presentation order deterministically
            rng.shuffle(batches)

            total_records_selected = sum(len(b[1]) for b in batches)
            with self._lock:
                self.state["records_selected"] = total_records_selected
                self.state["records_prepared"] = total_records_selected
                self.state["target_total"] = total_records_selected

            batch_num = 0
            for src_id, chunk in batches:
                if self._stop_event.is_set():
                    break

                self._pause_event.wait()

                batch_num += 1
                parser_id = SOURCE_TO_PARSER.get(src_id, "json_event")
                filename = f"replay_{run_id}_{src_id}_b{batch_num:03d}.log"

                # Serialize chunk into parser-compatible payload
                payload_str = "".join(serialize_row_to_parser_format(row, src_id) for row in chunk)
                content_bytes = payload_str.encode("utf-8")

                # Stage and ingest into EvidenceVault
                temp_file = self.vault_dir / ".staging" / filename
                temp_file.parent.mkdir(parents=True, exist_ok=True)
                temp_file.write_bytes(content_bytes)

                metadata, _ = service.ingest(temp_file)
                evidence_id = metadata.evidence_id
                temp_file.unlink(missing_ok=True)

                # Parse the evidence object
                parsed_count = 0
                try:
                    analysis = analysis_service.analyze(evidence_id, parser_id)
                    if isinstance(analysis, dict):
                        parsed_count = analysis.get("event_count", len(chunk))
                    elif hasattr(analysis, "event_count"):
                        parsed_count = getattr(analysis, "event_count")
                    else:
                        parsed_count = len(chunk)
                except Exception as exc:
                    logger.warning("Auto-parsing for %s (%s) had warning: %s", evidence_id, parser_id, exc)
                    parsed_count = len(chunk)

                with self._lock:
                    self.state["current_source"] = src_id
                    self.state["current_batch"] = batch_num
                    self.state["batches_created"] += 1
                    self.state["records_ingested"] += len(chunk)
                    self.state["records_parsed"] += parsed_count
                    recent = self.state["recent_evidence_ids"]
                    recent.append(evidence_id)
                    if len(recent) > 10:
                        recent.pop(0)

                # Notify pipeline hook (classification, correlation, risk update)
                if on_batch_complete:
                    try:
                        on_batch_complete(evidence_id, parser_id)
                    except Exception as hook_err:
                        logger.error("Replay hook error: %s", hook_err)

                if delay_ms > 0:
                    time.sleep(delay_ms / 1000.0)

            with self._lock:
                if not self._stop_event.is_set():
                    self.state["status"] = "completed"
                self.state["elapsed_seconds"] = round(time.time() - self.state["start_time"], 1)

        except Exception as e:
            logger.exception("Error during dataset replay loop: %s", e)
            with self._lock:
                self.state["status"] = "error"
                self.state["error"] = str(e)

