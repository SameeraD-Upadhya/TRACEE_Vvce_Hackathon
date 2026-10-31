"""SHA-256 Content-Addressed Recovery Vault and Restoration Centre.

Preserves byte-identical recovery copies under:
  vault/recovery/objects/sha256/<first-two-hex>/<full-64-char-sha256>/evidence.bin
Provides safe atomic restoration of MISSING and TAMPERED primary evidence objects,
automatic quarantine of corrupted artifacts, and append-only recovery audit events.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import stat
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from tracee.locking import set_read_only
from tracee.models import EvidenceMetadata
from tracee.verify import VerificationEngine, VerificationState

logger = logging.getLogger("tracee.recovery")


def _make_writable(path: Path) -> None:
    if path.exists():
        try:
            path.chmod(stat.S_IWRITE | stat.S_IREAD)
        except Exception:
            pass


class RecoveryStore:
    """Manages hash-addressed recovery copies and atomic evidence restoration."""

    def __init__(self, vault_dir: Path):
        self.vault_dir = Path(vault_dir)
        self.recovery_dir = self.vault_dir / "recovery"
        self.objects_dir = self.recovery_dir / "objects" / "sha256"
        self.manifests_dir = self.recovery_dir / "manifests"
        self.quarantine_dir = self.recovery_dir / "quarantine"
        self.events_file = self.recovery_dir / "events.jsonl"

    def _ensure_directories(self) -> None:
        self.objects_dir.mkdir(parents=True, exist_ok=True)
        self.manifests_dir.mkdir(parents=True, exist_ok=True)
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)

    def _recovery_path_for_hash(self, sha256_digest: str) -> Path:
        clean = sha256_digest.strip().lower()
        if len(clean) != 64 or not all(c in "0123456789abcdef" for c in clean):
            raise ValueError(f"Invalid SHA-256 digest format: {sha256_digest}")
        pfx = clean[:2]
        return self.objects_dir / pfx / clean / "evidence.bin"

    def _manifest_path(self, evidence_id: str) -> Path:
        return self.manifests_dir / f"{evidence_id}.json"

    def append_recovery_event(self, event_type: str, evidence_id: str, details: Dict[str, Any]) -> None:
        self._ensure_directories()
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "evidence_id": evidence_id,
            "details": details,
        }
        line = json.dumps(event, separators=(",", ":")) + "\n"
        with open(self.events_file, "a+", encoding="utf-8") as f:
            f.write(line)
            f.flush()

    def create_recovery_copy(
        self,
        evidence_id: str,
        content_bytes: Optional[bytes] = None,
    ) -> Tuple[bool, str]:
        """Creates a verified byte-identical recovery copy addressed by SHA-256."""
        self._ensure_directories()
        record_path = self.vault_dir / "records" / f"{evidence_id}.json"
        if not record_path.is_file():
            return False, f"Metadata record not found for {evidence_id}"

        try:
            meta_dict = json.loads(record_path.read_text(encoding="utf-8"))
            expected_hash = meta_dict["sha256"].lower()
            expected_size = meta_dict["size_bytes"]
        except Exception as exc:
            return False, f"Invalid metadata record: {exc}"

        primary_path = self.vault_dir / "objects" / evidence_id / "evidence.bin"

        # Obtain content bytes
        if content_bytes is None:
            if not primary_path.is_file():
                return False, f"Primary evidence file does not exist: {primary_path}"
            content_bytes = primary_path.read_bytes()

        # Stream / calculate SHA-256
        actual_hash = hashlib.sha256(content_bytes).hexdigest().lower()
        actual_size = len(content_bytes)

        if actual_hash != expected_hash:
            return False, f"Primary content hash {actual_hash} does not match metadata {expected_hash}"
        if actual_size != expected_size:
            return False, f"Primary size {actual_size} does not match metadata {expected_size}"

        # Write to hash-addressed recovery path via atomic staging
        rec_path = self._recovery_path_for_hash(expected_hash)
        if rec_path.is_file():
            # Idempotent check: verify existing copy
            existing_hash = hashlib.sha256(rec_path.read_bytes()).hexdigest().lower()
            if existing_hash == expected_hash:
                return True, "Recovery copy verified and already present"

        rec_path.parent.mkdir(parents=True, exist_ok=True)
        staging_dir = self.vault_dir / ".staging"
        staging_dir.mkdir(parents=True, exist_ok=True)
        staging_rec = staging_dir / f"rec_stage_{expected_hash[:12]}_{int(time.time())}.bin"
        staging_rec.write_bytes(content_bytes)
        if rec_path.exists():
            _make_writable(rec_path)
            rec_path.unlink()
        shutil.move(staging_rec, rec_path)
        set_read_only(rec_path)

        # Write recovery manifest
        manifest = {
            "schema_version": "1.0",
            "evidence_id": evidence_id,
            "original_sha256": expected_hash,
            "size_bytes": expected_size,
            "recovery_path": str(rec_path.relative_to(self.vault_dir)),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "status": "VERIFIED",
        }
        man_path = self._manifest_path(evidence_id)
        man_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

        self.append_recovery_event(
            "recovery_copy_created",
            evidence_id,
            {"sha256": expected_hash, "size_bytes": expected_size},
        )
        return True, "Recovery copy verified and stored"

    def bootstrap_recovery_store(self) -> Dict[str, Any]:
        """Scans records and initializes recovery copies for all valid existing evidence."""
        records_dir = self.vault_dir / "records"
        if not records_dir.is_dir():
            return {"bootstrapped": 0, "skipped": 0, "failed": 0}

        bootstrapped = 0
        skipped = 0
        failed = 0

        for rec_file in records_dir.glob("*.json"):
            eid = rec_file.stem
            man_path = self._manifest_path(eid)
            if man_path.is_file():
                skipped += 1
                continue
            ok, _ = self.create_recovery_copy(eid)
            if ok:
                bootstrapped += 1
            else:
                failed += 1

        return {"bootstrapped": bootstrapped, "skipped": skipped, "failed": failed}

    def get_recovery_status(self) -> Dict[str, Any]:
        """Comprehensive status report for the Recovery Centre UI."""
        records_dir = self.vault_dir / "records"
        chain_path = self.vault_dir / "chain" / "chain.jsonl"
        items = []

        valid_count = 0
        missing_count = 0
        tampered_count = 0
        recovery_copies_count = 0
        recovery_bytes = 0

        # Compute total recovery storage
        if self.objects_dir.exists():
            for f in self.objects_dir.rglob("evidence.bin"):
                if f.is_file():
                    recovery_copies_count += 1
                    recovery_bytes += f.stat().st_size

        if records_dir.is_dir():
            for rec_file in sorted(records_dir.glob("*.json")):
                eid = rec_file.stem
                primary_path = self.vault_dir / "objects" / eid / "evidence.bin"

                try:
                    meta = json.loads(rec_file.read_text(encoding="utf-8"))
                    expected_hash = meta.get("sha256", "").lower()
                    expected_size = meta.get("size_bytes", 0)
                    filename = meta.get("original_filename", eid)
                except Exception:
                    continue

                # Run fast verification
                eng = VerificationEngine(rec_file, primary_path, chain_path)
                res = eng.verify()
                state_str = res.state.value

                if state_str == "VALID":
                    valid_count += 1
                elif state_str == "MISSING":
                    missing_count += 1
                elif state_str == "TAMPERED":
                    tampered_count += 1

                # Check if recovery copy exists
                rec_path = self._recovery_path_for_hash(expected_hash)
                has_recovery = rec_path.is_file()
                recovery_valid = False

                if has_recovery:
                    # Quick size check
                    if rec_path.stat().st_size == expected_size:
                        recovery_valid = True

                recoverable = (state_str in ("MISSING", "TAMPERED")) and recovery_valid

                items.append({
                    "evidence_id": eid,
                    "original_filename": filename,
                    "state": state_str,
                    "original_sha256": expected_hash,
                    "size_bytes": expected_size,
                    "recovery_copy_exists": has_recovery,
                    "recovery_copy_valid": recovery_valid,
                    "recoverable": recoverable,
                    "failed_layer": getattr(res, "failed_layer", None),
                })

        return {
            "primary_valid_count": valid_count,
            "primary_missing_count": missing_count,
            "primary_tampered_count": tampered_count,
            "total_recovery_copies": recovery_copies_count,
            "recovery_storage_bytes": recovery_bytes,
            "items": items,
        }

    def restore_evidence(self, evidence_id: str) -> Dict[str, Any]:
        """Atomically restores a MISSING or TAMPERED evidence object from its hash-addressed recovery copy."""
        record_path = self.vault_dir / "records" / f"{evidence_id}.json"
        if not record_path.is_file():
            return {"status": "NOT_RECOVERABLE", "error": f"Metadata record not found for {evidence_id}"}

        try:
            meta = json.loads(record_path.read_text(encoding="utf-8"))
            expected_hash = meta["sha256"].lower()
            expected_size = meta["size_bytes"]
        except Exception as exc:
            return {"status": "NOT_RECOVERABLE", "error": f"Invalid metadata record: {exc}"}

        rec_path = self._recovery_path_for_hash(expected_hash)
        if not rec_path.is_file():
            return {
                "status": "NOT_RECOVERABLE",
                "error": f"No recovery copy exists with hash {expected_hash}",
            }

        # Independently verify recovery copy bytes before using it
        recovery_bytes = rec_path.read_bytes()
        actual_rec_hash = hashlib.sha256(recovery_bytes).hexdigest().lower()
        if actual_rec_hash != expected_hash or len(recovery_bytes) != expected_size:
            return {
                "status": "RECOVERY_COPY_INVALID",
                "error": "Recovery copy failed independent SHA-256 or size verification",
            }

        primary_path = self.vault_dir / "objects" / evidence_id / "evidence.bin"

        # Quarantine tampered primary file if present
        if primary_path.is_file():
            try:
                quarantine_name = f"{evidence_id}_{int(time.time())}.corrupted"
                quarantine_target = self.quarantine_dir / quarantine_name
                _make_writable(primary_path)
                shutil.copy2(primary_path, quarantine_target)
                self.append_recovery_event(
                    "tampered_quarantined",
                    evidence_id,
                    {"quarantine_path": str(quarantine_target.name)},
                )
            except Exception as q_exc:
                logger.warning("Quarantine backup warning: %s", q_exc)

        # Atomic restore via staging
        staging_dir = self.vault_dir / ".staging"
        staging_dir.mkdir(parents=True, exist_ok=True)
        staging_file = staging_dir / f"restore_{evidence_id}_{int(time.time())}.bin"
        staging_file.write_bytes(recovery_bytes)

        primary_path.parent.mkdir(parents=True, exist_ok=True)
        if primary_path.exists():
            _make_writable(primary_path)
            primary_path.unlink()

        shutil.move(staging_file, primary_path)
        set_read_only(primary_path)

        # Re-run complete verification
        chain_path = self.vault_dir / "chain" / "chain.jsonl"
        eng = VerificationEngine(record_path, primary_path, chain_path)
        verification_result = eng.verify()

        self.append_recovery_event(
            "evidence_restored",
            evidence_id,
            {
                "restored_sha256": expected_hash,
                "verified_state": verification_result.state.value,
            },
        )

        return {
            "status": "RESTORED_VERIFIED" if verification_result.state.value == "VALID" else "RESTORED_CHAIN_MISMATCH",
            "evidence_id": evidence_id,
            "verification_state": verification_result.state.value,
            "restored_sha256": expected_hash,
            "message": "Evidence payload restored from byte-identical recovery copy and verified.",
        }

    def simulate_tamper(self, evidence_id: str) -> Dict[str, Any]:
        """Alters the primary evidence payload to demonstrate tamper detection, ensuring a recovery copy exists first."""
        primary_path = self.vault_dir / "objects" / evidence_id / "evidence.bin"
        if not primary_path.is_file():
            return {"status": "ERROR", "error": f"Primary evidence file not found for {evidence_id}"}

        self.create_recovery_copy(evidence_id)

        _make_writable(primary_path)
        primary_path.write_bytes(b'{"tampered": true, "simulation": "tamper_detected_mismatch", "note": "altered payload"}\n')
        set_read_only(primary_path)

        self.append_recovery_event(
            "simulated_tamper",
            evidence_id,
            {"note": "Altered payload bytes for demonstration."},
        )
        return {
            "status": "TAMPERED",
            "evidence_id": evidence_id,
            "message": "Primary evidence payload altered to demonstrate tamper detection. Original copy safely retained in Recovery Vault.",
        }

    def simulate_missing(self, evidence_id: str) -> Dict[str, Any]:
        """Removes the primary evidence payload to demonstrate missing file detection, ensuring a recovery copy exists first."""
        primary_path = self.vault_dir / "objects" / evidence_id / "evidence.bin"
        if not primary_path.is_file():
            return {"status": "ERROR", "error": f"Primary evidence file not found for {evidence_id}"}

        self.create_recovery_copy(evidence_id)

        _make_writable(primary_path)
        primary_path.unlink()

        self.append_recovery_event(
            "simulated_missing",
            evidence_id,
            {"note": "Removed primary evidence file for demonstration."},
        )
        return {
            "status": "MISSING",
            "evidence_id": evidence_id,
            "message": "Primary evidence file removed to demonstrate missing file detection. Original copy safely retained in Recovery Vault.",
        }

    @staticmethod
    def run_disposable_vault_demo() -> Dict[str, Any]:
        """Demonstrates tamper detection, quarantine, and recovery in a temporary disposable vault."""
        import tempfile
        from .vault import FilesystemVaultStore
        from .services import TraceeService

        with tempfile.TemporaryDirectory(prefix="tracee-recovery-demo-") as tmp:
            tmp_vault = Path(tmp) / "vault"
            FilesystemVaultStore(tmp_vault).initialize()
            service = TraceeService(tmp_vault)

            # 1. Ingest test evidence
            test_content = b'{"log_type": "disposable_recovery_test", "status": "pristine"}\n'
            src_file = Path(tmp) / "test_artifact.log"
            src_file.write_bytes(test_content)
            meta, _ = service.ingest(src_file)
            eid = meta.evidence_id

            rec_store = RecoveryStore(tmp_vault)
            # Create recovery copy
            rec_store.create_recovery_copy(eid)

            # Step 1: Initial state is VALID
            status_init = rec_store.get_recovery_status()

            # Step 2: Simulate DELETION (Missing)
            primary_bin = tmp_vault / "objects" / eid / "evidence.bin"
            _make_writable(primary_bin)
            primary_bin.unlink()
            status_missing = rec_store.get_recovery_status()
            restore_missing_res = rec_store.restore_evidence(eid)

            # Step 3: Simulate TAMPER (Byte alteration)
            _make_writable(primary_bin)
            primary_bin.write_bytes(b'{"log_type": "TAMPERED_DISPOSABLE_CORRUPTED"}\n')
            set_read_only(primary_bin)
            status_tampered = rec_store.get_recovery_status()
            restore_tampered_res = rec_store.restore_evidence(eid)

            return {
                "test_evidence_id": eid,
                "initial_valid": status_init["primary_valid_count"] == 1,
                "missing_detected": status_missing["primary_missing_count"] == 1,
                "restore_missing_status": restore_missing_res["status"],
                "tamper_detected": status_tampered["primary_tampered_count"] == 1,
                "restore_tampered_status": restore_tampered_res["status"],
                "final_state": restore_tampered_res["verification_state"],
                "disclaimer": "Executed safely in an isolated temporary vault without modifying active evidence.",
            }
