import hashlib
import json
import shutil
from datetime import datetime, timezone

from config import (
    METADATA_DIR,
    QUARANTINE_RUN_DIR,
    RUN_ID,
    RUN_ROOT,
    TRUSTED_EVIDENCE_FILE,
    VAULT_EVIDENCE_DIR,
)

from custody import log_event
from logging_utils import (
    error,
    passed,
    warning,
)
from manifest import set_integrity_status


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def calculate_hash(file_path):
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:
        while chunk := file.read(4096):
            sha256.update(chunk)

    return sha256.hexdigest()


def quarantine_evidence(
    vault_file,
    metadata_file,
    metadata,
    current_hash,
):
    evidence_id = metadata["evidence_id"]

    quarantine_path = (
        QUARANTINE_RUN_DIR
        / evidence_id
    )

    quarantine_path.mkdir(
        parents=True,
        exist_ok=True,
    )

    destination_log = (
        quarantine_path
        / vault_file.name
    )

    destination_metadata = (
        quarantine_path
        / metadata_file.name
    )

    shutil.move(
        vault_file,
        destination_log,
    )

    shutil.move(
        metadata_file,
        destination_metadata,
    )

    quarantine_record = {
        "schema_version": "1.0",
        "evidence_id": evidence_id,
        "run_id": RUN_ID,
        "reason": "INTEGRITY_FAILURE",
        "detected_at": utc_now(),
        "stored_hash": metadata["sha256"],
        "current_hash": current_hash,
        "quarantine_path": str(
            quarantine_path
        ),
    }

    record_file = (
        quarantine_path
        / "quarantine_record.json"
    )

    with open(record_file, "w") as file:
        json.dump(
            quarantine_record,
            file,
            indent=4,
        )

    try:
        record_file.chmod(0o600)
    except OSError:
        pass

    log_event(
        evidence_id,
        "EVIDENCE_QUARANTINED",
        {
            "reason": "INTEGRITY_FAILURE",
            "stored_hash": metadata["sha256"],
            "current_hash": current_hash,
        },
    )

    warning(
        f"Evidence quarantined: {evidence_id}"
    )


def verify_evidence(
    vault_file,
    metadata_file,
):
    with open(metadata_file, "r") as file:
        metadata = json.load(file)

    evidence_id = metadata["evidence_id"]

    stored_hash = metadata["sha256"]
    current_hash = calculate_hash(
        vault_file
    )

    if stored_hash == current_hash:
        log_event(
            evidence_id,
            "INTEGRITY_VERIFIED",
            {
                "sha256": current_hash,
            },
        )

        passed(
            f"Evidence integrity verified: "
            f"{evidence_id}"
        )

        return {
            "evidence_id": evidence_id,
            "run_id": RUN_ID,
            "source": metadata[
                "original_filename"
            ],
            "sha256": current_hash,
            "path": str(vault_file),
            "verified_at": utc_now(),
        }

    log_event(
        evidence_id,
        "TAMPERING_DETECTED",
        {
            "stored_hash": stored_hash,
            "current_hash": current_hash,
        },
    )

    warning(
        f"Evidence integrity failed: "
        f"{evidence_id}"
    )

    quarantine_evidence(
        vault_file,
        metadata_file,
        metadata,
        current_hash,
    )

    return None


def main():
    metadata_files = sorted(
        METADATA_DIR.glob("*.json")
    )

    if not metadata_files:
        error("No evidence metadata found")
        set_integrity_status("FAILED")
        return False

    verified_evidence = []

    for metadata_file in metadata_files:
        with open(metadata_file, "r") as file:
            metadata = json.load(file)

        evidence_id = metadata["evidence_id"]

        vault_file = (
            VAULT_EVIDENCE_DIR
            / f"{evidence_id}.log"
        )

        if not vault_file.exists():
            error(
                f"Missing evidence: {evidence_id}"
            )

            set_integrity_status("FAILED")
            return False

        result = verify_evidence(
            vault_file,
            metadata_file,
        )

        if result is None:
            error(
                "Integrity verification failed"
            )

            if TRUSTED_EVIDENCE_FILE.exists():
                TRUSTED_EVIDENCE_FILE.unlink()

            set_integrity_status("FAILED")
            return False

        verified_evidence.append(result)

    RUN_ROOT.mkdir(
        parents=True,
        exist_ok=True,
    )

    trust_record = {
        "schema_version": "1.0",
        "run_id": RUN_ID,
        "status": "VERIFIED",
        "verified_at": utc_now(),
        "evidence": verified_evidence,
    }

    with open(
        TRUSTED_EVIDENCE_FILE,
        "w"
    ) as file:
        json.dump(
            trust_record,
            file,
            indent=4,
        )

    try:
        TRUSTED_EVIDENCE_FILE.chmod(0o600)
    except OSError:
        pass

    set_integrity_status("VERIFIED")

    return True


if __name__ == "__main__":
    raise SystemExit(
        0 if main() else 1
    )
