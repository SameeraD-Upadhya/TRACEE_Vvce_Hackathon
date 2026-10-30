import hashlib
import json
import shutil
from datetime import datetime, timezone

from config import (
    EVIDENCE_INPUT_DIR,
    EVIDENCE_INPUT_DIR,
    METADATA_DIR,
    RUN_ID,
    VAULT_EVIDENCE_DIR,
)

from custody import log_event
from logging_utils import (
    error,
    info,
)
from manifest import add_evidence


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def calculate_hash(file_path):
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:
        while chunk := file.read(4096):
            sha256.update(chunk)

    return sha256.hexdigest()


def load_existing_metadata():
    records = []

    if not METADATA_DIR.exists():
        return records

    for metadata_file in METADATA_DIR.glob("*.json"):
        try:
            with open(metadata_file, "r") as file:
                records.append(json.load(file))
        except (OSError, json.JSONDecodeError):
            continue

    return records


def find_duplicate(evidence_hash):
    for metadata in load_existing_metadata():
        if metadata.get("sha256") == evidence_hash:
            return metadata

    return None


def ingest_evidence(evidence_file):
    info(
        f"Evidence detected: {evidence_file.name}"
    )

    evidence_hash = calculate_hash(
        evidence_file
    )

    duplicate = find_duplicate(
        evidence_hash
    )

    if duplicate:
        evidence_id = duplicate["evidence_id"]

        info(
            f"Duplicate evidence detected: "
            f"{evidence_id}"
        )

        add_evidence({
            "evidence_id": evidence_id,
            "source": evidence_file.name,
            "sha256": evidence_hash,
            "status": "DUPLICATE",
            "duplicate_of": evidence_id,
            "detected_at": utc_now(),
        })

        log_event(
            evidence_id,
            "EVIDENCE_DUPLICATE",
            {
                "source": evidence_file.name,
                "sha256": evidence_hash,
            },
        )

        return None

    evidence_id = (
        "TRACE-EV-"
        + datetime.now(timezone.utc)
        .strftime("%Y%m%d%H%M%S%f")
    )

    collected_at = utc_now()

    VAULT_EVIDENCE_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    METADATA_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    vault_file = (
        VAULT_EVIDENCE_DIR
        / f"{evidence_id}.log"
    )

    metadata_file = (
        METADATA_DIR
        / f"{evidence_id}.json"
    )

    shutil.copy2(
        evidence_file,
        vault_file,
    )

    try:
        vault_file.chmod(0o600)
    except OSError:
        pass

    metadata = {
        "schema_version": "1.0",
        "evidence_id": evidence_id,
        "run_id": RUN_ID,
        "original_filename": evidence_file.name,
        "collection_time": collected_at,
        "sha256": evidence_hash,
    }

    with open(metadata_file, "w") as file:
        json.dump(
            metadata,
            file,
            indent=4,
        )

    try:
        metadata_file.chmod(0o600)
    except OSError:
        pass

    add_evidence({
        "evidence_id": evidence_id,
        "source": evidence_file.name,
        "sha256": evidence_hash,
        "status": "INGESTED",
        "collection_time": collected_at,
    })

    log_event(
        evidence_id,
        "EVIDENCE_STORED",
        {
            "source": evidence_file.name,
            "sha256": evidence_hash,
        },
    )

    info(
        f"Evidence stored: {evidence_id}"
    )

    return (
        vault_file,
        metadata_file,
        evidence_id,
    )


def main():
    info("Evidence ingestion started")

    if not EVIDENCE_INPUT_DIR.exists():
        error("Evidence input directory does not exist")
        return 1

    evidence_files = sorted(
        file
        for file in EVIDENCE_INPUT_DIR.iterdir()
        if file.is_file()
    )

    if not evidence_files:
        error("No evidence found")
        return 1

    ingested = 0
    duplicates = 0

    for evidence_file in evidence_files:
        result = ingest_evidence(
            evidence_file
        )

        if result is None:
            duplicates += 1
        else:
            ingested += 1

    info(
        f"New evidence: {ingested}"
    )

    info(
        f"Duplicate evidence: {duplicates}"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
