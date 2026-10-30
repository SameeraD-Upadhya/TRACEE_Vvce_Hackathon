import json
import sys
from datetime import datetime, timezone

from config import (
    MANIFEST_FILE,
    RUN_ID,
    RUN_ROOT,
)

from logging_utils import (
    error,
    info,
)


EXPECTED_OUTPUTS = [
    "chain_of_custody.jsonl",
    "trusted_evidence.json",
    "normalized_events.jsonl",
    "entities.jsonl",
    "correlated_events.jsonl",
    "incident_timeline.json",
    "investigation_graph.json",
]


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def load_manifest():
    if not MANIFEST_FILE.exists():
        return {
            "schema_version": "1.0",
            "run_id": RUN_ID,
            "created_at": utc_now(),
            "status": "UNKNOWN",
            "evidence": [],
            "outputs": [],
            "integrity": {
                "status": "PENDING"
            },
        }

    with open(MANIFEST_FILE, "r") as file:
        return json.load(file)


def save_manifest(manifest):
    RUN_ROOT.mkdir(
        parents=True,
        exist_ok=True,
    )

    with open(MANIFEST_FILE, "w") as file:
        json.dump(
            manifest,
            file,
            indent=4,
        )

    try:
        MANIFEST_FILE.chmod(0o600)
    except OSError:
        pass


def start_manifest():
    manifest = {
        "schema_version": "1.0",
        "run_id": RUN_ID,
        "created_at": utc_now(),
        "status": "STARTED",
        "evidence": [],
        "outputs": [],
        "integrity": {
            "status": "PENDING"
        },
    }

    save_manifest(manifest)

    info(
        f"Investigation started: {RUN_ID}"
    )


def add_evidence(record):
    manifest = load_manifest()

    manifest.setdefault(
        "evidence",
        []
    ).append(record)

    save_manifest(manifest)


def set_integrity_status(status):
    manifest = load_manifest()

    manifest["integrity"] = {
        "status": status,
        "updated_at": utc_now(),
    }

    save_manifest(manifest)

    info(
        f"Integrity status: {status}"
    )


def validate_outputs():
    missing = []

    for output_name in EXPECTED_OUTPUTS:
        output_path = RUN_ROOT / output_name

        if not output_path.exists():
            missing.append(output_name)

    return missing


def complete_manifest():
    manifest = load_manifest()

    integrity_status = (
        manifest
        .get("integrity", {})
        .get("status")
    )

    if integrity_status != "VERIFIED":
        error(
            "Investigation cannot be marked complete: "
            "integrity status is not VERIFIED"
        )

        return False

    missing_outputs = validate_outputs()

    if missing_outputs:
        error(
            "Investigation cannot be marked complete"
        )

        for output_name in missing_outputs:
            error(
                f"Missing output: {output_name}"
            )

        return False

    manifest["status"] = "COMPLETE"
    manifest["completed_at"] = utc_now()
    manifest["outputs"] = EXPECTED_OUTPUTS

    save_manifest(manifest)

    info("Investigation completed")

    return True


def fail_manifest():
    manifest = load_manifest()

    manifest["status"] = "FAILED"
    manifest["failed_at"] = utc_now()

    save_manifest(manifest)

    info("Investigation marked FAILED")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        error(
            "Usage: python3 src/manifest.py "
            "[start|complete|fail]"
        )
        sys.exit(1)

    command = sys.argv[1]

    if command == "start":
        start_manifest()

    elif command == "complete":
        if not complete_manifest():
            sys.exit(1)

    elif command == "fail":
        fail_manifest()

    else:
        error(
            f"Unknown command: {command}"
        )
        sys.exit(1)
