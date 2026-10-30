import hashlib
import json
from datetime import datetime, timezone

from config import (
    CUSTODY_FILE,
    RUN_ID,
)

from logging_utils import info


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def calculate_event_hash(event):
    event_data = event.copy()
    event_data.pop("event_hash", None)

    event_string = json.dumps(
        event_data,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    return hashlib.sha256(
        event_string
    ).hexdigest()


def get_previous_state():
    if not CUSTODY_FILE.exists():
        return 0, "GENESIS"

    with open(CUSTODY_FILE, "r") as file:
        lines = [
            line
            for line in file
            if line.strip()
        ]

    if not lines:
        return 0, "GENESIS"

    last_event = json.loads(lines[-1])

    return (
        int(last_event["sequence"]),
        last_event["event_hash"],
    )


def log_event(
    evidence_id,
    event_type,
    details,
):
    CUSTODY_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    previous_sequence, previous_hash = (
        get_previous_state()
    )

    event = {
        "sequence": previous_sequence + 1,
        "timestamp": utc_now(),
        "run_id": RUN_ID,
        "evidence_id": evidence_id,
        "event": event_type,
        "details": details,
        "previous_event_hash": previous_hash,
    }

    event["event_hash"] = (
        calculate_event_hash(event)
    )

    with open(CUSTODY_FILE, "a") as file:
        file.write(
            json.dumps(event) + "\n"
        )

    try:
        CUSTODY_FILE.chmod(0o600)
    except OSError:
        pass

    info(
        f"Custody event recorded: {event_type}"
    )

    return event
