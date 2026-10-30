import hashlib
import json

from config import (
    CUSTODY_FILE,
    RUN_ID,
)

from logging_utils import (
    error,
    passed,
)
from manifest import set_integrity_status


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


def fail():
    set_integrity_status("FAILED")
    return False


def verify_chain():
    if not CUSTODY_FILE.exists():
        error("Custody chain not found")
        return fail()

    with open(CUSTODY_FILE, "r") as file:
        lines = [
            line
            for line in file
            if line.strip()
        ]

    if not lines:
        error("Custody chain is empty")
        return fail()

    previous_hash = "GENESIS"
    expected_sequence = 1

    for line in lines:
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            error("Invalid custody record")
            return fail()

        if event.get("run_id") != RUN_ID:
            error("Custody record belongs to another run")
            return fail()

        if event.get("sequence") != expected_sequence:
            error(
                "Custody sequence validation failed"
            )
            return fail()

        if (
            event.get("previous_event_hash")
            != previous_hash
        ):
            error("Custody hash link validation failed")
            return fail()

        calculated_hash = calculate_event_hash(
            event
        )

        if (
            event.get("event_hash")
            != calculated_hash
        ):
            error(
                "Custody event hash validation failed"
            )
            return fail()

        previous_hash = event["event_hash"]
        expected_sequence += 1

    passed("Custody chain verified")
    return True


if __name__ == "__main__":
    raise SystemExit(
        0 if verify_chain() else 1
    )
