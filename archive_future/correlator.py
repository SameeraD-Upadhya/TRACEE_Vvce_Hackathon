import json
from datetime import datetime

from config import (
    CORRELATED_EVENTS_FILE,
    CORRELATION_WINDOW_SECONDS,
    ENTITIES_FILE,
    RUN_ID,
)

from logging_utils import (
    error,
    info,
)


def load_events():
    events = []

    with open(
        ENTITIES_FILE,
        "r"
    ) as file:

        for line in file:

            if line.strip():
                events.append(
                    json.loads(line)
                )

    return events


def get_entity_values(
    event,
    entity_type
):
    values = []

    for entity in event.get(
        "entities",
        []
    ):

        if entity.get("type") == entity_type:
            values.append(
                entity.get("value")
            )

    return [
        value
        for value in values
        if value
    ]


def parse_timestamp(value):
    return datetime.strptime(
        value,
        "%Y-%m-%d %H:%M:%S"
    )


def shared_entities(
    first_event,
    second_event
):
    shared = []

    entity_types = {
        "USER",
        "IP",
        "DOMAIN",
        "DEVICE",
    }

    for entity_type in entity_types:

        first_values = set(
            get_entity_values(
                first_event,
                entity_type
            )
        )

        second_values = set(
            get_entity_values(
                second_event,
                entity_type
            )
        )

        for value in sorted(
            first_values & second_values
        ):

            shared.append({
                "type": entity_type,
                "value": value
            })

    return shared


def events_are_related(
    current_event,
    candidate_event,
    previous_timestamp
):
    candidate_timestamp = parse_timestamp(
        candidate_event["timestamp"]
    )

    time_gap = (
        candidate_timestamp
        - previous_timestamp
    ).total_seconds()

    if time_gap < 0:
        return False

    if (
        time_gap
        > CORRELATION_WINDOW_SECONDS
    ):
        return False

    return bool(
        shared_entities(
            current_event,
            candidate_event
        )
    )


def build_correlation(
    group,
    correlation_number
):
    evidence_ids = sorted(
        {
            event["evidence_id"]
            for event in group
        }
    )

    shared = []

    for index, first_event in enumerate(
        group
    ):

        for second_event in group[
            index + 1:
        ]:

            shared.extend(
                shared_entities(
                    first_event,
                    second_event
                )
            )

    unique_shared = []
    seen = set()

    for entity in shared:

        key = (
            entity["type"],
            entity["value"]
        )

        if key not in seen:
            seen.add(key)
            unique_shared.append(
                entity
            )

    return {
        "schema_version": "1.3",
        "correlation_id":
            f"CORR-{correlation_number:04d}",
        "run_id": RUN_ID,
        "window_seconds":
            CORRELATION_WINDOW_SECONDS,
        "evidence_ids":
            evidence_ids,
        "shared_entities":
            unique_shared,
        "start_time":
            group[0]["timestamp"],
        "end_time":
            group[-1]["timestamp"],
        "events": [
            {
                "event_id":
                    event["event_id"],
                "evidence_id":
                    event["evidence_id"],
                "evidence_sha256":
                    event["evidence_sha256"],
                "timestamp":
                    event["timestamp"],
                "event_type":
                    event["event_type"],
                "parser":
                    event.get("parser"),
                "source":
                    event["source"],
                "line_number":
                    event["line_number"],
                "raw_line_sha256":
                    event["raw_line_sha256"],
                "attributes":
                    event.get(
                        "attributes",
                        {}
                    ),
                "entities":
                    event.get(
                        "entities",
                        []
                    ),
            }
            for event in group
        ],
        "event_count": len(group),
    }


def correlate(events):

    if not events:
        return []

    events.sort(
        key=lambda event:
        parse_timestamp(
            event["timestamp"]
        )
    )

    correlations = []
    used = set()

    for start_index, start_event in enumerate(
        events
    ):

        if start_event["event_id"] in used:
            continue

        group = [start_event]

        previous_timestamp = parse_timestamp(
            start_event["timestamp"]
        )

        used.add(
            start_event["event_id"]
        )

        for candidate_event in events[
            start_index + 1:
        ]:

            if candidate_event[
                "event_id"
            ] in used:
                continue

            if events_are_related(
                group[-1],
                candidate_event,
                previous_timestamp
            ):

                group.append(
                    candidate_event
                )

                previous_timestamp = (
                    parse_timestamp(
                        candidate_event[
                            "timestamp"
                        ]
                    )
                )

                used.add(
                    candidate_event[
                        "event_id"
                    ]
                )

        if len(group) > 1:

            correlations.append(
                build_correlation(
                    group,
                    len(correlations) + 1
                )
            )

    return correlations


def main():

    info(
        "Event correlation started"
    )

    info(
        "Correlation window: "
        f"{CORRELATION_WINDOW_SECONDS} seconds"
    )

    if not ENTITIES_FILE.exists():

        error(
            "Entity file not found"
        )

        return 1

    events = load_events()

    correlations = correlate(
        events
    )

    with open(
        CORRELATED_EVENTS_FILE,
        "w"
    ) as file:

        for correlation in correlations:

            file.write(
                json.dumps(
                    correlation
                ) + "\n"
            )

    info(
        f"Correlations identified: "
        f"{len(correlations)}"
    )

    info(
        f"Output: "
        f"{CORRELATED_EVENTS_FILE}"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(
        main()
    )
