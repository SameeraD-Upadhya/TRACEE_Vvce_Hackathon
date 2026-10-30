import json

from config import (
    CORRELATED_EVENTS_FILE,
    RUN_ID,
    TIMELINE_FILE,
)

from logging_utils import (
    error,
    info,
)


def main():

    info("Timeline generation started")

    if not CORRELATED_EVENTS_FILE.exists():
        error("Correlation file not found")
        return 1

    correlations = []

    with open(
        CORRELATED_EVENTS_FILE,
        "r"
    ) as file:

        for line in file:

            if line.strip():
                correlations.append(
                    json.loads(line)
                )

    timeline = []

    for correlation in correlations:

        incident = {
            "schema_version": "1.3",
            "correlation_id":
                correlation["correlation_id"],
            "run_id":
                correlation["run_id"],
            "window_seconds":
                correlation.get(
                    "window_seconds"
                ),
            "evidence_ids":
                correlation.get(
                    "evidence_ids",
                    []
                ),
            "shared_entities":
                correlation.get(
                    "shared_entities",
                    []
                ),
            "start_time":
                correlation["start_time"],
            "end_time":
                correlation["end_time"],
            "event_count":
                correlation["event_count"],
            "events": []
        }

        for event in correlation["events"]:

            incident["events"].append({
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
                    )
            })

        timeline.append(incident)

    with open(
        TIMELINE_FILE,
        "w"
    ) as file:

        json.dump(
            timeline,
            file,
            indent=4
        )

    info(
        f"Incidents generated: "
        f"{len(timeline)}"
    )

    info(
        f"Output: {TIMELINE_FILE}"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
