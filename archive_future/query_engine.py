import argparse
import json
from pathlib import Path


def load_jsonl(path):
    records = []

    if not path.exists():
        return records

    with open(path, "r") as file:
        for line in file:
            if line.strip():
                records.append(json.loads(line))

    return records


def load_json(path):
    if not path.exists():
        return None

    with open(path, "r") as file:
        return json.load(file)


def event_matches(
    event,
    event_type=None,
    entity=None,
    evidence_id=None
):
    if (
        event_type
        and event.get("event_type") != event_type
    ):
        return False

    if (
        evidence_id
        and event.get("evidence_id") != evidence_id
    ):
        return False

    if entity:
        event_text = json.dumps(
            event,
            sort_keys=True
        ).lower()

        if entity.lower() not in event_text:
            return False

    return True


def relationship_matches(
    edge,
    relationship=None
):
    if not relationship:
        return True

    return (
        edge.get("relationship")
        == relationship
    )


def correlation_matches(
    correlation,
    correlation_id=None,
    evidence_id=None,
    entity=None
):
    if (
        correlation_id
        and correlation.get("correlation_id")
        != correlation_id
    ):
        return False

    if evidence_id:

        if evidence_id not in correlation.get(
            "evidence_ids",
            []
        ):
            return False

    if entity:

        entity_lower = entity.lower()

        if entity_lower not in json.dumps(
            correlation,
            sort_keys=True
        ).lower():
            return False

    return True


def print_event_results(results):
    print(
        f"[INFO] Matching events: {len(results)}"
    )

    for event in results:
        print()
        print(
            f"[EVENT] {event['event_id']}"
        )
        print(
            f"  Type: {event['event_type']}"
        )
        print(
            f"  Time: {event['timestamp']}"
        )
        print(
            f"  Evidence: {event['evidence_id']}"
        )
        print(
            f"  Source: {event['source']}"
        )
        print(
            f"  Line: {event['line_number']}"
        )
        print(
            f"  Raw SHA-256: "
            f"{event['raw_line_sha256']}"
        )
        print(
            "  Attributes: "
            f"{json.dumps(event.get('attributes', {}))}"
        )


def print_correlation_results(results):
    print(
        f"[INFO] Matching correlations: "
        f"{len(results)}"
    )

    for correlation in results:
        print()
        print(
            f"[CORRELATION] "
            f"{correlation['correlation_id']}"
        )
        print(
            f"  Start: {correlation['start_time']}"
        )
        print(
            f"  End: {correlation['end_time']}"
        )
        print(
            f"  Events: {correlation['event_count']}"
        )
        print(
            "  Evidence: "
            f"{', '.join(correlation.get('evidence_ids', []))}"
        )
        print(
            "  Shared entities: "
            f"{json.dumps(correlation.get('shared_entities', []))}"
        )


def print_relationship_results(results):
    print(
        f"[INFO] Matching relationships: "
        f"{len(results)}"
    )

    for edge in results:
        print()
        print(
            f"[RELATIONSHIP] "
            f"{edge['source']} "
            f"--{edge['relationship']}--> "
            f"{edge['target']}"
        )

        if edge.get("event_id"):
            print(
                f"  Event: {edge['event_id']}"
            )


def run_query(args, run_dir):

    events_file = (
        run_dir / "normalized_events.jsonl"
    )

    correlations_file = (
        run_dir / "correlated_events.jsonl"
    )

    graph_file = (
        run_dir / "investigation_graph.json"
    )

    if args.relationship:
        graph = load_json(graph_file)

        if graph is None:
            print(
                "[ERROR] Investigation graph not found"
            )
            return 1

        results = [
            edge
            for edge in graph.get("edges", [])
            if relationship_matches(
                edge,
                args.relationship
            )
        ]

        print_relationship_results(results)
        return 0

    if args.correlation:
        correlations = load_jsonl(
            correlations_file
        )

        results = [
            correlation
            for correlation in correlations
            if correlation_matches(
                correlation,
                correlation_id=args.correlation,
                evidence_id=args.evidence,
                entity=args.entity
            )
        ]

        print_correlation_results(results)
        return 0

    events = load_jsonl(
        events_file
    )

    results = [
        event
        for event in events
        if event_matches(
            event,
            event_type=args.event_type,
            entity=args.entity,
            evidence_id=args.evidence
        )
    ]

    print_event_results(results)

    return 0


def main():

    parser = argparse.ArgumentParser(
        description="Query a TRACEE investigation"
    )

    parser.add_argument(
        "--run",
        required=True,
        help="Investigation run ID"
    )

    parser.add_argument(
        "--event-type",
        help="Filter events by event type"
    )

    parser.add_argument(
        "--entity",
        help="Search for an entity or attribute"
    )

    parser.add_argument(
        "--evidence",
        help="Filter by evidence ID"
    )

    parser.add_argument(
        "--correlation",
        help="Filter by correlation ID"
    )

    parser.add_argument(
        "--relationship",
        help="Filter graph relationships"
    )

    args = parser.parse_args()

    base_dir = (
        Path(__file__).resolve().parent.parent
    )

    run_dir = (
        base_dir
        / "investigations"
        / args.run
    )

    if not run_dir.exists():
        print(
            f"[ERROR] Investigation not found: "
            f"{args.run}"
        )
        return 1

    manifest = load_json(
        run_dir / "manifest.json"
    )

    if manifest is None:
        print(
            "[ERROR] Investigation manifest not found"
        )
        return 1

    print(
        f"[INFO] Investigation: {args.run}"
    )

    return run_query(
        args,
        run_dir
    )


if __name__ == "__main__":
    raise SystemExit(main())
