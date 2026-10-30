import json

from config import (
    GRAPH_FILE,
    RUN_ID,
    TIMELINE_FILE,
)

from logging_utils import (
    error,
    info,
)

from relationship_engine import (
    build_relationships,
)


def make_node(
    node_id,
    node_type,
    value,
    metadata=None,
):
    node = {
        "id": node_id,
        "type": node_type,
        "value": value,
    }

    if metadata:
        node["metadata"] = metadata

    return node


def make_edge(
    source,
    target,
    relationship,
    event_id=None,
):
    edge = {
        "source": source,
        "target": target,
        "relationship": relationship,
    }

    if event_id:
        edge["event_id"] = event_id

    return edge


def ensure_entity_node(
    nodes,
    node_ids,
    entity,
):
    node_id = (
        f"{entity['type']}:{entity['value']}"
    )

    if node_id not in node_ids:
        nodes.append(
            make_node(
                node_id,
                entity["type"],
                entity["value"],
            )
        )

        node_ids.add(node_id)


def build_graph(timeline):

    nodes = []
    edges = []
    node_ids = set()

    for incident in timeline:

        shared_entities = incident.get(
            "shared_entities",
            []
        )

        for entity in shared_entities:
            ensure_entity_node(
                nodes,
                node_ids,
                entity,
            )

        for event in incident["events"]:

            event_node_id = (
                f"EVENT:{event['event_id']}"
            )

            event_attributes = event.get(
                "attributes",
                {}
            )

            nodes.append(
                make_node(
                    event_node_id,
                    "EVENT",
                    event["event_type"],
                    {
                        "event_id":
                            event["event_id"],
                        "evidence_id":
                            event["evidence_id"],
                        "evidence_sha256":
                            event[
                                "evidence_sha256"
                            ],
                        "timestamp":
                            event["timestamp"],
                        "source":
                            event["source"],
                        "line_number":
                            event["line_number"],
                        "raw_line_sha256":
                            event[
                                "raw_line_sha256"
                            ],
                        "attributes":
                            event_attributes,
                    },
                )
            )

            event_entities = []

            for entity in shared_entities:
                event_entities.append(entity)

            relationships = build_relationships({
                "event_id":
                    event["event_id"],
                "event_type":
                    event["event_type"],
                "attributes":
                    event_attributes,
                "entities":
                    event_entities,
            })

            for relationship in relationships:

                ensure_entity_node(
                    nodes,
                    node_ids,
                    {
                        "type":
                            relationship["source"].split(
                                ":",
                                1
                            )[0],
                        "value":
                            relationship["source"].split(
                                ":",
                                1
                            )[1],
                    }
                )

                ensure_entity_node(
                    nodes,
                    node_ids,
                    {
                        "type":
                            relationship["target"].split(
                                ":",
                                1
                            )[0],
                        "value":
                            relationship["target"].split(
                                ":",
                                1
                            )[1],
                    }
                )

                edges.append(
                    make_edge(
                        relationship["source"],
                        relationship["target"],
                        relationship["relationship"],
                        relationship["event_id"],
                    )
                )

    return {
        "schema_version": "1.3",
        "run_id": RUN_ID,
        "nodes": nodes,
        "edges": edges,
    }


def main():

    info(
        "Investigation graph generation started"
    )

    if not TIMELINE_FILE.exists():

        error(
            "Timeline file not found"
        )

        return 1

    with open(
        TIMELINE_FILE,
        "r"
    ) as file:

        timeline = json.load(file)

    graph = build_graph(timeline)

    with open(
        GRAPH_FILE,
        "w"
    ) as file:

        json.dump(
            graph,
            file,
            indent=4
        )

    info(
        f"Nodes created: "
        f"{len(graph['nodes'])}"
    )

    info(
        f"Edges created: "
        f"{len(graph['edges'])}"
    )

    info(
        f"Output: {GRAPH_FILE}"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(
        main()
    )
