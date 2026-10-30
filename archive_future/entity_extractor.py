import json
import ipaddress

from config import (
    ENTITIES_FILE,
    NORMALIZED_EVENTS_FILE,
)

from logging_utils import (
    error,
    info,
)


def is_valid_ip(value):

    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def identify_entities(event):

    entities = []

    attributes = event.get(
        "attributes",
        {}
    )

    user = attributes.get("user")

    if user:
        entities.append({
            "type": "USER",
            "value": user
        })

    ip = attributes.get("ip")

    if ip and is_valid_ip(ip):
        entities.append({
            "type": "IP",
            "value": ip
        })

    source_ip = attributes.get(
        "source_ip"
    )

    if source_ip and is_valid_ip(source_ip):
        entities.append({
            "type": "IP",
            "value": source_ip,
            "role": "SOURCE"
        })

    destination_ip = attributes.get(
        "destination_ip"
    )

    if (
        destination_ip
        and is_valid_ip(destination_ip)
    ):
        entities.append({
            "type": "IP",
            "value": destination_ip,
            "role": "DESTINATION"
        })

    domain = attributes.get(
        "domain"
    )

    if domain:
        entities.append({
            "type": "DOMAIN",
            "value": domain
        })

    hostname = attributes.get(
        "hostname"
    )

    if hostname:
        entities.append({
            "type": "DEVICE",
            "value": hostname
        })

    process = attributes.get(
        "process"
    )

    if process:
        entities.append({
            "type": "PROCESS",
            "value": process
        })

    file_path = attributes.get(
        "file"
    )

    if file_path:
        entities.append({
            "type": "FILE",
            "value": file_path
        })

    return entities


def main():

    info("Entity extraction started")

    if not NORMALIZED_EVENTS_FILE.exists():

        error(
            "Normalized event file not found"
        )

        return 1

    total_entities = 0

    with open(
        NORMALIZED_EVENTS_FILE,
        "r"
    ) as input_file, open(
        ENTITIES_FILE,
        "w"
    ) as output_file:

        for line in input_file:

            if not line.strip():
                continue

            event = json.loads(line)

            entities = identify_entities(
                event
            )

            enriched_event = {
                "schema_version": "1.1",
                "event_id": event[
                    "event_id"
                ],
                "run_id": event[
                    "run_id"
                ],
                "evidence_id": event[
                    "evidence_id"
                ],
                "evidence_sha256":
                    event[
                        "evidence_sha256"
                    ],
                "timestamp":
                    event[
                        "timestamp"
                    ],
                "event_type":
                    event[
                        "event_type"
                    ],
                "parser":
                    event[
                        "parser"
                    ],
                "source":
                    event[
                        "source"
                    ],
                "line_number":
                    event[
                        "line_number"
                    ],
                "raw_line_sha256":
                    event[
                        "raw_line_sha256"
                    ],
                "attributes":
                    event[
                        "attributes"
                    ],
                "entities":
                    entities
            }

            output_file.write(
                json.dumps(
                    enriched_event
                ) + "\n"
            )

            total_entities += len(
                entities
            )

    info(
        f"Entities extracted: "
        f"{total_entities}"
    )

    info(
        f"Output: {ENTITIES_FILE}"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
