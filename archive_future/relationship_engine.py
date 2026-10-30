from logging_utils import info


def make_entity(
    entity_type,
    value
):
    if not value:
        return None

    return {
        "type": entity_type,
        "value": value
    }


def entity_id(entity):
    return (
        f"{entity['type']}:{entity['value']}"
    )


def get_attribute(
    attributes,
    *names
):
    for name in names:
        value = attributes.get(name)

        if value:
            return value

    return None


def unique_relationships(
    relationships
):
    result = []
    seen = set()

    for relationship in relationships:

        key = (
            relationship["source"],
            relationship["target"],
            relationship["relationship"],
            relationship.get("event_id")
        )

        if key in seen:
            continue

        seen.add(key)
        result.append(relationship)

    return result


def build_relationships(event):

    attributes = event.get(
        "attributes",
        {}
    )

    event_type = event.get(
        "event_type",
        ""
    )

    event_id = event.get(
        "event_id"
    )

    relationships = []

    user = make_entity(
        "USER",
        get_attribute(
            attributes,
            "user",
            "username",
            "account"
        )
    )

    source_ip = make_entity(
        "IP",
        get_attribute(
            attributes,
            "source_ip",
            "ip"
        )
    )

    destination_ip = make_entity(
        "IP",
        get_attribute(
            attributes,
            "destination_ip",
            "remote_ip",
            "dest_ip"
        )
    )

    domain = make_entity(
        "DOMAIN",
        get_attribute(
            attributes,
            "domain",
            "hostname_domain"
        )
    )

    device = make_entity(
        "DEVICE",
        get_attribute(
            attributes,
            "hostname",
            "device"
        )
    )

    process = make_entity(
        "PROCESS",
        get_attribute(
            attributes,
            "process",
            "process_name"
        )
    )

    file_entity = make_entity(
        "FILE",
        get_attribute(
            attributes,
            "file",
            "file_path",
            "filename"
        )
    )

    if (
        event_type in {
            "SUCCESS_LOGIN",
            "LOGIN_SUCCESS"
        }
        and user
        and source_ip
    ):
        relationships.append({
            "source": entity_id(user),
            "target": entity_id(source_ip),
            "relationship": "AUTHENTICATES_FROM",
            "event_id": event_id
        })

    if (
        event_type == "PROCESS_START"
        and user
        and process
    ):
        relationships.append({
            "source": entity_id(user),
            "target": entity_id(process),
            "relationship": "STARTS",
            "event_id": event_id
        })

    if (
        event_type == "NETWORK_CONNECTION"
        and process
        and destination_ip
    ):
        relationships.append({
            "source": entity_id(process),
            "target": entity_id(destination_ip),
            "relationship": "CONNECTS_TO",
            "event_id": event_id
        })

    if (
        event_type in {
            "FILE_MODIFIED",
            "FILE_CREATED",
            "FILE_DELETED"
        }
        and process
        and file_entity
    ):

        relationship_map = {
            "FILE_MODIFIED": "MODIFIES",
            "FILE_CREATED": "CREATES",
            "FILE_DELETED": "DELETES"
        }

        relationships.append({
            "source": entity_id(process),
            "target": entity_id(file_entity),
            "relationship": relationship_map[
                event_type
            ],
            "event_id": event_id
        })

    if (
        event_type == "DNS_QUERY"
        and user
        and domain
    ):
        relationships.append({
            "source": entity_id(user),
            "target": entity_id(domain),
            "relationship": "QUERIES",
            "event_id": event_id
        })

    if (
        event_type == "NETWORK_CONNECTION"
        and device
        and destination_ip
    ):
        relationships.append({
            "source": entity_id(device),
            "target": entity_id(destination_ip),
            "relationship": "COMMUNICATES_WITH",
            "event_id": event_id
        })

    relationships = unique_relationships(
        relationships
    )

    for relationship in relationships:
        info(
            "Relationship inferred: "
            f"{relationship['source']} "
            f"--{relationship['relationship']}--> "
            f"{relationship['target']}"
        )

    return relationships
