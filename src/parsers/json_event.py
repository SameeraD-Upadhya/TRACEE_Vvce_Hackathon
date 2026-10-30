import json
from pathlib import Path

from .base import BaseParser


class JsonEventParser(BaseParser):

    name = "json_event"

    def can_parse(
        self,
        file_path: Path,
        sample_lines: list[str]
    ) -> bool:

        for line in sample_lines:

            if not line.strip():
                continue

            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                return False

            if (
                isinstance(event, dict)
                and "timestamp" in event
                and "event_type" in event
            ):
                return True

            return False

        return False

    def parse_line(
        self,
        line: str
    ) -> dict | None:

        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            return None

        if (
            not isinstance(event, dict)
            or "timestamp" not in event
            or "event_type" not in event
        ):
            return None

        attributes = event.get(
            "attributes",
            {}
        )

        if not isinstance(attributes, dict):
            attributes = {}

        for key in (
            "user",
            "ip",
            "source_ip",
            "destination_ip",
            "domain",
            "hostname",
            "process",
            "file"
        ):
            if key in event and key not in attributes:
                attributes[key] = event[key]

        return {
            "timestamp": event["timestamp"],
            "event_type": event["event_type"],
            "attributes": attributes
        }
