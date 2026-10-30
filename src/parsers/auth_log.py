import re
from pathlib import Path

from .base import BaseParser


class AuthLogParser(BaseParser):

    name = "linux_auth"

    PATTERN = re.compile(
        r"(?P<timestamp>\d{4}-\d{2}-\d{2} "
        r"\d{2}:\d{2}:\d{2}) "
        r"(?P<event_type>\S+) "
        r"user=(?P<user>\S+) "
        r"ip=(?P<ip>\S+)"
    )

    def can_parse(
        self,
        file_path: Path,
        sample_lines: list[str]
    ) -> bool:

        for line in sample_lines:
            if self.PATTERN.match(line.strip()):
                return True

        return False

    def parse_line(
        self,
        line: str
    ) -> dict | None:

        match = self.PATTERN.match(
            line.strip()
        )

        if not match:
            return None

        return {
            "timestamp": match.group("timestamp"),
            "event_type": match.group("event_type"),
            "attributes": {
                "user": match.group("user"),
                "ip": match.group("ip")
            }
        }
