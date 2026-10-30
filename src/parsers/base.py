from abc import ABC, abstractmethod
from pathlib import Path


class BaseParser(ABC):

    name = "unknown"

    @abstractmethod
    def can_parse(
        self,
        file_path: Path,
        sample_lines: list[str]
    ) -> bool:
        pass

    @abstractmethod
    def parse_line(
        self,
        line: str
    ) -> dict | None:
        pass
