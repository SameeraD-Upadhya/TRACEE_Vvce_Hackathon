from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

try:
    from src.config import BASE_DIR
except ModuleNotFoundError:
    from config import BASE_DIR


RUN_ID_PATTERN = re.compile(r"^TRACE-RUN-[A-Za-z0-9T:_-]+$")
EVIDENCE_ID_PATTERN = re.compile(r"^TRACE-EV-[A-Za-z0-9_-]+$")

TEXT_SUFFIXES = {
    ".log",
    ".txt",
    ".json",
    ".jsonl",
    ".ndjson",
    ".csv",
}

MAX_RAW_BYTES = 256 * 1024


class CaseStore:
    """Read-only access to completed TRACEE investigations."""

    def __init__(self, base_dir: Path | None = None) -> None:
        self.base_dir = Path(base_dir or BASE_DIR).resolve()
        self.vault_dir = (self.base_dir / "vault").resolve()
        self.investigations_dir = (self.base_dir / "investigations").resolve()

    def _validate_run_id(self, run_id: str) -> str:
        if not RUN_ID_PATTERN.fullmatch(run_id):
            raise ValueError("invalid run_id")
        return run_id

    def _validate_evidence_id(self, evidence_id: str) -> str:
        if not EVIDENCE_ID_PATTERN.fullmatch(evidence_id):
            raise ValueError("invalid evidence_id")
        return evidence_id

    def _run_investigation_dir(self, run_id: str) -> Path:
        run_id = self._validate_run_id(run_id)

        path = (self.investigations_dir / run_id).resolve()

        if path.parent != self.investigations_dir:
            raise ValueError("invalid investigation path")

        if not path.is_dir():
            raise FileNotFoundError(run_id)

        return path

    def _run_vault_dir(self, run_id: str) -> Path:
        run_id = self._validate_run_id(run_id)

        path = (self.vault_dir / run_id).resolve()

        if path.parent != self.vault_dir:
            raise ValueError("invalid vault path")

        if not path.is_dir():
            raise FileNotFoundError(run_id)

        return path

    @staticmethod
    def _load_json(path: Path) -> Any:
        return json.loads(path.read_text(encoding="utf-8"))

    @staticmethod
    def _load_jsonl(path: Path) -> list[dict[str, Any]]:
        if not path.exists():
            return []

        records: list[dict[str, Any]] = []

        for line_number, line in enumerate(
            path.read_text(encoding="utf-8").splitlines(),
            start=1,
        ):
            if not line.strip():
                continue

            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                records.append(
                    {
                        "_parse_error": True,
                        "line_number": line_number,
                        "raw": line,
                    }
                )
                continue

            if isinstance(record, dict):
                records.append(record)
            else:
                records.append({"value": record})

        return records

    def _manifest_path(self, run_id: str) -> Path:
        return self._run_investigation_dir(run_id) / "manifest.json"

    def list_investigations(self) -> list[dict[str, Any]]:
        if not self.investigations_dir.is_dir():
            return []

        results: list[dict[str, Any]] = []

        for path in sorted(
            self.investigations_dir.iterdir(),
            reverse=True,
        ):
            if not path.is_dir() or not path.name.startswith("TRACE-RUN-"):
                continue

            manifest_path = path / "manifest.json"

            record: dict[str, Any] = {
                "run_id": path.name,
                "status": "UNKNOWN",
                "integrity": "UNKNOWN",
                "evidence_count": 0,
            }

            if manifest_path.exists():
                try:
                    manifest = self._load_json(manifest_path)

                    record.update(
                        {
                            "run_id": manifest.get(
                                "run_id",
                                path.name,
                            ),
                            "status": manifest.get(
                                "status",
                                "UNKNOWN",
                            ),
                            "integrity": manifest.get(
                                "integrity",
                                manifest.get(
                                    "integrity_status",
                                    "UNKNOWN",
                                ),
                            ),
                            "evidence_count": len(
                                manifest.get(
                                    "evidence",
                                    [],
                                )
                            ),
                            "started_at": manifest.get(
                                "started_at"
                            ),
                            "completed_at": manifest.get(
                                "completed_at"
                            ),
                        }
                    )

                except (
                    OSError,
                    json.JSONDecodeError,
                ):
                    record["status"] = "INVALID_MANIFEST"

            results.append(record)

        return results

    def get_investigation(
        self,
        run_id: str,
    ) -> dict[str, Any]:

        manifest_path = self._manifest_path(run_id)

        if not manifest_path.exists():
            raise FileNotFoundError(run_id)

        manifest = self._load_json(manifest_path)

        manifest["evidence"] = self.list_evidence(run_id)

        return manifest

    def _output_path(
        self,
        run_id: str,
        filename: str,
    ) -> Path:

        run_dir = self._run_investigation_dir(run_id)

        path = (run_dir / filename).resolve()

        if path.parent != run_dir:
            raise ValueError("invalid output path")

        return path

    def get_events(
        self,
        run_id: str,
    ) -> list[dict[str, Any]]:

        return self._load_jsonl(
            self._output_path(
                run_id,
                "normalized_events.jsonl",
            )
        )

    def get_correlations(
        self,
        run_id: str,
    ) -> list[dict[str, Any]]:

        return self._load_jsonl(
            self._output_path(
                run_id,
                "correlated_events.jsonl",
            )
        )

    def get_timeline(
        self,
        run_id: str,
    ) -> Any:

        return self._load_json(
            self._output_path(
                run_id,
                "incident_timeline.json",
            )
        )

    def get_graph(
        self,
        run_id: str,
    ) -> Any:

        return self._load_json(
            self._output_path(
                run_id,
                "investigation_graph.json",
            )
        )

    def _metadata_dir(
        self,
        run_id: str,
    ) -> Path:

        return self._run_vault_dir(run_id) / "metadata"

    def _evidence_dir(
        self,
        run_id: str,
    ) -> Path:

        return self._run_vault_dir(run_id) / "evidence"

    def list_evidence(
        self,
        run_id: str,
    ) -> list[dict[str, Any]]:

        manifest_path = self._manifest_path(run_id)

        manifest_evidence: list[dict[str, Any]] = []

        if manifest_path.exists():
            try:
                manifest = self._load_json(manifest_path)

                raw = manifest.get("evidence", [])

                if isinstance(raw, list):
                    manifest_evidence = [
                        item
                        for item in raw
                        if isinstance(item, dict)
                    ]

            except (
                OSError,
                json.JSONDecodeError,
            ):
                manifest_evidence = []

        metadata_dir = self._metadata_dir(run_id)

        metadata_records: dict[
            str,
            dict[str, Any],
        ] = {}

        if metadata_dir.is_dir():

            for path in sorted(
                metadata_dir.glob("*.json")
            ):
                try:
                    record = self._load_json(path)

                except (
                    OSError,
                    json.JSONDecodeError,
                ):
                    continue

                if not isinstance(record, dict):
                    continue

                evidence_id = (
                    record.get("evidence_id")
                    or path.stem
                )

                if isinstance(
                    evidence_id,
                    str,
                ):
                    metadata_records[
                        evidence_id
                    ] = record

        merged: dict[
            str,
            dict[str, Any],
        ] = {}

        for item in manifest_evidence:

            evidence_id = (
                item.get("evidence_id")
                or item.get("id")
            )

            if isinstance(
                evidence_id,
                str,
            ):
                merged[evidence_id] = dict(item)

        for (
            evidence_id,
            metadata,
        ) in metadata_records.items():

            merged.setdefault(
                evidence_id,
                {},
            )

            merged[evidence_id].update(
                metadata
            )

        evidence_dir = self._evidence_dir(run_id)

        if evidence_dir.is_dir():

            for path in sorted(
                evidence_dir.iterdir()
            ):

                if not path.is_file():
                    continue

                for evidence_id in list(
                    merged
                ):

                    if path.stem == evidence_id:

                        merged[
                            evidence_id
                        ].setdefault(
                            "vault_filename",
                            path.name,
                        )

                        break

        results = list(
            merged.values()
        )

        results.sort(
            key=lambda item: str(
                item.get(
                    "evidence_id",
                    "",
                )
            )
        )

        return results

    def _locate_evidence_file(
        self,
        run_id: str,
        evidence_id: str,
        metadata: dict[str, Any],
    ) -> Path | None:

        evidence_dir = self._evidence_dir(
            run_id
        )

        if not evidence_dir.is_dir():
            return None

        candidates: list[Path] = []

        for key in (
            "vault_path",
            "stored_path",
            "path",
            "evidence_path",
            "vault_filename",
        ):

            value = metadata.get(key)

            if isinstance(
                value,
                str,
            ) and value:

                candidate = Path(value)

                if not candidate.is_absolute():
                    candidate = (
                        evidence_dir
                        / candidate
                    )

                candidates.append(
                    candidate
                )

        candidates.extend(
            sorted(
                evidence_dir.glob(
                    f"{evidence_id}.*"
                )
            )
        )

        candidates.append(
            evidence_dir / evidence_id
        )

        seen: set[Path] = set()

        for candidate in candidates:

            try:
                resolved = candidate.resolve()

            except OSError:
                continue

            if resolved in seen:
                continue

            seen.add(resolved)

            try:
                resolved.relative_to(
                    evidence_dir.resolve()
                )

            except ValueError:
                continue

            if resolved.is_file():
                return resolved

        return None

    def get_evidence_detail(
        self,
        run_id: str,
        evidence_id: str,
    ) -> dict[str, Any]:

        self._validate_run_id(run_id)

        self._validate_evidence_id(
            evidence_id
        )

        evidence_records = self.list_evidence(
            run_id
        )

        metadata: dict[str, Any] = {}

        for item in evidence_records:

            item_id = (
                item.get("evidence_id")
                or item.get("id")
            )

            if item_id == evidence_id:

                metadata = dict(item)

                break

        metadata_path = (
            self._metadata_dir(run_id)
            / f"{evidence_id}.json"
        )

        if metadata_path.exists():

            try:

                file_metadata = self._load_json(
                    metadata_path
                )

                if isinstance(
                    file_metadata,
                    dict,
                ):

                    metadata = {
                        **metadata,
                        **file_metadata,
                    }

            except (
                OSError,
                json.JSONDecodeError,
            ):
                pass

        if (
            not metadata
            and not metadata_path.exists()
        ):
            raise FileNotFoundError(
                evidence_id
            )

        evidence_path = (
            self._locate_evidence_file(
                run_id,
                evidence_id,
                metadata,
            )
        )

        raw_content: str | None = None

        raw_available = False
        raw_truncated = False

        current_sha256: str | None = None

        if evidence_path is not None:

            raw_available = True

            current_sha256 = (
                hashlib.sha256(
                    evidence_path.read_bytes()
                ).hexdigest()
            )

            if (
                evidence_path.suffix.lower()
                in TEXT_SUFFIXES
            ):

                data = (
                    evidence_path.read_bytes()
                )

                if len(data) > MAX_RAW_BYTES:

                    data = data[
                        :MAX_RAW_BYTES
                    ]

                    raw_truncated = True

                raw_content = data.decode(
                    "utf-8",
                    errors="replace",
                )

        expected_sha256 = (
            metadata.get("sha256")
            or metadata.get(
                "evidence_sha256"
            )
        )

        integrity_status = "UNAVAILABLE"

        if (
            expected_sha256
            and current_sha256
        ):

            integrity_status = (
                "VERIFIED"
                if expected_sha256
                == current_sha256
                else "MISMATCH"
            )

        custody_path = self._output_path(
            run_id,
            "chain_of_custody.jsonl",
        )

        custody_events = [
            event
            for event in self._load_jsonl(
                custody_path
            )
            if event.get(
                "evidence_id"
            )
            == evidence_id
        ]

        return {
            "run_id": run_id,
            "evidence_id": evidence_id,
            "metadata": metadata,
            "vault_filename": (
                evidence_path.name
                if evidence_path
                else None
            ),
            "raw_available": raw_available,
            "raw_content": raw_content,
            "raw_truncated": raw_truncated,
            "current_sha256": current_sha256,
            "expected_sha256": expected_sha256,
            "integrity_status": integrity_status,
            "custody_events": custody_events,
        }
