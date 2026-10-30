"""Verified evidence-backed reconstruction and immutable run storage."""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .analysis import AnalysisError, EvidenceAnalysisService, is_valid_analysis_id
from .events import (
    NormalizedEvent, ParseStatus, SourceObservation, TemporalExtent,
    TimestampInfo, TimestampPrecision, TimezoneStatus,
)
from .hypotheses import EventHypothesis, InferenceRule, InterpretationState, ReviewStatus
from .ids import is_valid_evidence_id
from .locking import exclusive_file_lock, set_private_file_permissions, set_private_permissions
from .models import ModelValidationError
from .reconstruction import ReconstructionConfig, ReconstructionResult, SkippedInput, reconstruct
from .reconstruction_rules import BUILTIN_RULES, EVENT_TYPE_ATTRIBUTE, rules_for_source
from .services import TraceeService

RECONSTRUCTION_SCHEMA_VERSION = "1.0"
RECONSTRUCTION_DIRECTORY = "reconstructions"
RECONSTRUCTION_ID_RE = re.compile(r"^TRACE-RC-[0-9a-f]{32}$")
DEFAULT_WINDOW_SECONDS = 300
MAX_WINDOW_SECONDS = 86_400
MAX_RESULT_BYTES = 16 * 1024 * 1024
MAX_HARD_RESULT_BYTES = 64 * 1024 * 1024
DEFAULT_PAGE_SIZE = 25
MAX_PAGE_SIZE = 50
MAX_OFFSET = 1_000_000
MAX_STORED_RUNS = 10_000


class ReconstructionError(Exception):
    """Safe reconstruction failure suitable for stable API mapping."""

    def __init__(self, code: str, message: str, status_code: int) -> None:
        super().__init__(message)
        self.code, self.message, self.status_code = code, message, status_code


def is_valid_reconstruction_id(value: str) -> bool:
    return isinstance(value, str) and RECONSTRUCTION_ID_RE.fullmatch(value) is not None


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _result_limit() -> int:
    configured = os.environ.get("TRACEE_MAX_RECONSTRUCTION_RESULT_BYTES")
    if configured is None:
        return MAX_RESULT_BYTES
    if not configured.isascii() or not configured.isdecimal():
        raise ReconstructionError("reconstruction_configuration_invalid", "The configured reconstruction result limit is invalid.", 503)
    value = int(configured)
    if value < 1 or value > MAX_HARD_RESULT_BYTES:
        raise ReconstructionError("reconstruction_configuration_invalid", "The configured reconstruction result limit is outside the supported range.", 503)
    return value


def page_size_limits() -> tuple[int, int]:
    """Return configured default/max page size, capped by the hard ceiling."""
    raw_max = os.environ.get("TRACEE_MAX_RECONSTRUCTION_PAGE_SIZE")
    raw_default = os.environ.get("TRACEE_DEFAULT_RECONSTRUCTION_PAGE_SIZE")
    try:
        maximum = MAX_PAGE_SIZE if raw_max is None else int(raw_max)
        default = DEFAULT_PAGE_SIZE if raw_default is None else int(raw_default)
        if (
            (raw_max is not None and (not raw_max.isascii() or not raw_max.isdecimal()))
            or (raw_default is not None and (not raw_default.isascii() or not raw_default.isdecimal()))
            or maximum < 1 or maximum > MAX_PAGE_SIZE or default < 1 or default > maximum
        ):
            raise ValueError
    except (TypeError, ValueError):
        raise ReconstructionError("reconstruction_configuration_invalid", "The configured reconstruction page limits are invalid.", 503) from None
    return default, maximum


def _iso(value: str | None) -> datetime | None:
    if value is None:
        return None
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise ValueError("timestamp is not UTC")
    return parsed


def _observation(raw: dict[str, Any]) -> SourceObservation:
    timestamp = raw["timestamp"]
    extent = timestamp["normalized_extent"]
    return SourceObservation(
        observation_id=raw["observation_id"], evidence_id=raw["evidence_id"],
        source_type=raw["source_type"], source_locator=raw["source_locator"],
        parser_name=raw["parser_name"], parser_version=raw["parser_version"],
        schema_version=raw["schema_version"],
        timestamp=TimestampInfo(
            raw_value=timestamp["raw_value"], raw_format=timestamp["raw_format"],
            timezone_status=TimezoneStatus(timestamp["timezone_status"]),
            precision=TimestampPrecision(timestamp["precision"]),
            normalized_extent=TemporalExtent(
                _iso(extent["earliest_utc"]), _iso(extent["latest_utc"]),
            ),
        ),
        attributes=raw["attributes"], parse_status=ParseStatus(raw["parse_status"]),
        parse_errors=raw["parse_errors"],
    )


class ReconstructionService:
    """Runs versioned candidate rules on a verified persisted analysis."""

    def __init__(self, service: TraceeService) -> None:
        self.service = service
        self.analysis_service = EvidenceAnalysisService(service)
        self.directory = service.vault_dir / RECONSTRUCTION_DIRECTORY
        self.lock_path = self.directory / ".reconstruction.lock"

    @staticmethod
    def validate_window(value: Any) -> int:
        if not isinstance(value, int) or isinstance(value, bool) or value < 0 or value > MAX_WINDOW_SECONDS:
            raise ReconstructionError("invalid_request", "candidate_window_seconds must be an integer from 0 to 86400.", 422)
        return value

    def _analysis(self, evidence_id: str, analysis_id: str) -> dict[str, Any]:
        if not is_valid_analysis_id(analysis_id):
            raise AnalysisError("invalid_analysis_id", "Analysis ID has an invalid format.", 400)
        return self.analysis_service.load_analysis(evidence_id, analysis_id)

    def _verify_current_source(self, evidence_id: str) -> None:
        try:
            self.analysis_service.verify_source(evidence_id)
        except AnalysisError as exc:
            if exc.code in {"integrity_verification_failed", "stale_analysis"}:
                raise ReconstructionError("stale_reconstruction", "The reconstruction source is no longer currently verified.", 409) from None
            raise

    @staticmethod
    def _validated_inputs(analysis: dict[str, Any], evidence_id: str) -> tuple[tuple[SourceObservation, ...], tuple[dict[str, Any], ...]]:
        try:
            if analysis["evidence_id"] != evidence_id:
                raise ValueError("evidence mismatch")
            observations = tuple(_observation(item) for item in analysis["observations"])
            observation_map = {item.observation_id: item for item in observations}
            if len(observation_map) != len(observations):
                raise ValueError("duplicate observation")
            events = tuple(analysis["events"])
            event_by_observation: dict[str, dict[str, Any]] = {}
            for event in events:
                refs = event["source_observation_ids"]
                if len(refs) != 1 or refs[0] not in observation_map or refs[0] in event_by_observation:
                    raise ValueError("broken event link")
                if event["event_type"] is None or not isinstance(event["event_type"], str) or not event["event_type"].strip():
                    raise ValueError("invalid event type")
                event_by_observation[refs[0]] = event
                temporal = event["temporal_extent"]
                NormalizedEvent(
                    event_id=event["event_id"], event_type=event["event_type"],
                    source_observation_ids=tuple(refs), normalizer_name=event["normalizer_name"],
                    normalizer_version=event["normalizer_version"], attributes=event["attributes"],
                    temporal_extent=TemporalExtent(_iso(temporal["earliest_utc"]), _iso(temporal["latest_utc"])),
                    schema_version=event["schema_version"],
                )
            if set(event_by_observation) != set(observation_map):
                raise ValueError("incomplete event references")
            if any(item.evidence_id != evidence_id or item.parser_name != analysis["parser"] or item.source_type != analysis["parser"] for item in observations):
                raise ValueError("observation provenance mismatch")
            return observations, tuple(events)
        except (KeyError, TypeError, ValueError, ModelValidationError, RecursionError):
            raise ReconstructionError("analysis_invalid", "The stored analysis structure or provenance is invalid.", 500) from None

    def _ensure_directory(self) -> None:
        root = self.service.vault_dir
        if root.is_symlink() or not root.is_dir():
            raise ReconstructionError("vault_unavailable", "The configured evidence vault is unavailable.", 503)
        if self.directory.is_symlink():
            raise ReconstructionError("reconstruction_storage_unavailable", "Reconstruction storage is unavailable.", 503)
        try:
            if not self.directory.exists():
                self.directory.mkdir(mode=0o700, exist_ok=True)
                set_private_permissions(self.directory, 0o700)
            if self.directory.is_symlink() or not self.directory.is_dir():
                raise OSError("not a directory")
            if self.lock_path.is_symlink():
                raise OSError("invalid lock path")
        except OSError:
            raise ReconstructionError("reconstruction_storage_unavailable", "Reconstruction storage is unavailable.", 503) from None

    def _persist(self, result: dict[str, Any]) -> None:
        try:
            payload = dict(result)
            payload["content_sha256"] = hashlib.sha256(_canonical(result)).hexdigest()
            serialized = _canonical(payload) + b"\n"
            if len(serialized) > _result_limit():
                raise ReconstructionError("reconstruction_limit_exceeded", "The reconstruction result exceeds the supported storage limit.", 413)
            self._ensure_directory()
            evidence_dir = self.directory / result["evidence_id"]
            if evidence_dir.is_symlink():
                raise OSError("symlink")
            evidence_dir.mkdir(mode=0o700, exist_ok=True)
            if evidence_dir.is_symlink() or not evidence_dir.is_dir():
                raise OSError("invalid evidence result directory")
            set_private_permissions(evidence_dir, 0o700)
            flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(self.lock_path, flags, 0o600)
            try:
                if self.lock_path.is_symlink() or not os.path.isfile(self.lock_path):
                    raise OSError("invalid lock file")
                set_private_file_permissions(descriptor, 0o600)
                with os.fdopen(descriptor, "r+b") as lock:
                    descriptor = -1
                    with exclusive_file_lock(lock, lock_path=self.lock_path):
                        destination = evidence_dir / f"{result['reconstruction_id']}.json"
                        if destination.exists() or destination.is_symlink():
                            raise ReconstructionError("reconstruction_id_conflict", "A unique reconstruction identifier could not be reserved.", 503)
                        fd, temporary = tempfile.mkstemp(prefix=".reconstruction-", suffix=".tmp", dir=evidence_dir)
                        try:
                            set_private_file_permissions(fd, 0o600)
                            with os.fdopen(fd, "wb") as stream:
                                stream.write(serialized)
                                stream.flush()
                                os.fsync(stream.fileno())
                            # Recheck under the cross-process lock; replace is safe only after this check.
                            if destination.exists() or destination.is_symlink():
                                raise ReconstructionError("reconstruction_id_conflict", "A unique reconstruction identifier could not be reserved.", 503)
                            os.replace(temporary, destination)
                        finally:
                            if os.path.exists(temporary):
                                os.unlink(temporary)
            finally:
                if descriptor >= 0:
                    os.close(descriptor)
        except ReconstructionError:
            raise
        except OSError:
            raise ReconstructionError("reconstruction_storage_failed", "The reconstruction result could not be stored safely.", 503) from None

    def reconstruct(self, evidence_id: str, analysis_id: str, candidate_window_seconds: Any) -> dict[str, Any]:
        if not is_valid_analysis_id(analysis_id):
            raise AnalysisError("invalid_analysis_id", "Analysis ID has an invalid format.", 400)
        window = self.validate_window(candidate_window_seconds)
        analysis = self._analysis(evidence_id, analysis_id)
        observations, events = self._validated_inputs(analysis, evidence_id)
        rules = tuple(item for item in rules_for_source(analysis["parser"]))
        if not rules:
            raise ReconstructionError("unsupported_source_type", "No built-in reconstruction rule supports this parser.", 422)
        event_map = {event["source_observation_ids"][0]: event for event in events}
        projected: list[SourceObservation] = []
        for item in observations:
            attributes = dict(item.attributes)
            if EVENT_TYPE_ATTRIBUTE in attributes:
                raise ReconstructionError("analysis_invalid", "An analysis attribute collides with a reserved reconstruction field.", 500)
            attributes[EVENT_TYPE_ATTRIBUTE] = event_map[item.observation_id]["event_type"]
            projected.append(SourceObservation(
                observation_id=item.observation_id, evidence_id=item.evidence_id,
                source_type=item.source_type, source_locator=item.source_locator,
                parser_name=item.parser_name, parser_version=item.parser_version,
                timestamp=item.timestamp, attributes=attributes, parse_status=item.parse_status,
                parse_errors=item.parse_errors, schema_version=item.schema_version,
            ))
        try:
            engine_result = reconstruct(
                observations=projected,
                rules=tuple(item.rule for item in rules),
                candidate_window_seconds=window,
            )
        except (TypeError, ValueError, ModelValidationError, RecursionError):
            raise ReconstructionError("reconstruction_failed", "The stored analysis could not be reconstructed safely.", 422) from None
        # Re-read through the public validated path after processing so a source change cannot be persisted as current.
        post = self._analysis(evidence_id, analysis_id)
        if post["source_sha256"] != analysis["source_sha256"]:
            raise ReconstructionError("stale_analysis", "The source analysis changed during reconstruction.", 409)
        reconstruction_id = f"TRACE-RC-{uuid.uuid4().hex}"
        result_data = engine_result.to_dict()
        record = {
            "schema_version": RECONSTRUCTION_SCHEMA_VERSION,
            "reconstruction_id": reconstruction_id,
            "evidence_id": evidence_id,
            "source_sha256": analysis["source_sha256"],
            "analysis_id": analysis_id,
            "parser": analysis["parser"],
            "parser_version": analysis["parser_version"],
            "created_at": datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z"),
            "config": engine_result.config.to_dict(),
            "rule_versions": result_data["rule_versions"],
            "hypothesis_count": len(engine_result.hypotheses),
            "skipped_input_count": len(engine_result.skipped_inputs),
            "result_status": "candidates_generated" if engine_result.hypotheses else "no_candidates",
            "result": result_data,
        }
        self._persist(record)
        return self.summary(record)

    @staticmethod
    def summary(record: dict[str, Any]) -> dict[str, Any]:
        return {key: record[key] for key in (
            "reconstruction_id", "evidence_id", "source_sha256", "analysis_id", "parser",
            "parser_version", "created_at", "config", "rule_versions", "hypothesis_count",
            "skipped_input_count", "result_status",
        )}

    def _read(self, evidence_id: str, reconstruction_id: str) -> dict[str, Any]:
        if not is_valid_evidence_id(evidence_id):
            raise AnalysisError("invalid_evidence_id", "Evidence ID has an invalid format.", 400)
        if not is_valid_reconstruction_id(reconstruction_id):
            raise ReconstructionError("invalid_reconstruction_id", "Reconstruction ID has an invalid format.", 400)
        self._verify_current_source(evidence_id)
        directory = self.directory / evidence_id
        path = directory / f"{reconstruction_id}.json"
        try:
            if self.service.vault_dir.is_symlink() or self.directory.is_symlink() or directory.is_symlink():
                raise ReconstructionError("reconstruction_unavailable", "Reconstruction storage is unavailable.", 503)
            if path.is_symlink() or not path.is_file():
                raise FileNotFoundError
            if path.stat().st_size > MAX_HARD_RESULT_BYTES:
                raise ReconstructionError("reconstruction_invalid", "A stored reconstruction exceeds the supported size.", 500)
            with path.open("r", encoding="utf-8") as stream:
                record = json.load(stream)
        except FileNotFoundError:
            raise ReconstructionError("reconstruction_not_found", "Reconstruction record was not found.", 404) from None
        except (OSError, UnicodeError, json.JSONDecodeError, RecursionError):
            raise ReconstructionError("reconstruction_invalid", "A stored reconstruction is malformed or unreadable.", 500) from None
        fields = {
            "schema_version", "reconstruction_id", "evidence_id", "source_sha256", "analysis_id",
            "parser", "parser_version", "created_at", "config", "rule_versions", "hypothesis_count",
            "skipped_input_count", "result_status", "result", "content_sha256",
        }
        if not isinstance(record, dict) or set(record) != fields or record.get("schema_version") != RECONSTRUCTION_SCHEMA_VERSION or record.get("reconstruction_id") != reconstruction_id or record.get("evidence_id") != evidence_id:
            raise ReconstructionError("reconstruction_invalid", "A stored reconstruction has invalid provenance or structure.", 500)
        digest = record.pop("content_sha256", None)
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest) or not hashlib.sha256(_canonical(record)).hexdigest() == digest:
            raise ReconstructionError("reconstruction_invalid", "A stored reconstruction failed content validation.", 500)
        try:
            if (
                not re.fullmatch(r"[0-9a-f]{64}", record["source_sha256"])
                or not is_valid_analysis_id(record["analysis_id"])
                or record["parser"] not in {"linux_auth", "json_event"}
                or not isinstance(record["parser_version"], str)
                or not isinstance(record["created_at"], str)
                or _iso(record["created_at"]) is None
                or record["config"] != ReconstructionConfig(self.validate_window(record["config"]["candidate_window_seconds"])).to_dict()
                or record["rule_versions"] != [{"rule_id": item.rule.rule_id, "version": item.rule.version} for item in rules_for_source(record["parser"])]
                or set(record["result"]) != {"config", "rule_versions", "hypotheses", "skipped_inputs"}
                or record["result"]["config"] != record["config"]
                or record["result"]["rule_versions"] != record["rule_versions"]
                or record["result_status"] not in {"candidates_generated", "no_candidates"}
                or not isinstance(record["result"]["hypotheses"], list)
                or not isinstance(record["result"]["skipped_inputs"], list)
            ):
                raise ValueError("invalid shape")
            hypotheses = []
            for item in record["result"]["hypotheses"]:
                extent = item["temporal_extent"]
                hypotheses.append(EventHypothesis(
                    schema_version=item["schema_version"], hypothesis_id=item["hypothesis_id"],
                    event_type=item["event_type"], inference_rule_id=item["inference_rule_id"],
                    inference_rule_version=item["inference_rule_version"],
                    input_observation_ids=item["input_observation_ids"],
                    interpretation=InterpretationState(item["interpretation"]),
                    supporting_observation_ids=item["supporting_observation_ids"],
                    correlated_observation_ids=item["correlated_observation_ids"],
                    contradicting_observation_ids=item["contradicting_observation_ids"],
                    coverage_ids=item["coverage_ids"], observation_assessment_ids=item["observation_assessment_ids"],
                    contradicting_assessment_ids=item["contradicting_assessment_ids"], attributes=item["attributes"],
                    temporal_extent=TemporalExtent(_iso(extent["earliest_utc"]), _iso(extent["latest_utc"])),
                    assumptions=item["assumptions"], unresolved_conditions=item["unresolved_conditions"],
                    limitations=item["limitations"], review_status=ReviewStatus(item["review_status"]),
                ))
            skipped = [SkippedInput(**item) for item in record["result"]["skipped_inputs"]]
            rebuilt = ReconstructionResult(
                config=ReconstructionConfig(record["config"]["candidate_window_seconds"]),
                rule_versions=tuple((item["rule_id"], item["version"]) for item in record["rule_versions"]),
                hypotheses=tuple(hypotheses), skipped_inputs=tuple(skipped),
            )
            expected_status = "candidates_generated" if hypotheses else "no_candidates"
            if rebuilt.to_dict() != record["result"] or record["hypothesis_count"] != len(hypotheses) or record["skipped_input_count"] != len(skipped) or record["result_status"] != expected_status:
                raise ValueError("invalid model data")
        except (KeyError, TypeError, ValueError, ModelValidationError, RecursionError):
            raise ReconstructionError("reconstruction_invalid", "A stored reconstruction has invalid model data.", 500) from None
        try:
            analysis = self._analysis(evidence_id, record.get("analysis_id", ""))
        except AnalysisError as exc:
            if exc.code in {"integrity_verification_failed", "stale_analysis"}:
                raise ReconstructionError("stale_reconstruction", "The reconstruction source is no longer currently verified.", 409) from None
            raise
        if analysis["source_sha256"] != record.get("source_sha256") or analysis["parser"] != record.get("parser") or analysis["parser_version"] != record.get("parser_version"):
            raise ReconstructionError("stale_reconstruction", "The reconstruction no longer matches currently verified source evidence.", 409)
        return record

    def list_reconstructions(self, evidence_id: str, *, offset: int, limit: int) -> tuple[list[dict[str, Any]], int]:
        _, maximum = page_size_limits()
        if offset < 0 or offset > MAX_OFFSET or limit < 1 or limit > maximum:
            raise ReconstructionError("invalid_pagination", "Pagination values are outside the supported range.", 422)
        self._verify_current_source(evidence_id)
        # Validate source evidence even when no reconstruction directory exists.
        directory = self.directory / evidence_id
        if directory.is_symlink():
            raise ReconstructionError("reconstruction_unavailable", "Reconstruction storage is unavailable.", 503)
        if not directory.exists():
            return [], 0
        try:
            paths = sorted(directory.iterdir())
        except OSError:
            raise ReconstructionError("reconstruction_unavailable", "Reconstruction records could not be listed.", 503) from None
        if len(paths) > MAX_STORED_RUNS:
            raise ReconstructionError("reconstruction_limit_exceeded", "The evidence has more stored reconstruction runs than the supported listing limit.", 413)
        if any(
            path.is_symlink() or not path.is_file() or not is_valid_reconstruction_id(path.stem) or path.suffix != ".json"
            for path in paths
        ):
            raise ReconstructionError("reconstruction_invalid", "A stored reconstruction entry has an invalid name or type.", 500)
        records = [self._read(evidence_id, path.stem) for path in paths]
        records.sort(key=lambda item: item["created_at"], reverse=True)
        return [self.summary(item) for item in records[offset:offset + limit]], len(records)

    def get_reconstruction(self, evidence_id: str, reconstruction_id: str, *, hypothesis_offset: int, hypothesis_limit: int, skipped_offset: int, skipped_limit: int) -> dict[str, Any]:
        _, maximum = page_size_limits()
        for offset, limit in ((hypothesis_offset, hypothesis_limit), (skipped_offset, skipped_limit)):
            if offset < 0 or offset > MAX_OFFSET or limit < 1 or limit > maximum:
                raise ReconstructionError("invalid_pagination", "Pagination values are outside the supported range.", 422)
        record = self._read(evidence_id, reconstruction_id)
        hypotheses = record["result"]["hypotheses"]
        skipped = record["result"]["skipped_inputs"]
        return {
            **self.summary(record),
            "rule_versions": record["rule_versions"],
            "hypotheses": hypotheses[hypothesis_offset:hypothesis_offset + hypothesis_limit],
            "skipped_inputs": skipped[skipped_offset:skipped_offset + skipped_limit],
            "pagination": {
                "hypotheses": {"offset": hypothesis_offset, "limit": hypothesis_limit, "total": len(hypotheses)},
                "skipped_inputs": {"offset": skipped_offset, "limit": skipped_limit, "total": len(skipped)},
            },
        }
