"""Verified, provenance-preserving parsing of evidence already in a vault.

This service adapts the existing ``src.parsers`` line parsers to TRACEE's
immutable observation and normalized-event models. It never changes source
evidence, metadata, or the evidence chain.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from parsers.registry import get_parsers

from .errors import VaultError
from .events import (
    NormalizedEvent,
    ParseStatus,
    SourceObservation,
    TemporalExtent,
    TimestampInfo,
    TimestampPrecision,
    TimezoneStatus,
)
from .ids import is_valid_evidence_id
from .locking import (
    exclusive_file_lock,
    set_private_file_permissions,
    set_private_permissions,
)
from .models import EvidenceMetadata, ModelValidationError
from .services import TraceeService

ANALYSIS_SCHEMA_VERSION = "1.0"
ANALYSIS_DIRECTORY = "analyses"
MAX_ANALYSIS_INPUT_BYTES = 64 * 1024 * 1024
HARD_MAX_ANALYSIS_INPUT_BYTES = 256 * 1024 * 1024
MAX_RECORD_BYTES = 16 * 1024
MAX_EVENT_COUNT = 20_000
MAX_RESULT_BYTES = 16 * 1024 * 1024
HARD_MAX_RESULT_BYTES = 64 * 1024 * 1024
MAX_DIAGNOSTICS = 100
DEFAULT_EVENT_PAGE_SIZE = 25
MAX_EVENT_PAGE_SIZE = 50
ANALYSIS_ID_PATTERN = re.compile(r"^TRACE-AN-[0-9a-f]{32}$")
PARSER_ADAPTER_VERSION = "1.0"
PARSER_BY_NAME = {parser.name: parser for parser in get_parsers()}
SUPPORTED_PARSER_IDS = tuple(PARSER_BY_NAME)


class AnalysisError(Exception):
    """A safe, client-displayable analysis failure."""

    def __init__(
        self,
        code: str,
        message: str,
        status_code: int,
        *,
        verification_state: str | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code
        self.verification_state = verification_state


def is_valid_analysis_id(value: str) -> bool:
    return isinstance(value, str) and ANALYSIS_ID_PATTERN.fullmatch(value) is not None


def _now_utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _analysis_id() -> str:
    return f"TRACE-AN-{uuid.uuid4().hex}"


def _configured_limit(name: str, default: int, hard_maximum: int) -> int:
    configured = os.environ.get(name)
    if configured is None:
        return default
    if not configured.isascii() or not configured.isdecimal():
        raise AnalysisError("analysis_configuration_invalid", f"{name} must be a positive integer.", 503)
    value = int(configured)
    if value < 1 or value > hard_maximum:
        raise AnalysisError("analysis_configuration_invalid", f"{name} is outside the supported range.", 503)
    return value


def _input_limit() -> int:
    return _configured_limit(
        "TRACEE_MAX_ANALYSIS_BYTES", MAX_ANALYSIS_INPUT_BYTES,
        HARD_MAX_ANALYSIS_INPUT_BYTES,
    )


def _result_limit() -> int:
    return _configured_limit(
        "TRACEE_MAX_ANALYSIS_RESULT_BYTES", MAX_RESULT_BYTES,
        HARD_MAX_RESULT_BYTES,
    )


def _diagnostic(diagnostics: dict[str, Any], code: str, line: int) -> None:
    diagnostics["malformed_lines"] += 1
    if len(diagnostics["issues"]) < MAX_DIAGNOSTICS:
        diagnostics["issues"].append({"line_number": line, "code": code})


def _timestamp(raw: Any, parser_name: str) -> tuple[TimestampInfo, TemporalExtent, str | None]:
    if raw is None:
        return TimestampInfo(), TemporalExtent(), "missing_timestamp"
    if not isinstance(raw, str) or not raw.strip():
        return TimestampInfo(), TemporalExtent(), "invalid_timestamp"

    uses_iso8601 = parser_name in {"json_event", "systemd_journal", "windows_event"}
    raw_format = "iso8601" if uses_iso8601 else "%Y-%m-%d %H:%M:%S"
    precision = TimestampPrecision.SECOND
    if uses_iso8601:
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}", raw):
            precision = TimestampPrecision.DAY
        elif re.search(r"[T ]\d{2}$", raw):
            precision = TimestampPrecision.HOUR
        elif re.search(r"[T ]\d{2}:\d{2}(?:Z|[+-]\d{2}:?\d{2})?$", raw):
            precision = TimestampPrecision.MINUTE
        fractional = re.search(r"\.(\d+)", raw)
        if fractional:
            precision = (
                TimestampPrecision.MILLISECOND
                if len(fractional.group(1)) <= 3
                else TimestampPrecision.MICROSECOND
            )
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00")) if uses_iso8601 else datetime.strptime(raw, raw_format)
    except ValueError:
        return (
            TimestampInfo(
                raw_value=raw,
                raw_format=raw_format,
                timezone_status=TimezoneStatus.UNKNOWN,
                precision=precision,
            ),
            TemporalExtent(),
            "invalid_timestamp",
        )

    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return (
            TimestampInfo(
                raw_value=raw,
                raw_format=raw_format,
                timezone_status=TimezoneStatus.UNKNOWN,
                precision=precision,
            ),
            TemporalExtent(),
            None,
        )

    utc = parsed.astimezone(timezone.utc)
    extent = TemporalExtent(utc, utc)
    return (
        TimestampInfo(
            raw_value=raw,
            raw_format=raw_format,
            timezone_status=TimezoneStatus.KNOWN,
            precision=precision,
            normalized_extent=extent,
        ),
        extent,
        None,
    )


def _read_json(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise AnalysisError("analysis_unavailable", "A stored analysis is unavailable.", 500)
    try:
        if path.stat().st_size > HARD_MAX_RESULT_BYTES:
            raise AnalysisError("analysis_invalid", "A stored analysis exceeds the supported size.", 500)
        with path.open("r", encoding="utf-8") as handle:
            value = json.load(handle)
    except AnalysisError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError):
        raise AnalysisError("analysis_invalid", "A stored analysis is malformed or unreadable.", 500) from None
    if not isinstance(value, dict):
        raise AnalysisError("analysis_invalid", "A stored analysis has an invalid structure.", 500)
    return value


class EvidenceAnalysisService:
    """Analyze verified evidence using a named legacy parser."""

    def __init__(self, service: TraceeService) -> None:
        self.service = service
        self.directory = service.vault_dir / ANALYSIS_DIRECTORY
        self.lock_path = self.directory / ".analysis.lock"

    def _metadata_and_hash(self, evidence_id: str) -> tuple[EvidenceMetadata, str]:
        if not is_valid_evidence_id(evidence_id):
            raise AnalysisError("invalid_evidence_id", "Evidence ID has an invalid format.", 400)
        vault = self.service.vault
        record_path = vault.record_path(evidence_id)
        evidence_path = vault.evidence_path(evidence_id)
        chain_path = vault.chain_path
        if (
            vault.root.is_symlink()
            or any(path.is_symlink() or not path.is_dir() for path in (
                vault.objects_dir, vault.records_dir, vault.chain_dir,
            ))
            or chain_path.is_symlink()
            or (chain_path.exists() and not chain_path.is_file())
            or record_path.is_symlink()
            or (record_path.exists() and not record_path.is_file())
            or evidence_path.is_symlink()
            or (evidence_path.exists() and not evidence_path.is_file())
        ):
            raise AnalysisError("vault_unavailable", "The configured evidence vault is unavailable.", 503)
        if not record_path.exists():
            raise AnalysisError("evidence_not_found", "Evidence metadata record was not found.", 404)
        try:
            raw = self.service.get_metadata(evidence_id)
            metadata = EvidenceMetadata(**raw)
        except VaultError:
            if not self.service.vault.record_path(evidence_id).is_file():
                raise AnalysisError("evidence_not_found", "Evidence metadata record was not found.", 404) from None
            raise AnalysisError("unreadable_metadata", "Evidence metadata could not be read safely.", 500) from None
        except (TypeError, ValueError, ModelValidationError):
            raise AnalysisError("malformed_metadata", "Evidence metadata is malformed.", 500) from None
        if metadata.evidence_id != evidence_id:
            raise AnalysisError("malformed_metadata", "Evidence metadata does not match the requested ID.", 500)

        verification = self.service.verify(evidence_id)
        state = verification.state.value
        if state != "VALID":
            messages = {
                "TAMPERED": "Evidence integrity verification detected a mismatch.",
                "MISSING": "A required evidence or vault file is missing.",
                "INVALID": "Evidence metadata or integrity data is invalid.",
            }
            raise AnalysisError(
                "integrity_verification_failed",
                messages.get(state, "Evidence integrity verification did not pass."),
                409,
                verification_state=state,
            )
        return metadata, metadata.sha256

    def _ensure_analysis_directory(self, *, create: bool) -> None:
        root = self.service.vault_dir
        if root.is_symlink() or not root.is_dir():
            raise AnalysisError("vault_unavailable", "The configured vault is unavailable.", 503)
        if self.directory.is_symlink():
            raise AnalysisError("analysis_unavailable", "Derived analysis storage is unavailable.", 503)
        if not self.directory.exists():
            if not create:
                return
            try:
                self.directory.mkdir(mode=0o700)
                set_private_permissions(self.directory, 0o700)
            except FileExistsError:
                pass
            except OSError:
                raise AnalysisError("analysis_storage_failed", "Derived analysis storage could not be prepared.", 503) from None
            if self.directory.is_symlink() or not self.directory.is_dir():
                raise AnalysisError("analysis_storage_failed", "Derived analysis storage could not be prepared.", 503)
        if not self.directory.is_dir():
            raise AnalysisError("analysis_unavailable", "Derived analysis storage is unavailable.", 503)
        if create:
            try:
                set_private_permissions(self.directory, 0o700)
            except OSError:
                raise AnalysisError("analysis_unavailable", "Derived analysis storage permissions could not be secured.", 503) from None

    def _evidence_analysis_directory(self, evidence_id: str, *, create: bool) -> Path:
        if not is_valid_evidence_id(evidence_id):
            raise AnalysisError("invalid_evidence_id", "Evidence ID has an invalid format.", 400)
        self._ensure_analysis_directory(create=create)
        target = self.directory / evidence_id
        if target.is_symlink():
            raise AnalysisError("analysis_unavailable", "Derived analysis storage is unavailable.", 503)
        if not target.exists():
            if not create:
                return target
            try:
                target.mkdir(mode=0o700)
                set_private_permissions(target, 0o700)
            except FileExistsError:
                pass
            except OSError:
                raise AnalysisError("analysis_storage_failed", "Derived analysis storage could not be prepared.", 503) from None
        if target.is_symlink() or not target.is_dir():
            raise AnalysisError("analysis_unavailable", "Derived analysis storage is unavailable.", 503)
        return target

    def _lock(self, *, create: bool):
        self._ensure_analysis_directory(create=create)
        if not self.directory.exists():
            return None
        if self.lock_path.is_symlink():
            raise AnalysisError("analysis_unavailable", "Derived analysis locking is unavailable.", 503)
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
        try:
            descriptor = os.open(self.lock_path, flags, 0o600)
            if self.lock_path.is_symlink() or not stat.S_ISREG(os.fstat(descriptor).st_mode):
                os.close(descriptor)
                raise OSError("invalid analysis lock")
            set_private_file_permissions(descriptor, 0o600)
            return os.fdopen(descriptor, "r+b")
        except OSError:
            raise AnalysisError("analysis_unavailable", "Derived analysis locking is unavailable.", 503) from None

    def _source_parser(self, parser_name: str, source_path: Path):
        parser = PARSER_BY_NAME.get(parser_name)
        if parser is None:
            raise AnalysisError(
                "unsupported_parser",
                f"Select one of the supported parsers: {', '.join(SUPPORTED_PARSER_IDS)}.",
                422,
            )
        # Inspect a bounded sample only to catch a clearly mismatched choice.
        # An entirely malformed file still produces line diagnostics under the
        # explicitly selected parser rather than being assigned a guessed type.
        samples: list[str] = []
        other_matches: list[str] = []
        try:
            with source_path.open("rb") as stream:
                for _ in range(20):
                    raw = stream.readline(MAX_RECORD_BYTES + 2)
                    if not raw:
                        break
                    if len(raw.rstrip(b"\r\n")) <= MAX_RECORD_BYTES:
                        try:
                            line = raw.decode("utf-8").rstrip("\r\n")
                        except UnicodeDecodeError:
                            continue
                        if line.strip():
                            samples.append(line)
        except OSError:
            raise AnalysisError("evidence_unavailable", "The verified evidence object could not be read.", 503) from None
        for candidate in PARSER_BY_NAME.values():
            try:
                if candidate.name != parser_name and candidate.can_parse(source_path, samples):
                    other_matches.append(candidate.name)
            except Exception:
                continue
        if other_matches:
            raise AnalysisError(
                "parser_mismatch",
                "The selected parser does not match the evidence format. Choose the matching supported parser.",
                422,
            )
        return parser

    def analyze(self, evidence_id: str, parser_name: str) -> dict[str, Any]:
        if not isinstance(parser_name, str) or not parser_name.strip():
            raise AnalysisError("invalid_request", "A parser identifier is required.", 422)
        metadata, source_sha256 = self._metadata_and_hash(evidence_id)
        source_path = self.service.vault.evidence_path(evidence_id)
        if source_path.is_symlink() or not source_path.is_file():
            raise AnalysisError("evidence_unavailable", "The verified evidence object could not be read.", 503)
        input_limit = _input_limit()
        result_limit = _result_limit()
        if metadata.size_bytes > input_limit:
            raise AnalysisError("analysis_limit_exceeded", "Evidence exceeds the configured analysis input limit.", 413)
        parser = self._source_parser(parser_name, source_path)
        analysis_id = _analysis_id()
        diagnostics: dict[str, Any] = {
            "lines_total": 0,
            "parsed_records": 0,
            "partial_records": 0,
            "blank_lines": 0,
            "malformed_lines": 0,
            "issues": [],
        }
        events: list[dict[str, Any]] = []
        observations: list[dict[str, Any]] = []
        serialized_event_bytes = 0
        source_digest = hashlib.sha256()
        source_bytes_read = 0

        try:
            with source_path.open("rb") as stream:
                line_number = 0
                while True:
                    raw_bytes = stream.readline(MAX_RECORD_BYTES + 2)
                    if not raw_bytes:
                        break
                    line_number += 1
                    source_digest.update(raw_bytes)
                    source_bytes_read += len(raw_bytes)
                    if source_bytes_read > input_limit:
                        raise AnalysisError("analysis_limit_exceeded", "Evidence exceeds the configured analysis input limit.", 413)
                    oversized = len(raw_bytes) > MAX_RECORD_BYTES and not raw_bytes.endswith(b"\n")
                    while oversized:
                        remainder = stream.readline(MAX_RECORD_BYTES + 2)
                        if not remainder:
                            break
                        source_digest.update(remainder)
                        source_bytes_read += len(remainder)
                        if source_bytes_read > input_limit:
                            raise AnalysisError("analysis_limit_exceeded", "Evidence exceeds the configured analysis input limit.", 413)
                        oversized = not remainder.endswith(b"\n")
                    diagnostics["lines_total"] += 1
                    content = raw_bytes.rstrip(b"\r\n")
                    if len(content) > MAX_RECORD_BYTES or (
                        not raw_bytes.endswith(b"\n")
                        and len(raw_bytes) > MAX_RECORD_BYTES
                    ):
                        _diagnostic(diagnostics, "record_too_large", line_number)
                        continue
                    if not content.strip():
                        diagnostics["blank_lines"] += 1
                        continue
                    try:
                        raw_line = content.decode("utf-8")
                    except UnicodeDecodeError:
                        _diagnostic(diagnostics, "invalid_utf8", line_number)
                        continue
                    try:
                        parsed = parser.parse_line(raw_line)
                    except Exception:
                        _diagnostic(diagnostics, "parser_error", line_number)
                        continue
                    if not parsed:
                        _diagnostic(diagnostics, "unsupported_record", line_number)
                        continue
                    if not isinstance(parsed, dict) or not isinstance(parsed.get("event_type"), str) or not parsed["event_type"].strip() or not isinstance(parsed.get("attributes"), dict):
                        _diagnostic(diagnostics, "invalid_parser_output", line_number)
                        continue
                    if len(events) >= MAX_EVENT_COUNT:
                        raise AnalysisError("analysis_limit_exceeded", "Evidence contains more supported records than the analysis limit.", 413)

                    timestamp, extent, timestamp_issue = _timestamp(parsed.get("timestamp"), parser_name)
                    observation_id = f"{analysis_id}:obs:{line_number}"
                    event_id = f"{analysis_id}:event:{line_number}"
                    parse_status = ParseStatus.PARTIAL if timestamp_issue else ParseStatus.PARSED
                    parse_errors = (timestamp_issue,) if timestamp_issue else ()
                    try:
                        observation = SourceObservation(
                            observation_id=observation_id,
                            evidence_id=evidence_id,
                            source_type=parser_name,
                            source_locator=f"line:{line_number}",
                            parser_name=parser_name,
                            parser_version=PARSER_ADAPTER_VERSION,
                            timestamp=timestamp,
                            attributes=parsed["attributes"],
                            parse_status=parse_status,
                            parse_errors=parse_errors,
                        )
                        event = NormalizedEvent(
                            event_id=event_id,
                            event_type=parsed["event_type"],
                            source_observation_ids=(observation_id,),
                            normalizer_name="legacy_parser_adapter",
                            normalizer_version=PARSER_ADAPTER_VERSION,
                            attributes=parsed["attributes"],
                            temporal_extent=extent,
                        )
                    except (TypeError, ValueError, ModelValidationError, RecursionError):
                        _diagnostic(diagnostics, "invalid_parser_output", line_number)
                        continue
                    try:
                        observation_data = observation.to_dict()
                        event_data = event.to_dict()
                        event_size = len(json.dumps(event_data, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
                        observation_size = len(json.dumps(observation_data, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
                    except (TypeError, ValueError, RecursionError):
                        _diagnostic(diagnostics, "invalid_parser_output", line_number)
                        continue
                    serialized_event_bytes += event_size + observation_size
                    if serialized_event_bytes > result_limit:
                        raise AnalysisError("analysis_limit_exceeded", "Derived analysis exceeds the configured result limit.", 413)
                    events.append(event_data)
                    observations.append(observation_data)
                    diagnostics["parsed_records"] += 1
                    if timestamp_issue:
                        diagnostics["partial_records"] += 1
                        if len(diagnostics["issues"]) < MAX_DIAGNOSTICS:
                            diagnostics["issues"].append(
                                {"line_number": line_number, "code": timestamp_issue}
                            )
        except AnalysisError:
            raise
        except OSError:
            raise AnalysisError("evidence_unavailable", "The verified evidence object could not be read.", 503) from None
        except (TypeError, ValueError, ModelValidationError):
            raise AnalysisError("invalid_record", "A parsed record could not be normalized safely.", 422) from None

        if source_digest.hexdigest() != source_sha256:
            raise AnalysisError("source_changed", "Evidence changed while analysis was running.", 409)
        post_metadata, post_sha256 = self._metadata_and_hash(evidence_id)
        if post_sha256 != source_sha256 or post_metadata.size_bytes != metadata.size_bytes:
            raise AnalysisError("source_changed", "Evidence changed while analysis was running.", 409)

        result: dict[str, Any] = {
            "schema_version": ANALYSIS_SCHEMA_VERSION,
            "analysis_id": analysis_id,
            "evidence_id": evidence_id,
            "source_sha256": source_sha256,
            "parser": parser_name,
            "parser_version": PARSER_ADAPTER_VERSION,
            "created_at": _now_utc(),
            "event_count": len(events),
            "diagnostics": diagnostics,
            "events": events,
            "observations": observations,
        }
        self._persist(result)
        return self.summary(result)

    @staticmethod
    def summary(result: dict[str, Any]) -> dict[str, Any]:
        return {
            key: result[key]
            for key in (
                "analysis_id", "evidence_id", "source_sha256", "parser",
                "parser_version", "created_at", "event_count", "diagnostics",
            )
        }

    def _persist(self, result: dict[str, Any]) -> None:
        result_directory = self._evidence_analysis_directory(result["evidence_id"], create=True)
        serialized = json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
        if len(serialized) > _result_limit():
            raise AnalysisError("analysis_limit_exceeded", "Derived analysis exceeds the configured result limit.", 413)
        lock_file = self._lock(create=True)
        assert lock_file is not None
        temporary: str | None = None
        reserved_path: Path | None = None
        try:
            with lock_file:
                with exclusive_file_lock(lock_file, lock_path=self.lock_path):
                    destination = result_directory / f"{result['analysis_id']}.json"
                    if destination.exists() or destination.is_symlink():
                        raise AnalysisError("analysis_id_conflict", "A unique analysis identifier could not be reserved.", 503)
                    descriptor, temporary = tempfile.mkstemp(prefix=".analysis-", suffix=".tmp", dir=result_directory)
                    try:
                        set_private_file_permissions(descriptor, 0o600)
                        with os.fdopen(descriptor, "wb") as stream:
                            stream.write(serialized)
                            stream.flush()
                            os.fsync(stream.fileno())
                        # Reserve the destination without replacing any
                        # existing path, then atomically promote the complete
                        # temporary record over our own empty reservation.
                        reserve_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
                        reserve_descriptor = os.open(destination, reserve_flags, 0o600)
                        reserved_path = destination
                        set_private_file_permissions(reserve_descriptor, 0o600)
                        os.close(reserve_descriptor)
                        os.replace(temporary, destination)
                        temporary = None
                        reserved_path = None
                    except OSError:
                        raise AnalysisError("analysis_storage_failed", "The derived analysis could not be persisted safely.", 503) from None
        finally:
            if reserved_path is not None:
                try:
                    reserved_path.unlink()
                except OSError:
                    pass
            if temporary:
                try:
                    os.unlink(temporary)
                except OSError:
                    pass

    def _load_bound(self, evidence_id: str, analysis_id: str) -> dict[str, Any]:
        if not is_valid_analysis_id(analysis_id):
            raise AnalysisError("invalid_analysis_id", "Analysis ID has an invalid format.", 400)
        metadata, current_hash = self._metadata_and_hash(evidence_id)
        del metadata
        result_directory = self._evidence_analysis_directory(evidence_id, create=False)
        if not result_directory.exists():
            raise AnalysisError("analysis_not_found", "Analysis record was not found.", 404)
        path = result_directory / f"{analysis_id}.json"
        if path.is_symlink() or not path.is_file():
            raise AnalysisError("analysis_not_found", "Analysis record was not found.", 404)
        result = _read_json(path)
        self._validate_result(result, evidence_id, analysis_id)
        if result["source_sha256"] != current_hash:
            raise AnalysisError("stale_analysis", "Stored analysis does not match the currently verified evidence.", 409)
        return result

    def load_analysis(self, evidence_id: str, analysis_id: str) -> dict[str, Any]:
        """Load a complete validated analysis bound to currently verified evidence.

        This public service boundary is intended for trusted derived-analysis
        services. It performs the same identifier, schema, provenance, digest
        binding, and evidence-integrity validation as the API read methods.
        The returned mapping is a fresh JSON-decoded value; callers must not
        persist modifications back to the source analysis.
        """
        return self._load_bound(evidence_id, analysis_id)

    def verify_source(self, evidence_id: str) -> tuple[EvidenceMetadata, str]:
        """Validate the identifier, metadata binding, and current evidence integrity."""
        return self._metadata_and_hash(evidence_id)

    def list_analyses(
        self, evidence_id: str, *, offset: int = 0, limit: int = 25
    ) -> tuple[list[dict[str, Any]], int]:
        if offset < 0 or offset > 1_000_000 or limit < 1 or limit > 100:
            raise AnalysisError("invalid_pagination", "Pagination values are outside the supported range.", 422)
        _, source_hash = self._metadata_and_hash(evidence_id)
        result_directory = self._evidence_analysis_directory(evidence_id, create=False)
        if not result_directory.exists():
            return [], 0
        summaries: list[dict[str, Any]] = []
        try:
            paths = sorted(result_directory.glob("*.json"))
        except OSError:
            raise AnalysisError("analysis_unavailable", "Derived analysis records could not be enumerated.", 503) from None
        for path in paths:
            if path.is_symlink() or not path.is_file() or not is_valid_analysis_id(path.stem):
                raise AnalysisError("analysis_invalid", "A stored analysis record has an invalid name or type.", 500)
            result = _read_json(path)
            self._validate_result(result, evidence_id, path.stem)
            if result["source_sha256"] != source_hash:
                raise AnalysisError("stale_analysis", "Stored analysis does not match the currently verified evidence.", 409)
            summaries.append(self.summary(result))
        ordered = sorted(summaries, key=lambda item: item["created_at"], reverse=True)
        return ordered[offset:offset + limit], len(ordered)

    def get_analysis(self, evidence_id: str, analysis_id: str, *, offset: int, limit: int) -> dict[str, Any]:
        if offset < 0 or limit < 1 or limit > MAX_EVENT_PAGE_SIZE:
            raise AnalysisError("invalid_pagination", "Pagination values are outside the supported range.", 422)
        result = self._load_bound(evidence_id, analysis_id)
        events = result["events"][offset:offset + limit]
        observation_ids = {identifier for event in events for identifier in event["source_observation_ids"]}
        observations = [item for item in result["observations"] if item["observation_id"] in observation_ids]
        return {
            **self.summary(result),
            "events": events,
            "observations": observations,
            "pagination": {
                "offset": offset,
                "limit": limit,
                "total_events": result["event_count"],
            },
        }

    @staticmethod
    def _validate_result(result: dict[str, Any], evidence_id: Any, analysis_id: str) -> None:
        required = {
            "schema_version", "analysis_id", "evidence_id", "source_sha256", "parser",
            "parser_version", "created_at", "event_count", "diagnostics", "events", "observations",
        }
        if (
            set(result) != required
            or result.get("schema_version") != ANALYSIS_SCHEMA_VERSION
            or result.get("analysis_id") != analysis_id
            or not is_valid_analysis_id(analysis_id)
            or not is_valid_evidence_id(evidence_id)
            or result.get("evidence_id") != evidence_id
            or not isinstance(result.get("parser"), str)
            or result.get("parser") not in PARSER_BY_NAME
            or result.get("parser_version") != PARSER_ADAPTER_VERSION
            or not isinstance(result.get("source_sha256"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", result["source_sha256"])
            or not isinstance(result.get("created_at"), str)
            or not isinstance(result.get("event_count"), int)
            or isinstance(result.get("event_count"), bool)
            or not isinstance(result.get("events"), list)
            or result["event_count"] != len(result["events"])
            or not isinstance(result.get("observations"), list)
            or len(result["observations"]) != result["event_count"]
            or not isinstance(result.get("diagnostics"), dict)
        ):
            raise AnalysisError("analysis_invalid", "A stored analysis record has invalid provenance or structure.", 500)
        try:
            created_at = datetime.fromisoformat(result["created_at"].replace("Z", "+00:00"))
            if created_at.utcoffset() != timezone.utc.utcoffset(created_at):
                raise ValueError("non-UTC timestamp")
            diagnostic_fields = {
                "lines_total", "parsed_records", "partial_records", "blank_lines",
                "malformed_lines", "issues",
            }
            diagnostics = result["diagnostics"]
            if set(diagnostics) != diagnostic_fields:
                raise ValueError("invalid diagnostic shape")
            for name in diagnostic_fields - {"issues"}:
                if not isinstance(diagnostics[name], int) or isinstance(diagnostics[name], bool) or diagnostics[name] < 0:
                    raise ValueError("invalid diagnostic count")
            if not isinstance(diagnostics["issues"], list) or len(diagnostics["issues"]) > MAX_DIAGNOSTICS:
                raise ValueError("invalid diagnostic issue list")
            issue_codes = {
                "record_too_large", "invalid_utf8", "parser_error", "unsupported_record",
                "invalid_parser_output", "invalid_timestamp", "missing_timestamp",
            }
            for issue in diagnostics["issues"]:
                if (
                    not isinstance(issue, dict)
                    or set(issue) != {"line_number", "code"}
                    or not isinstance(issue["line_number"], int)
                    or isinstance(issue["line_number"], bool)
                    or issue["line_number"] < 1
                    or issue["line_number"] > diagnostics["lines_total"]
                    or issue["code"] not in issue_codes
                ):
                    raise ValueError("invalid diagnostic issue")
        except (AttributeError, KeyError, TypeError, ValueError, RecursionError):
            raise AnalysisError("analysis_invalid", "A stored analysis record has invalid diagnostics or timestamp data.", 500) from None
        observation_fields = {
            "schema_version", "observation_id", "evidence_id", "source_type",
            "source_locator", "parser_name", "parser_version", "timestamp",
            "attributes", "parse_status", "parse_errors",
        }
        observation_map: dict[str, dict[str, Any]] = {}
        for item in result["observations"]:
            if not isinstance(item, dict) or not isinstance(item.get("observation_id"), str):
                raise AnalysisError("analysis_invalid", "A stored analysis record has invalid provenance or structure.", 500)
            observation_map[item["observation_id"]] = item
        if len(observation_map) != len(result["observations"]):
            raise AnalysisError("analysis_invalid", "A stored analysis record has invalid provenance or structure.", 500)
        try:
            for observation in result["observations"]:
                if set(observation) != observation_fields:
                    raise ValueError("invalid observation shape")
                if (
                    observation["evidence_id"] != evidence_id
                    or observation["parser_name"] != result["parser"]
                    or observation["parser_version"] != PARSER_ADAPTER_VERSION
                    or observation["source_type"] != result["parser"]
                    or not re.fullmatch(r"line:[1-9][0-9]*", observation["source_locator"])
                    or observation["observation_id"] != f"{analysis_id}:obs:{observation['source_locator'][5:]}"
                ):
                    raise ValueError("observation provenance mismatch")
                timestamp_data = observation["timestamp"]
                extent_data = timestamp_data["normalized_extent"]
                earliest = datetime.fromisoformat(extent_data["earliest_utc"].replace("Z", "+00:00")) if extent_data["earliest_utc"] else None
                latest = datetime.fromisoformat(extent_data["latest_utc"].replace("Z", "+00:00")) if extent_data["latest_utc"] else None
                timestamp = TimestampInfo(
                    raw_value=timestamp_data["raw_value"],
                    raw_format=timestamp_data["raw_format"],
                    timezone_status=TimezoneStatus(timestamp_data["timezone_status"]),
                    precision=TimestampPrecision(timestamp_data["precision"]),
                    normalized_extent=TemporalExtent(earliest, latest),
                )
                SourceObservation(
                    observation_id=observation["observation_id"],
                    evidence_id=observation["evidence_id"],
                    source_type=observation["source_type"],
                    source_locator=observation["source_locator"],
                    parser_name=observation["parser_name"],
                    parser_version=observation["parser_version"],
                    timestamp=timestamp,
                    attributes=observation["attributes"],
                    parse_status=ParseStatus(observation["parse_status"]),
                    parse_errors=observation["parse_errors"],
                    schema_version=observation["schema_version"],
                )
        except (AttributeError, KeyError, TypeError, ValueError, ModelValidationError, RecursionError):
            raise AnalysisError("analysis_invalid", "A stored analysis record has invalid observation data.", 500) from None
        event_fields = {
            "schema_version", "event_id", "event_type", "source_observation_ids",
            "normalizer_name", "normalizer_version", "attributes", "temporal_extent",
        }
        for event in result["events"]:
            if not isinstance(event, dict) or set(event) != event_fields or event.get("schema_version") != "1.0":
                raise AnalysisError("analysis_invalid", "A stored analysis record has invalid event data.", 500)
            source_ids = event.get("source_observation_ids")
            if not isinstance(source_ids, list) or not source_ids or any(
                not isinstance(identifier, str) or identifier not in observation_map
                for identifier in source_ids
            ):
                raise AnalysisError("analysis_invalid", "A stored analysis record has broken event provenance.", 500)
            if any(observation_map[identifier].get("evidence_id") != evidence_id for identifier in source_ids):
                raise AnalysisError("analysis_invalid", "A stored analysis record has broken evidence provenance.", 500)
            try:
                extent_data = event["temporal_extent"]
                event_line = observation_map[source_ids[0]]["source_locator"][5:]
                if event["event_id"] != f"{analysis_id}:event:{event_line}" or len(source_ids) != 1:
                    raise ValueError("event provenance mismatch")
                NormalizedEvent(
                    event_id=event["event_id"],
                    event_type=event["event_type"],
                    source_observation_ids=source_ids,
                    normalizer_name=event["normalizer_name"],
                    normalizer_version=event["normalizer_version"],
                    attributes=event["attributes"],
                    temporal_extent=TemporalExtent(
                        datetime.fromisoformat(extent_data["earliest_utc"].replace("Z", "+00:00")) if extent_data["earliest_utc"] else None,
                        datetime.fromisoformat(extent_data["latest_utc"].replace("Z", "+00:00")) if extent_data["latest_utc"] else None,
                    ),
                )
            except (AttributeError, KeyError, TypeError, ValueError, ModelValidationError, RecursionError):
                raise AnalysisError("analysis_invalid", "A stored analysis record has invalid event data.", 500) from None
