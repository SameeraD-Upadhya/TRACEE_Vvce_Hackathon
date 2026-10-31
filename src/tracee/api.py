"""Local TRACEE HTTP API for evidence metadata, acquisition, and activity."""

from __future__ import annotations

import hmac
import json
import logging
import os
import re
import tempfile
import unicodedata
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import FastAPI, Query, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.datastructures import UploadFile as StarletteUploadFile

from .activity import ActivityLog, ActivityLogError, ActivityLogIntegrityError
from .analysis import (
    AnalysisError,
    DEFAULT_EVENT_PAGE_SIZE,
    EvidenceAnalysisService,
    MAX_EVENT_PAGE_SIZE,
    SUPPORTED_PARSER_IDS,
    is_valid_analysis_id,
)
from .errors import (
    ChainError,
    DuplicateEvidenceError,
    IngestionError,
    InvalidInputError,
    MetadataError,
    VaultError,
)
from .ids import is_valid_evidence_id
from .locking import set_private_permissions
from .models import EvidenceMetadata
from .services import TraceeService
from .reconstruction_rules import BUILTIN_RULES, public_rule
from .reconstruction_service import (
    MAX_PAGE_SIZE as RECONSTRUCTION_PAGE_MAX,
    MAX_WINDOW_SECONDS,
    ReconstructionError,
    ReconstructionService,
    page_size_limits,
)
from .vault import FilesystemVaultStore
from .verify import VerificationResult

logger = logging.getLogger(__name__)
DEFAULT_MAX_UPLOAD_BYTES = 100 * 1024 * 1024
UPLOAD_CHUNK_BYTES = 64 * 1024
MAX_MULTIPART_OVERHEAD_BYTES = 1024 * 1024
ACTIVITY_LIMIT_DEFAULT = 50
ACTIVITY_LIMIT_MAX = 200
API_TOKEN_MIN_LENGTH = 32
ANALYSIS_SUMMARY_SCHEMA = {
    "type": "object",
    "required": [
        "analysis_id", "evidence_id", "source_sha256", "parser",
        "parser_version", "created_at", "event_count", "diagnostics",
    ],
    "properties": {
        "analysis_id": {"type": "string", "pattern": "^TRACE-AN-[0-9a-f]{32}$"},
        "evidence_id": {"type": "string", "pattern": "^TRACE-EV-[0-9]{6}$"},
        "source_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
        "parser": {"type": "string", "enum": list(SUPPORTED_PARSER_IDS)},
        "parser_version": {"type": "string"},
        "created_at": {"type": "string", "format": "date-time"},
        "event_count": {"type": "integer", "minimum": 0},
        "diagnostics": {
            "type": "object",
            "required": [
                "lines_total", "parsed_records", "partial_records", "blank_lines",
                "malformed_lines", "issues",
            ],
            "properties": {
                name: {"type": "integer", "minimum": 0}
                for name in (
                    "lines_total", "parsed_records", "partial_records",
                    "blank_lines", "malformed_lines",
                )
            } | {
                "issues": {
                    "type": "array",
                    "maxItems": 100,
                    "items": {
                        "type": "object",
                        "required": ["line_number", "code"],
                        "properties": {
                            "line_number": {"type": "integer", "minimum": 1},
                            "code": {"type": "string"},
                        },
                        "additionalProperties": False,
                    },
                }
            },
            "additionalProperties": False,
        },
    },
    "additionalProperties": False,
}
ANALYSIS_TIMESTAMP_SCHEMA = {
    "type": "object",
    "required": ["raw_value", "raw_format", "timezone_status", "precision", "normalized_extent"],
    "properties": {
        "raw_value": {"type": ["string", "null"]},
        "raw_format": {"type": ["string", "null"]},
        "timezone_status": {"type": "string", "enum": ["known", "unknown", "not_present"]},
        "precision": {
            "type": "string",
            "enum": ["year", "month", "day", "hour", "minute", "second", "millisecond", "microsecond", "unknown"],
        },
        "normalized_extent": {
            "type": "object",
            "required": ["earliest_utc", "latest_utc"],
            "properties": {
                "earliest_utc": {"type": ["string", "null"], "format": "date-time"},
                "latest_utc": {"type": ["string", "null"], "format": "date-time"},
            },
            "additionalProperties": False,
        },
    },
    "additionalProperties": False,
}
ANALYSIS_EVENT_SCHEMA = {
    "type": "object",
    "required": [
        "schema_version", "event_id", "event_type", "source_observation_ids",
        "normalizer_name", "normalizer_version", "attributes", "temporal_extent",
    ],
    "properties": {
        "schema_version": {"type": "string"},
        "event_id": {"type": "string"},
        "event_type": {"type": "string"},
        "source_observation_ids": {"type": "array", "items": {"type": "string"}, "minItems": 1},
        "normalizer_name": {"type": "string"},
        "normalizer_version": {"type": "string"},
        "attributes": {"type": "object"},
        "temporal_extent": ANALYSIS_TIMESTAMP_SCHEMA["properties"]["normalized_extent"],
    },
    "additionalProperties": False,
}
ANALYSIS_OBSERVATION_SCHEMA = {
    "type": "object",
    "required": [
        "schema_version", "observation_id", "evidence_id", "source_type",
        "source_locator", "parser_name", "parser_version", "timestamp",
        "attributes", "parse_status", "parse_errors",
    ],
    "properties": {
        "schema_version": {"type": "string"},
        "observation_id": {"type": "string"},
        "evidence_id": {"type": "string", "pattern": "^TRACE-EV-[0-9]{6}$"},
        "source_type": {"type": "string"},
        "source_locator": {"type": "string"},
        "parser_name": {"type": "string", "enum": list(SUPPORTED_PARSER_IDS)},
        "parser_version": {"type": "string"},
        "timestamp": ANALYSIS_TIMESTAMP_SCHEMA,
        "attributes": {"type": "object"},
        "parse_status": {"type": "string", "enum": ["parsed", "partial", "failed", "unsupported"]},
        "parse_errors": {"type": "array", "items": {"type": "string"}},
    },
    "additionalProperties": False,
}
ANALYSIS_PAGINATION_SCHEMA = {
    "type": "object",
    "required": ["offset", "limit", "total_analyses"],
    "properties": {
        "offset": {"type": "integer", "minimum": 0, "maximum": 1_000_000},
        "limit": {"type": "integer", "minimum": 1, "maximum": 100},
        "total_analyses": {"type": "integer", "minimum": 0},
    },
    "additionalProperties": False,
}
ANALYSIS_LIST_SCHEMA = {
    "type": "object",
    "required": ["evidence_id", "analyses", "pagination"],
    "properties": {
        "evidence_id": ANALYSIS_SUMMARY_SCHEMA["properties"]["evidence_id"],
        "analyses": {"type": "array", "items": ANALYSIS_SUMMARY_SCHEMA},
        "pagination": ANALYSIS_PAGINATION_SCHEMA,
    },
    "additionalProperties": False,
}
ANALYSIS_DETAIL_PAGINATION_SCHEMA = {
    "type": "object",
    "required": ["offset", "limit", "total_events"],
    "properties": {
        "offset": {"type": "integer", "minimum": 0, "maximum": 1_000_000},
        "limit": {"type": "integer", "minimum": 1, "maximum": MAX_EVENT_PAGE_SIZE},
        "total_events": {"type": "integer", "minimum": 0},
    },
    "additionalProperties": False,
}
ANALYSIS_DETAIL_SCHEMA = {
    "type": "object",
    "required": ANALYSIS_SUMMARY_SCHEMA["required"] + ["events", "observations", "pagination"],
    "properties": ANALYSIS_SUMMARY_SCHEMA["properties"] | {
        "events": {"type": "array", "items": ANALYSIS_EVENT_SCHEMA},
        "observations": {"type": "array", "items": ANALYSIS_OBSERVATION_SCHEMA},
        "pagination": ANALYSIS_DETAIL_PAGINATION_SCHEMA,
    },
    "additionalProperties": False,
}
TIMELINE_ENTRY_SCHEMA = {
    "type": "object",
    "required": ["event_id", "event_type", "temporal_extent", "time_status", "source_observation_ids", "source_observations", "attributes"],
    "properties": {
        "event_id": {"type": "string"}, "event_type": {"type": "string"},
        "temporal_extent": ANALYSIS_TIMESTAMP_SCHEMA["properties"]["normalized_extent"],
        "time_status": {"type": "string", "enum": ["bounded_utc", "partially_bounded", "unresolved"]},
        "source_observation_ids": {"type": "array", "items": {"type": "string"}},
        "source_observations": {"type": "array", "items": ANALYSIS_OBSERVATION_SCHEMA},
        "attributes": {"type": "object"},
    }, "additionalProperties": False,
}
TIMELINE_SCHEMA = {
    "type": "object", "required": ["evidence_id", "analysis_id", "source_sha256", "parser", "parser_version", "entries", "counts", "pagination"],
    "properties": {
        "evidence_id": ANALYSIS_SUMMARY_SCHEMA["properties"]["evidence_id"],
        "analysis_id": ANALYSIS_SUMMARY_SCHEMA["properties"]["analysis_id"],
        "source_sha256": ANALYSIS_SUMMARY_SCHEMA["properties"]["source_sha256"],
        "parser": ANALYSIS_SUMMARY_SCHEMA["properties"]["parser"],
        "parser_version": ANALYSIS_SUMMARY_SCHEMA["properties"]["parser_version"],
        "entries": {"type": "array", "items": TIMELINE_ENTRY_SCHEMA},
        "counts": {"type": "object", "required": ["total", "known_time", "partially_bounded", "unresolved_time"], "properties": {
            "total": {"type": "integer", "minimum": 0}, "known_time": {"type": "integer", "minimum": 0, "description": "Events with both normalized UTC bounds."},
            "partially_bounded": {"type": "integer", "minimum": 0, "description": "Subset of unresolved_time with exactly one normalized UTC bound."},
            "unresolved_time": {"type": "integer", "minimum": 0, "description": "Events without a fully bounded UTC extent, including partial and unknown extents."},
        }, "additionalProperties": False},
        "pagination": {"type": "object", "required": ["offset", "limit", "total"], "properties": {
            "offset": {"type": "integer", "minimum": 0, "maximum": 1_000_000},
            "limit": {"type": "integer", "minimum": 1, "maximum": 100}, "total": {"type": "integer", "minimum": 0},
        }, "additionalProperties": False},
    }, "additionalProperties": False,
}
RECONSTRUCTION_RULES_SCHEMA = {
    "type": "object", "required": ["rules"],
    "properties": {"rules": {"type": "array", "items": {
        "type": "object",
        "required": ["rule_id", "version", "description", "supported_source_types", "required_attributes", "assumptions", "limitations", "minimum_supporting_observations"],
        "properties": {
            "rule_id": {"type": "string"}, "version": {"type": "string"},
            "description": {"type": "string"}, "supported_source_types": {"type": "array", "items": {"type": "string"}},
            "required_attributes": {"type": "array", "items": {"type": "string"}},
            "assumptions": {"type": "array", "items": {"type": "string"}},
            "limitations": {"type": "array", "items": {"type": "string"}},
            "minimum_supporting_observations": {"type": "integer", "minimum": 2},
        }, "additionalProperties": False,
    }}}, "additionalProperties": False,
}
RECONSTRUCTION_SUMMARY_SCHEMA = {
    "type": "object", "required": ["reconstruction_id", "evidence_id", "source_sha256", "analysis_id", "parser", "parser_version", "created_at", "config", "rule_versions", "hypothesis_count", "skipped_input_count", "result_status"],
    "properties": {
        "reconstruction_id": {"type": "string"}, "evidence_id": {"type": "string"},
        "source_sha256": {"type": "string"}, "analysis_id": {"type": "string"},
        "parser": {"type": "string"}, "parser_version": {"type": "string"},
        "created_at": {"type": "string", "format": "date-time"},
        "config": {"type": "object"}, "rule_versions": {"type": "array", "items": {"type": "object"}},
        "hypothesis_count": {"type": "integer"}, "skipped_input_count": {"type": "integer"},
        "result_status": {"type": "string", "enum": ["candidates_generated", "no_candidates"]},
    }, "additionalProperties": False,
}
RECONSTRUCTION_LIST_SCHEMA = {
    "type": "object", "required": ["evidence_id", "reconstructions", "pagination"],
    "properties": {
        "evidence_id": {"type": "string"},
        "reconstructions": {"type": "array", "items": RECONSTRUCTION_SUMMARY_SCHEMA},
        "pagination": {"type": "object", "required": ["offset", "limit", "total_reconstructions"], "properties": {
            "offset": {"type": "integer"}, "limit": {"type": "integer"}, "total_reconstructions": {"type": "integer"},
        }, "additionalProperties": False},
    }, "additionalProperties": False,
}
RECONSTRUCTION_DETAIL_SCHEMA = {
    "type": "object", "required": list(RECONSTRUCTION_SUMMARY_SCHEMA["required"]) + ["hypotheses", "skipped_inputs", "pagination"],
    "properties": RECONSTRUCTION_SUMMARY_SCHEMA["properties"] | {
        "hypotheses": {"type": "array", "items": {"type": "object"}},
        "skipped_inputs": {"type": "array", "items": {"type": "object", "required": ["rule_id", "rule_version", "observation_id", "reason"]}},
        "pagination": {"type": "object", "required": ["hypotheses", "skipped_inputs"], "properties": {
            "hypotheses": {"type": "object", "required": ["offset", "limit", "total"]},
            "skipped_inputs": {"type": "object", "required": ["offset", "limit", "total"]},
        }},
    }, "additionalProperties": False,
}


def _error(code: str, message: str, status_code: int) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={"error": {"code": code, "message": message}},
    )


def _safe_filename(filename: str | None) -> str | None:
    if not isinstance(filename, str) or not filename:
        return None
    normalized = unicodedata.normalize("NFC", filename.replace("\\", "/"))
    basename = normalized.rsplit("/", 1)[-1]
    try:
        too_long = len(basename.encode("utf-8")) > 255
    except UnicodeEncodeError:
        return None
    if not basename or basename in {".", ".."} or too_long or any(
        unicodedata.category(char).startswith("C") for char in basename
    ):
        return None
    return basename


def _configured_upload_limit() -> int | None:
    configured = os.environ.get("TRACEE_MAX_UPLOAD_BYTES")
    if configured is None:
        return DEFAULT_MAX_UPLOAD_BYTES
    if not re.fullmatch(r"[0-9]+", configured):
        return None
    try:
        limit = int(configured)
    except ValueError:
        return None
    return limit if limit > 0 else None


def _origin_is_same(request: Request) -> bool:
    supplied = request.headers.get("origin")
    if supplied is None:
        return True
    try:
        parsed = urlsplit(supplied)
        expected_scheme = request.url.scheme.casefold()
        expected_netloc = request.url.netloc.casefold()
        return (
            parsed.scheme.casefold() == expected_scheme
            and parsed.netloc.casefold() == expected_netloc
            and parsed.path in ("", "/")
            and not parsed.query
            and not parsed.fragment
            and not parsed.username
            and not parsed.password
        )
    except (ValueError, AttributeError):
        return False


def _upload_auth_error(request: Request) -> JSONResponse | None:
    configured = os.environ.get("TRACEE_UPLOAD_TOKEN")
    if configured is None:
        return _error(
            "upload_disabled",
            "Evidence upload is disabled until TRACEE_UPLOAD_TOKEN is configured.",
            503,
        )
    if len(configured) < 32:
        return _error(
            "upload_token_misconfigured",
            "The configured upload token is too weak; use at least 32 characters.",
            503,
        )
    api_token = os.environ.get("TRACEE_API_TOKEN")
    if api_token is None or not hmac.compare_digest(
        configured.encode("utf-8"), api_token.encode("utf-8")
    ):
        return _error(
            "upload_token_misconfigured",
            "TRACEE_UPLOAD_TOKEN must be the same credential as TRACEE_API_TOKEN.",
            503,
        )
    if not _origin_is_same(request):
        return _error(
            "invalid_origin",
            "The upload request origin does not match this API origin.",
            403,
        )
    authorization = request.headers.get("authorization", "")
    scheme, separator, supplied = authorization.partition(" ")
    if (
        not separator
        or scheme.casefold() != "bearer"
        or not supplied
        or not hmac.compare_digest(
            supplied.encode("utf-8"), configured.encode("utf-8")
        )
    ):
        return _error(
            "unauthorized",
            "A valid bearer upload token is required.",
            401,
        )
    return None


def _api_auth_error(request: Request) -> JSONResponse | None:
    configured = os.environ.get("TRACEE_API_TOKEN")
    if configured is None:
        return _error(
            "api_auth_not_configured",
            "The API is unavailable until TRACEE_API_TOKEN is configured.",
            503,
        )
    if len(configured) < API_TOKEN_MIN_LENGTH:
        return _error(
            "api_auth_misconfigured",
            "The configured API credential is too weak; use at least 32 characters.",
            503,
        )
    authorization = request.headers.get("authorization", "")
    scheme, separator, supplied = authorization.partition(" ")
    if (
        not separator
        or scheme.casefold() != "bearer"
        or not supplied
        or not hmac.compare_digest(
            supplied.encode("utf-8"), configured.encode("utf-8")
        )
    ):
        return _error(
            "unauthorized",
            "A valid API bearer credential is required.",
            401,
        )
    return None


def create_app(vault_dir: str | Path | None = None) -> FastAPI:
    """Build the API, optionally injecting an existing vault directory."""

    configured_dir = vault_dir
    if configured_dir is None:
        configured_dir = os.environ.get("TRACEE_API_VAULT_DIR")

    docs_enabled = os.environ.get("TRACEE_API_DOCS_ENABLED") == "1"
    app = FastAPI(
        title="TRACEE API",
        version="1.0.0",
        description=(
            "Sensitive API routes require a shared bearer credential. "
            "It is not individual identity authentication or a production security boundary."
        ),
        docs_url="/docs" if docs_enabled else None,
        redoc_url="/redoc" if docs_enabled else None,
        openapi_url="/openapi.json" if docs_enabled else None,
    )
    app.state.vault_dir = Path(configured_dir).resolve() if configured_dir else None

    @app.middleware("http")
    async def require_api_bearer(request: Request, call_next):
        if request.url.path == "/api/v1" or request.url.path.startswith("/api/v1/"):
            auth_error = _api_auth_error(request)
            if auth_error is not None:
                return auth_error
        response = await call_next(request)
        if request.url.path.endswith((".css", ".js", ".html", ".png")):
            response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"
        return response

    def service_or_error() -> tuple[TraceeService | None, JSONResponse | None]:
        root = app.state.vault_dir
        if root is None:
            return None, _error(
                "vault_not_configured",
                "Set TRACEE_API_VAULT_DIR or inject vault_dir.",
                503,
            )
        if not root.is_dir():
            return None, _error(
                "vault_unavailable",
                "The configured vault is unavailable. Check its location and local access permissions.",
                503,
            )
        store = FilesystemVaultStore(root)
        if not store.records_dir.is_dir():
            return None, _error(
                "vault_unavailable",
                "The configured vault metadata directory is unavailable.",
                503,
            )
        return TraceeService(root), None

    def existing_ingest_service() -> tuple[TraceeService | None, JSONResponse | None]:
        """Validate every required vault entry without initializing it."""
        root = app.state.vault_dir
        if root is None:
            return None, _error(
                "vault_not_configured",
                "Set TRACEE_API_VAULT_DIR or inject vault_dir.",
                503,
            )
        if not root.is_dir() or root.is_symlink():
            return None, _error(
                "vault_unavailable",
                "The configured vault is unavailable. Initialize and check the existing vault locally.",
                503,
            )
        store = FilesystemVaultStore(root)
        required_dirs = (
            store.objects_dir,
            store.records_dir,
            store.chain_dir,
            store.staging_dir,
        )
        required_files = (store.chain_path, store.lock_path)
        if any(path.is_symlink() or not path.is_dir() for path in required_dirs):
            return None, _error(
                "vault_unavailable",
                "The configured vault layout is incomplete or unavailable.",
                503,
            )
        if any(path.is_symlink() or not path.is_file() for path in required_files):
            return None, _error(
                "vault_unavailable",
                "The configured vault layout is incomplete or unavailable.",
                503,
            )
        return TraceeService(root), None

    def activity_failure(
        exc: ActivityLogError,
        *,
        operation_completed: bool = False,
        operation: dict | None = None,
    ) -> JSONResponse:
        if isinstance(exc, ActivityLogIntegrityError):
            code = "activity_log_invalid"
            message = "The activity log is malformed or its integrity check failed."
            status_code = 500
        else:
            logger.exception("TRACEE activity log operation failed")
            code = "activity_log_unavailable"
            message = "The activity log could not be accessed safely."
            status_code = 503
        content = {"error": {"code": code, "message": message}}
        if operation is not None or operation_completed:
            content["operation"] = operation or {"completed": operation_completed}
            content["audit"] = {"recorded": False}
        return JSONResponse(status_code=status_code, content=content)

    @app.exception_handler(Exception)
    async def unexpected_error_handler(request: Request, exc: Exception) -> JSONResponse:
        logger.exception("Unexpected API error for %s %s", request.method, request.url.path)
        return _error(
            "internal_error",
            "An unexpected internal error occurred.",
            500,
        )

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"service": "TRACEE", "status": "ok"}

    @app.get("/api/v1/evidence")
    def list_evidence():
        service, error_response = service_or_error()
        if error_response:
            return error_response
        assert service is not None
        records = []
        try:
            for path in sorted(service.vault.records_dir.glob("*.json")):
                evidence_id = path.stem
                if not is_valid_evidence_id(evidence_id):
                    logger.warning("Malformed metadata filename in API inventory: %s", path.name)
                    return _error(
                        "malformed_metadata",
                        "A metadata record has an invalid evidence ID.",
                        500,
                    )
                try:
                    raw_record = service.get_metadata(evidence_id)
                except Exception:
                    logger.exception("Unable to read metadata record for %s", evidence_id)
                    return JSONResponse(
                        status_code=500,
                        content={"error": {"code": "unreadable_metadata", "message": "A metadata record could not be read.", "evidence_id": evidence_id}},
                    )
                try:
                    records.append(EvidenceMetadata(**raw_record).to_dict())
                except (TypeError, ValueError):
                    logger.warning("Malformed metadata record for %s", evidence_id)
                    return JSONResponse(
                        status_code=500,
                        content={"error": {"code": "malformed_metadata", "message": "A metadata record has an invalid structure or field value.", "evidence_id": evidence_id}},
                    )
        except OSError:
            logger.exception("Unable to enumerate metadata records")
            return _error(
                "unreadable_metadata",
                "The metadata inventory could not be read.",
                500,
            )
        return {"evidence": records}

    @app.get("/api/v1/evidence/{evidence_id}")
    def get_evidence(evidence_id: str):
        if not is_valid_evidence_id(evidence_id):
            return _error("invalid_evidence_id", "Evidence ID has an invalid format.", 400)
        service, error_response = service_or_error()
        if error_response:
            return error_response
        assert service is not None
        try:
            raw_record = service.get_metadata(evidence_id)
        except Exception:
            if not service.vault.record_path(evidence_id).is_file():
                return JSONResponse(
                    status_code=404,
                    content={"error": {"code": "evidence_not_found", "message": "Evidence metadata record was not found.", "evidence_id": evidence_id}},
                )
            logger.exception("Unable to read metadata record for %s", evidence_id)
            return JSONResponse(
                status_code=500,
                content={"error": {"code": "unreadable_metadata", "message": "The metadata record could not be read.", "evidence_id": evidence_id}},
            )
        try:
            metadata = EvidenceMetadata(**raw_record).to_dict()
        except (TypeError, ValueError):
            logger.warning("Malformed metadata record for %s", evidence_id)
            return JSONResponse(
                status_code=500,
                content={"error": {"code": "malformed_metadata", "message": "The metadata record has an invalid structure or field value.", "evidence_id": evidence_id}},
            )
        try:
            ActivityLog(service.vault_dir).append(
                event_type="evidence_viewed",
                actor="local_api_token",
                outcome="success",
                evidence_id=evidence_id,
            )
        except ActivityLogError as exc:
            logger.exception("Metadata was read but its activity event could not be recorded")
            return activity_failure(
                exc,
                operation_completed=True,
                operation={"completed": True, "type": "evidence_viewed", "evidence_id": evidence_id},
            )
        return metadata

    @app.get("/api/v1/evidence/{evidence_id}/verify")
    def verify_evidence(evidence_id: str):
        if not is_valid_evidence_id(evidence_id):
            return _error("invalid_evidence_id", "Evidence ID has an invalid format.", 400)
        service, error_response = service_or_error()
        if error_response:
            return error_response
        assert service is not None
        result: VerificationResult = service.verify(evidence_id)
        safe_messages = {
            "VALID": "Evidence, metadata, and chain verification successful.",
            "TAMPERED": "Integrity verification detected a mismatch.",
            "MISSING": "A required evidence or vault file is missing.",
            "INVALID": "The evidence metadata or integrity data is invalid.",
        }
        safe_id = result.evidence_id if is_valid_evidence_id(result.evidence_id) else evidence_id
        response = {
            "state": result.state.value,
            "evidence_id": safe_id,
            "message": safe_messages[result.state.value],
        }
        if result.message and result.message != safe_messages.get(result.state.value):
            response["diagnostics"] = result.message
        try:
            ActivityLog(service.vault_dir).append(
                event_type="integrity_verification",
                actor="local_api_token",
                outcome=result.state.value,
                evidence_id=safe_id,
            )
        except ActivityLogError as exc:
            logger.exception("Verification completed but its activity event could not be recorded")
            return activity_failure(
                exc,
                operation_completed=True,
                operation={
                    "completed": True,
                    "type": "integrity_verification",
                    "evidence_id": safe_id,
                    "state": result.state.value,
                },
            )
        return response

    @app.post(
        "/api/v1/evidence/{evidence_id}/analyze",
        summary="Analyze verified evidence",
        description=(
            "Parses an existing verified evidence object using an explicit parser. "
            f"Supported parser identifiers are {', '.join(f'`{parser}`' for parser in SUPPORTED_PARSER_IDS)}. "
            "This operation writes only a separate immutable derived analysis."
        ),
        openapi_extra={
            "requestBody": {
                "required": True,
                "content": {
                    "application/json": {
                        "schema": {
                            "type": "object",
                            "required": ["parser"],
                            "additionalProperties": False,
                            "properties": {
                                "parser": {"type": "string", "enum": list(SUPPORTED_PARSER_IDS)}
                            },
                        }
                    }
                },
            }
        },
        responses={
            201: {
                "description": "Analysis persisted with source provenance.",
                "content": {"application/json": {"schema": ANALYSIS_SUMMARY_SCHEMA}},
            },
            400: {"description": "Invalid evidence identifier."},
            404: {"description": "Evidence record not found."},
            409: {"description": "Source evidence failed integrity checks or changed."},
            413: {"description": "Analysis input or result limit exceeded."},
            422: {"description": "Request or parser selection is unsupported."},
            503: {"description": "Vault or derived analysis storage unavailable."},
        },
    )
    def analyze_evidence(evidence_id: str, payload: dict, request: Request):
        if not is_valid_evidence_id(evidence_id):
            return _error("invalid_evidence_id", "Evidence ID has an invalid format.", 400)
        if not _origin_is_same(request):
            return _error("invalid_origin", "The request origin does not match this API origin.", 403)
        if set(payload) != {"parser"} or not isinstance(payload.get("parser"), str) or not payload["parser"].strip():
            return _error("invalid_request", "Request JSON must contain only a non-empty parser identifier.", 422)
        service, error_response = service_or_error()
        if error_response:
            return error_response
        assert service is not None
        activity = ActivityLog(service.vault_dir)
        try:
            activity.append(
                event_type="evidence_analysis_started",
                actor="local_api_token",
                outcome="accepted",
                evidence_id=evidence_id,
            )
        except ActivityLogError as exc:
            logger.exception("Analysis was not started because its activity event could not be recorded")
            return activity_failure(exc)

        analyzer = EvidenceAnalysisService(service)
        try:
            summary = analyzer.analyze(evidence_id, payload["parser"])
        except AnalysisError as exc:
            try:
                activity.append(
                    event_type="evidence_analysis_failed",
                    actor="local_api_token",
                    outcome=exc.code if exc.code in {
                        "unsupported_parser", "parser_mismatch", "integrity_verification_failed",
                        "evidence_not_found", "evidence_unavailable", "analysis_limit_exceeded",
                        "source_changed", "invalid_record", "analysis_storage_failed",
                        "malformed_metadata", "unreadable_metadata", "analysis_configuration_invalid",
                        "vault_unavailable", "analysis_id_conflict", "analysis_unavailable",
                    } else "internal_error",
                    evidence_id=evidence_id,
                )
            except ActivityLogError as audit_exc:
                logger.exception("Analysis failed and its failure activity could not be recorded")
                return activity_failure(
                    audit_exc,
                    operation_completed=False,
                    operation={
                        "completed": False,
                        "type": "evidence_analysis",
                        "evidence_id": evidence_id,
                        "failure_code": exc.code,
                    },
                )
            response = _error(exc.code, exc.message, exc.status_code)
            if exc.verification_state:
                response = JSONResponse(
                    status_code=exc.status_code,
                    content={
                        "error": {"code": exc.code, "message": exc.message},
                        "verification": {"state": exc.verification_state},
                    },
                )
            return response
        except Exception:
            logger.exception("Unexpected evidence analysis failure")
            try:
                activity.append(
                    event_type="evidence_analysis_failed",
                    actor="local_api_token",
                    outcome="internal_error",
                    evidence_id=evidence_id,
                )
            except ActivityLogError as audit_exc:
                return activity_failure(audit_exc, operation={"completed": False, "type": "evidence_analysis", "evidence_id": evidence_id})
            return _error("internal_error", "An unexpected internal error occurred.", 500)

        try:
            activity.append(
                event_type="evidence_analysis_completed",
                actor="local_api_token",
                outcome="success",
                evidence_id=evidence_id,
                sha256=summary["source_sha256"],
            )
        except ActivityLogError as exc:
            logger.exception("Analysis was persisted but its completion activity could not be recorded")
            return activity_failure(
                exc,
                operation_completed=True,
                operation={"completed": True, "type": "evidence_analysis", **summary},
            )
        return JSONResponse(status_code=201, content=summary)

    @app.get(
        "/api/v1/evidence/{evidence_id}/analyses",
        summary="List stored analyses for evidence",
        description="Returns stored analysis summaries whose source evidence still verifies against the recorded source hash.",
        responses={
            200: {
                "description": "A bounded page of stored analysis summaries.",
                "content": {"application/json": {"schema": ANALYSIS_LIST_SCHEMA}},
            }
        },
    )
    def list_evidence_analyses(
        evidence_id: str,
        offset: int = Query(0, ge=0, le=1_000_000),
        limit: int = Query(25, ge=1, le=100),
    ):
        if not is_valid_evidence_id(evidence_id):
            return _error("invalid_evidence_id", "Evidence ID has an invalid format.", 400)
        service, error_response = service_or_error()
        if error_response:
            return error_response
        assert service is not None
        try:
            summaries, total = EvidenceAnalysisService(service).list_analyses(
                evidence_id, offset=offset, limit=limit
            )
        except AnalysisError as exc:
            return _error(exc.code, exc.message, exc.status_code)
        return {
            "evidence_id": evidence_id,
            "analyses": summaries,
            "pagination": {"offset": offset, "limit": limit, "total_analyses": total},
        }

    @app.get(
        "/api/v1/evidence/{evidence_id}/analyses/{analysis_id}",
        summary="Retrieve a stored analysis page",
        description=(
            "Returns a bounded page of normalized events and matching source observations. "
            "Offset defaults to 0; limit defaults to 25 and is capped at 50."
        ),
        responses={
            200: {
                "description": "One validated page of events and source observations.",
                "content": {"application/json": {"schema": ANALYSIS_DETAIL_SCHEMA}},
            }
        },
    )
    def get_evidence_analysis(
        evidence_id: str,
        analysis_id: str,
        offset: int = Query(0, ge=0, le=1_000_000),
        limit: int = Query(DEFAULT_EVENT_PAGE_SIZE, ge=1, le=MAX_EVENT_PAGE_SIZE),
    ):
        if not is_valid_evidence_id(evidence_id):
            return _error("invalid_evidence_id", "Evidence ID has an invalid format.", 400)
        service, error_response = service_or_error()
        if error_response:
            return error_response
        assert service is not None
        try:
            return EvidenceAnalysisService(service).get_analysis(
                evidence_id, analysis_id, offset=offset, limit=limit
            )
        except AnalysisError as exc:
            return _error(exc.code, exc.message, exc.status_code)

    @app.get(
        "/api/v1/evidence/{evidence_id}/analyses/{analysis_id}/timeline",
        summary="Build a read-only event timeline from a stored analysis",
        description=(
            "Returns events from a validated stored analysis. Fully bounded UTC events are ordered first; "
            "partial and unresolved timestamps remain visible after them. Temporal proximity does not establish causality."
        ),
        responses={200: {"description": "A page of validated evidence-backed timeline entries.", "content": {"application/json": {"schema": TIMELINE_SCHEMA}}}},
    )
    def get_evidence_timeline(
        evidence_id: str,
        analysis_id: str,
        offset: int = Query(0, ge=0, le=1_000_000),
        limit: int = Query(DEFAULT_EVENT_PAGE_SIZE, ge=1, le=100),
    ):
        if not is_valid_evidence_id(evidence_id):
            return _error("invalid_evidence_id", "Evidence ID has an invalid format.", 400)
        if not is_valid_analysis_id(analysis_id):
            return _error("invalid_analysis_id", "Analysis ID has an invalid format.", 400)
        service, error_response = service_or_error()
        if error_response:
            return error_response
        assert service is not None
        analyzer = EvidenceAnalysisService(service)
        try:
            analysis = analyzer.load_analysis(evidence_id, analysis_id)
            all_events = analysis["events"]
            observations = {item["observation_id"]: item for item in analysis["observations"]}

            def normalized_utc(value):
                if value is None:
                    return None
                if not isinstance(value, str):
                    raise ValueError("invalid UTC bound")
                parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
                if parsed.utcoffset() != timezone.utc.utcoffset(parsed):
                    raise ValueError("non-UTC bound")
                return parsed.astimezone(timezone.utc)

            entries = []
            for event in all_events:
                refs = event.get("source_observation_ids")
                if not isinstance(refs, list) or not refs or any(ref not in observations for ref in refs):
                    return _error("analysis_invalid", "The stored analysis contains a broken source reference.", 500)
                linked = [observations[ref] for ref in refs]
                if any(item.get("evidence_id") != evidence_id for item in linked):
                    return _error("analysis_invalid", "The stored analysis contains a source from another evidence record.", 500)
                extent = event["temporal_extent"]
                earliest = normalized_utc(extent["earliest_utc"])
                latest = normalized_utc(extent["latest_utc"])
                if earliest is not None and latest is not None:
                    status = "bounded_utc"
                    sort_key = (0, earliest, latest, event["event_id"])
                elif earliest is not None or latest is not None:
                    status = "partially_bounded"
                    sort_key = (1, earliest or latest, event["event_id"])
                else:
                    status = "unresolved"
                    sort_key = (2, event["event_id"])
                entries.append((sort_key, {
                    "event_id": event["event_id"], "event_type": event["event_type"],
                    "temporal_extent": extent, "time_status": status,
                    "source_observation_ids": refs, "source_observations": linked,
                    "attributes": event["attributes"],
                }))
            entries.sort(key=lambda pair: pair[0])
            result = [item for _, item in entries]
        except AnalysisError as exc:
            return _error(exc.code, exc.message, exc.status_code)
        except (KeyError, TypeError, ValueError):
            logger.exception("Validated analysis could not be converted to timeline for %s", analysis_id)
            return _error("analysis_invalid", "The stored analysis contains invalid timeline data.", 500)
        counts = {
            "total": len(result),
            "known_time": sum(item["time_status"] == "bounded_utc" for item in result),
            "partially_bounded": sum(item["time_status"] == "partially_bounded" for item in result),
            "unresolved_time": sum(item["time_status"] != "bounded_utc" for item in result),
        }
        return {
            "evidence_id": evidence_id, "analysis_id": analysis_id,
            "source_sha256": analysis["source_sha256"], "parser": analysis["parser"],
            "parser_version": analysis["parser_version"],
            "entries": result[offset:offset + limit], "counts": counts,
            "pagination": {"offset": offset, "limit": limit, "total": len(result)},
        }

    @app.get(
        "/api/v1/reconstruction/rules",
        summary="List built-in reconstruction rules",
        responses={200: {"description": "The versioned production rule registry.", "content": {"application/json": {"schema": RECONSTRUCTION_RULES_SCHEMA}}}},
    )
    def list_reconstruction_rules():
        return {"rules": [public_rule(item) for item in BUILTIN_RULES]}

    @app.post(
        "/api/v1/evidence/{evidence_id}/analyses/{analysis_id}/reconstruct",
        status_code=201,
        summary="Generate evidence-backed candidate reconstructions",
        description=(
            "Runs parser-specific deterministic candidate grouping over a validated analysis. "
            f"candidate_window_seconds defaults to 300 and is bounded from 0 through {MAX_WINDOW_SECONDS}. "
            "Grouping does not prove an incident or causal relationship."
        ),
        openapi_extra={"requestBody": {"required": True, "content": {"application/json": {"schema": {
            "type": "object", "properties": {"candidate_window_seconds": {"type": "integer", "minimum": 0, "maximum": MAX_WINDOW_SECONDS}}, "additionalProperties": False,
        }}}}},
        responses={201: {"description": "A persisted reconstruction summary.", "content": {"application/json": {"schema": RECONSTRUCTION_SUMMARY_SCHEMA}}}},
    )
    async def create_reconstruction(evidence_id: str, analysis_id: str, request: Request):
        if not is_valid_evidence_id(evidence_id):
            return _error("invalid_evidence_id", "Evidence ID has an invalid format.", 400)
        if not is_valid_analysis_id(analysis_id):
            return _error("invalid_analysis_id", "Analysis ID has an invalid format.", 400)
        service, error_response = service_or_error()
        if error_response:
            return error_response
        assert service is not None
        try:
            body = await request.json()
        except (ValueError, json.JSONDecodeError):
            return _error("invalid_request", "Request body must be a JSON object.", 422)
        if not isinstance(body, dict) or set(body) - {"candidate_window_seconds"}:
            return _error("invalid_request", "Request body must contain only candidate_window_seconds.", 422)
        window = body.get("candidate_window_seconds", 300)
        try:
            window = ReconstructionService.validate_window(window)
        except ReconstructionError as exc:
            return _error(exc.code, exc.message, exc.status_code)
        activity = ActivityLog(service.vault_dir)
        try:
            activity.append(
                event_type="evidence_reconstruction_started",
                actor="local_api_token", outcome="accepted", evidence_id=evidence_id,
            )
        except ActivityLogError as exc:
            return activity_failure(exc)
        reconstructor = ReconstructionService(service)
        try:
            summary = reconstructor.reconstruct(evidence_id, analysis_id, window)
        except (AnalysisError, ReconstructionError) as exc:
            try:
                activity.append(
                    event_type="evidence_reconstruction_failed",
                    actor="local_api_token", outcome=exc.code,
                    evidence_id=evidence_id,
                )
            except ActivityLogError as audit_exc:
                response = activity_failure(audit_exc)
                return JSONResponse(status_code=response.status_code, content={
                    "error": {"code": exc.code, "message": exc.message},
                    "audit": {"recorded": False},
                })
            return _error(exc.code, exc.message, exc.status_code)
        except Exception:
            logger.exception("Unexpected reconstruction failure")
            try:
                activity.append(
                    event_type="evidence_reconstruction_failed",
                    actor="local_api_token", outcome="internal_error",
                    evidence_id=evidence_id,
                )
            except ActivityLogError as audit_exc:
                response = activity_failure(audit_exc)
                return JSONResponse(status_code=response.status_code, content={
                    "error": {"code": "internal_error", "message": "An unexpected internal error occurred."},
                    "audit": {"recorded": False},
                })
            return _error("internal_error", "An unexpected internal error occurred.", 500)
        try:
            activity.append(
                event_type="evidence_reconstruction_completed",
                actor="local_api_token", outcome="success",
                evidence_id=evidence_id, sha256=summary["source_sha256"],
            )
        except ActivityLogError as exc:
            logger.exception("Reconstruction was persisted but completion activity could not be recorded")
            response = activity_failure(exc, operation_completed=True, operation={
                "completed": True, "type": "evidence_reconstruction", **summary,
            })
            return response
        return JSONResponse(status_code=201, content=summary)

    @app.get(
        "/api/v1/evidence/{evidence_id}/reconstructions",
        summary="List validated reconstruction summaries",
        responses={200: {"description": "A bounded page of current, provenance-validated reconstruction summaries.", "content": {"application/json": {"schema": RECONSTRUCTION_LIST_SCHEMA}}}},
    )
    def list_reconstructions(
        evidence_id: str,
        offset: int = Query(0, ge=0, le=1_000_000),
        limit: int | None = Query(None, ge=1, le=RECONSTRUCTION_PAGE_MAX),
    ):
        if not is_valid_evidence_id(evidence_id):
            return _error("invalid_evidence_id", "Evidence ID has an invalid format.", 400)
        service, error_response = service_or_error()
        if error_response:
            return error_response
        assert service is not None
        try:
            default_limit, _ = page_size_limits()
            resolved_limit = default_limit if limit is None else limit
            records, total = ReconstructionService(service).list_reconstructions(evidence_id, offset=offset, limit=resolved_limit)
        except AnalysisError as exc:
            return _error(exc.code, exc.message, exc.status_code)
        except ReconstructionError as exc:
            return _error(exc.code, exc.message, exc.status_code)
        return {"evidence_id": evidence_id, "reconstructions": records, "pagination": {"offset": offset, "limit": resolved_limit, "total_reconstructions": total}}

    @app.get(
        "/api/v1/evidence/{evidence_id}/reconstructions/{reconstruction_id}",
        summary="Retrieve a validated reconstruction run",
        responses={200: {"description": "The actual stored run, with bounded hypothesis and skipped-input pages.", "content": {"application/json": {"schema": RECONSTRUCTION_DETAIL_SCHEMA}}}},
    )
    def get_reconstruction(
        evidence_id: str,
        reconstruction_id: str,
        hypothesis_offset: int = Query(0, ge=0, le=1_000_000),
        hypothesis_limit: int | None = Query(None, ge=1, le=RECONSTRUCTION_PAGE_MAX),
        skipped_offset: int = Query(0, ge=0, le=1_000_000),
        skipped_limit: int | None = Query(None, ge=1, le=RECONSTRUCTION_PAGE_MAX),
    ):
        if not is_valid_evidence_id(evidence_id):
            return _error("invalid_evidence_id", "Evidence ID has an invalid format.", 400)
        service, error_response = service_or_error()
        if error_response:
            return error_response
        assert service is not None
        try:
            default_limit, _ = page_size_limits()
            return ReconstructionService(service).get_reconstruction(
                evidence_id, reconstruction_id,
                hypothesis_offset=hypothesis_offset, hypothesis_limit=default_limit if hypothesis_limit is None else hypothesis_limit,
                skipped_offset=skipped_offset, skipped_limit=default_limit if skipped_limit is None else skipped_limit,
            )
        except AnalysisError as exc:
            return _error(exc.code, exc.message, exc.status_code)
        except ReconstructionError as exc:
            return _error(exc.code, exc.message, exc.status_code)

    @app.post(
        "/api/v1/evidence",
        status_code=201,
        summary="Acquire one evidence file",
        description=(
            "Accepts exactly one multipart file field named `file`. Requires a "
            "valid API bearer token configured through TRACEE_API_TOKEN and the "
            "same credential configured through TRACEE_UPLOAD_TOKEN. Existing "
            "upload size, origin, and multipart checks also apply. The shared "
            "credential does not identify an individual."
        ),
        openapi_extra={
            "requestBody": {
                "required": True,
                "content": {
                    "multipart/form-data": {
                        "schema": {
                            "type": "object",
                            "required": ["file"],
                            "additionalProperties": False,
                            "properties": {
                                "file": {"type": "string", "format": "binary"}
                            },
                        }
                    }
                },
            }
        },
        responses={
            201: {
                "description": "Evidence and its acquisition activity record were persisted.",
                "content": {
                    "application/json": {
                        "schema": {
                            "type": "object",
                            "required": ["evidence_id", "metadata", "chain_sequence"],
                            "properties": {
                                "evidence_id": {"type": "string"},
                                "metadata": {
                                    "type": "object",
                                    "required": [
                                        "schema_version", "evidence_id", "original_filename",
                                        "size_bytes", "sha256", "ingested_at", "media_type",
                                    ],
                                    "properties": {
                                        "schema_version": {"type": "string"},
                                        "evidence_id": {"type": "string"},
                                        "original_filename": {"type": "string"},
                                        "size_bytes": {"type": "integer", "minimum": 1},
                                        "sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                                        "ingested_at": {"type": "string", "format": "date-time"},
                                        "media_type": {"type": "string"},
                                    },
                                },
                                "chain_sequence": {"type": "integer", "minimum": 1},
                            },
                        }
                    }
                },
            }
        },
    )
    async def upload_evidence(request: Request):
        auth_error = _upload_auth_error(request)
        if auth_error:
            return auth_error
        max_bytes = _configured_upload_limit()
        if max_bytes is None:
            return _error(
                "upload_configuration_invalid",
                "TRACEE_MAX_UPLOAD_BYTES must be a positive integer.",
                503,
            )
        service, vault_error = existing_ingest_service()
        if vault_error:
            return vault_error
        assert service is not None
        activity = ActivityLog(service.vault_dir)
        try:
            activity.append(
                event_type="evidence_acquisition_started",
                actor="local_upload_token",
                outcome="accepted",
            )
        except ActivityLogError as exc:
            logger.exception("Acquisition was not started because activity logging failed")
            return activity_failure(exc)

        filename: str | None = None
        copied_size = 0

        def fail_upload(
            code: str,
            message: str,
            status_code: int,
            *,
            outcome: str,
            evidence_id: str | None = None,
            size_bytes: int | None = None,
            operation_outcome: str = "rejected",
        ) -> JSONResponse:
            try:
                activity.append(
                    event_type="evidence_acquisition_failed",
                    actor="local_upload_token",
                    outcome=outcome,
                    evidence_id=evidence_id,
                    filename=filename,
                    size_bytes=size_bytes,
                )
            except ActivityLogError as exc:
                logger.exception("Acquisition failed and its failure activity event could not be recorded")
                return activity_failure(
                    exc,
                    operation={
                        "completed": True,
                        "type": "evidence_acquisition",
                        "outcome": operation_outcome,
                        "evidence_stored": False,
                    },
                )
            return _error(code, message, status_code)

        content_length = request.headers.get("content-length")
        if content_length is not None:
            if not re.fullmatch(r"[0-9]+", content_length):
                return fail_upload(
                    "invalid_content_length",
                    "The request content length is invalid.",
                    400,
                    outcome="invalid_content_length",
                )
            try:
                request_size = int(content_length)
            except ValueError:
                return fail_upload(
                    "invalid_content_length",
                    "The request content length is invalid.",
                    400,
                    outcome="invalid_content_length",
                )
            if request_size > max_bytes + MAX_MULTIPART_OVERHEAD_BYTES:
                return fail_upload(
                    "upload_too_large",
                    "The upload exceeds the configured file size limit.",
                    413,
                    outcome="upload_too_large",
                )
        media_type = request.headers.get("content-type", "").split(";", 1)[0].strip().casefold()
        if media_type != "multipart/form-data":
            return fail_upload(
                "unsupported_media_type",
                "Upload one file using multipart/form-data.",
                415,
                outcome="unsupported_media_type",
            )

        form = None
        upload: StarletteUploadFile | None = None
        try:
            try:
                form = await request.form(max_files=2, max_fields=2)
            except Exception:
                return fail_upload(
                    "invalid_multipart",
                    "The multipart upload is malformed.",
                    400,
                    outcome="invalid_multipart",
                )
            items = form.multi_items()
            if not items:
                return fail_upload(
                    "missing_file",
                    "Provide exactly one file field named `file`.",
                    400,
                    outcome="missing_file",
                )
            if any(key != "file" for key, _ in items):
                return fail_upload(
                    "unexpected_form_field",
                    "Only the multipart field named `file` is accepted.",
                    400,
                    outcome="unexpected_form_field",
                )
            if len(items) != 1:
                return fail_upload(
                    "invalid_upload",
                    "Provide exactly one file field named `file`.",
                    400,
                    outcome="invalid_upload",
                )
            if not isinstance(items[0][1], StarletteUploadFile):
                return fail_upload(
                    "missing_file",
                    "The `file` field must contain one uploaded file.",
                    400,
                    outcome="missing_file",
                )
            upload = items[0][1]
            filename = _safe_filename(upload.filename)
            if filename is None:
                return fail_upload(
                    "invalid_filename",
                    "The uploaded file must have a usable filename.",
                    400,
                    outcome="invalid_filename",
                )

            with tempfile.TemporaryDirectory(prefix="tracee-upload-") as temporary_dir:
                temporary_path = Path(temporary_dir) / filename
                try:
                    with temporary_path.open("xb") as destination:
                        try:
                            set_private_permissions(temporary_path, 0o600)
                        except OSError:
                            logger.exception("Unable to secure staged upload permissions")
                            return fail_upload(
                                "storage_failure",
                                "The upload could not be staged safely.",
                                500,
                                outcome="storage_failure",
                                size_bytes=copied_size,
                            )
                        while chunk := await upload.read(UPLOAD_CHUNK_BYTES):
                            if copied_size + len(chunk) > max_bytes:
                                return fail_upload(
                                    "upload_too_large",
                                    "The upload exceeds the configured file size limit.",
                                    413,
                                    outcome="upload_too_large",
                                    size_bytes=copied_size,
                                )
                            destination.write(chunk)
                            copied_size += len(chunk)
                except OSError:
                    logger.exception("Unable to stage uploaded evidence")
                    return fail_upload(
                        "storage_failure",
                        "The upload could not be staged safely.",
                        500,
                        outcome="storage_failure",
                        size_bytes=copied_size,
                    )
                if copied_size == 0:
                    return fail_upload(
                        "empty_file",
                        "Empty evidence files are not accepted.",
                        400,
                        outcome="empty_file",
                        size_bytes=0,
                    )

                try:
                    metadata, chain_record = service.ingest(temporary_path)
                except DuplicateEvidenceError:
                    logger.info("Duplicate evidence upload rejected")
                    return fail_upload(
                        "duplicate_evidence",
                        "Evidence with the same SHA-256 digest already exists.",
                        409,
                        outcome="duplicate_evidence",
                        size_bytes=copied_size,
                        operation_outcome="failed",
                    )
                except (InvalidInputError, IngestionError):
                    logger.exception("Evidence upload failed during ingestion")
                    return fail_upload(
                        "ingestion_failed",
                        "Evidence could not be ingested. Check the local server logs.",
                        422,
                        outcome="ingestion_failed",
                        size_bytes=copied_size,
                        operation_outcome="failed",
                    )
                except (VaultError, MetadataError, ChainError):
                    logger.exception("Evidence upload failed due to vault storage")
                    return fail_upload(
                        "storage_failure",
                        "The vault could not persist this evidence safely.",
                        500,
                        outcome="storage_failure",
                        size_bytes=copied_size,
                        operation_outcome="failed",
                    )
                except Exception:
                    logger.exception("Unexpected evidence acquisition failure")
                    return fail_upload(
                        "internal_error",
                        "An unexpected internal error occurred.",
                        500,
                        outcome="internal_error",
                        size_bytes=copied_size,
                        operation_outcome="failed",
                    )

                try:
                    activity.append(
                        event_type="evidence_acquired",
                        actor="local_upload_token",
                        outcome="success",
                        evidence_id=metadata.evidence_id,
                        filename=metadata.original_filename,
                        size_bytes=metadata.size_bytes,
                        sha256=metadata.sha256,
                    )
                except ActivityLogError as exc:
                    logger.exception(
                        "Evidence was stored but acquisition completion activity could not be recorded"
                    )
                    if isinstance(exc, ActivityLogIntegrityError):
                        code = "activity_log_invalid"
                        message = "Evidence was stored, but the activity log failed integrity validation."
                        status_code = 500
                    else:
                        code = "activity_audit_failed"
                        message = "Evidence was stored, but its completion could not be audited."
                        status_code = 503
                    return JSONResponse(
                        status_code=status_code,
                        content={
                            "error": {"code": code, "message": message},
                            "operation": {
                                "completed": True,
                                "evidence_stored": True,
                                "evidence_id": metadata.evidence_id,
                            },
                            "audit": {"recorded": False},
                        },
                    )
                return {
                    "evidence_id": metadata.evidence_id,
                    "metadata": metadata.to_dict(),
                    "chain_sequence": chain_record.sequence,
                }
        finally:
            if form is not None:
                await form.close()

    @app.get(
        "/api/v1/activity",
        summary="List recent operational activity",
        description="Returns validated activity-log entries, newest first. Reading this endpoint is not itself logged.",
    )
    def list_activity(limit: int = Query(ACTIVITY_LIMIT_DEFAULT, ge=1, le=ACTIVITY_LIMIT_MAX)):
        service, error_response = service_or_error()
        if error_response:
            return error_response
        assert service is not None
        try:
            return {
                "activity": ActivityLog(service.vault_dir).recent(limit),
                "limit": limit,
            }
        except ActivityLogError as exc:
            return activity_failure(exc)

    # -------------------------------------------------------------------------
    # Integration: Dataset Replay, Adaptive mTLS Lab, Recovery Centre, Risk Engine
    # -------------------------------------------------------------------------
    from dataclasses import asdict
    from .dataset_replay import discover_dataset, validate_dataset_corpus, DatasetReplayController
    from .mtls_lab import MtlsSimulator, HopResult
    from .recovery import RecoveryStore
    from .classifier import IncidentRiskEngine, CorrelationEngine

    workspace_root = Path(__file__).resolve().parents[2]
    effective_vault = vault_dir if vault_dir else (workspace_root / "demo_vault")

    recovery_store = RecoveryStore(effective_vault)
    replay_controller = DatasetReplayController(workspace_root, effective_vault)
    mtls_sim = MtlsSimulator()
    risk_engine = IncidentRiskEngine()
    correlator = CorrelationEngine()

    @app.get("/api/v1/dataset/info")
    def get_dataset_info(request: Request):
        auth_error = _api_auth_error(request)
        if auth_error:
            return auth_error
        ds_dir = discover_dataset(workspace_root)
        if not ds_dir:
            return {"discovered": False, "message": "Dataset not found in workspace."}
        res = validate_dataset_corpus(ds_dir)
        res["discovered"] = True
        return res

    @app.get("/api/v1/dataset/replay/status")
    def get_replay_status(request: Request):
        auth_error = _api_auth_error(request)
        if auth_error:
            return auth_error
        return replay_controller.get_status()

    @app.post("/api/v1/dataset/replay/start")
    async def start_replay(request: Request):
        auth_error = _api_auth_error(request)
        if auth_error:
            return auth_error
        try:
            body = await request.json()
        except Exception:
            body = {}
        sources = body.get("sources")
        seed = int(body.get("seed", 42))
        record_limit = int(body.get("record_limit", 1000))
        batch_size = int(body.get("batch_size", 100))
        delay_ms = int(body.get("delay_ms", 50))

        def _on_batch(eid: str, parser_id: str):
            try:
                recovery_store.create_recovery_copy(eid)
            except Exception as exc:
                logger.warning("Recovery copy warning for %s: %s", eid, exc)

        res = replay_controller.start_replay(
            sources=sources,
            seed=seed,
            record_limit=record_limit,
            batch_size=batch_size,
            delay_ms=delay_ms,
            on_batch_complete=_on_batch,
        )
        return res

    @app.post("/api/v1/dataset/replay/pause")
    def pause_replay(request: Request):
        auth_error = _api_auth_error(request)
        if auth_error:
            return auth_error
        return replay_controller.pause_replay()

    @app.post("/api/v1/dataset/replay/resume")
    def resume_replay(request: Request):
        auth_error = _api_auth_error(request)
        if auth_error:
            return auth_error
        return replay_controller.resume_replay()

    @app.post("/api/v1/dataset/replay/stop")
    def stop_replay(request: Request):
        auth_error = _api_auth_error(request)
        if auth_error:
            return auth_error
        return replay_controller.stop_replay()

    @app.post("/api/v1/mtls/simulate")
    async def simulate_mtls(request: Request):
        auth_error = _api_auth_error(request)
        if auth_error:
            return auth_error
        try:
            body = await request.json()
        except Exception:
            body = {}
        profile = body.get("profile", "adaptive")
        risk_score = int(body.get("risk_score", 15))
        mismatch = bool(body.get("inject_cert_mismatch", False))
        seed = int(body.get("seed", 42))
        client_id = body.get("client_id", "client-service-mesh-01")

        result = mtls_sim.run_simulation(
            profile=profile,
            risk_score=risk_score,
            inject_cert_mismatch=mismatch,
            seed=seed,
            client_id=client_id,
        )
        return {
            "run_id": result.run_id,
            "profile": result.profile,
            "timestamp": result.timestamp,
            "seed": result.seed,
            "client_id": result.client_id,
            "session_id": result.session_id,
            "inject_cert_mismatch": result.inject_cert_mismatch,
            "risk_score": result.risk_score,
            "risk_band": result.risk_band,
            "total_latency_ms": result.total_latency_ms,
            "status": result.status,
            "context_evicted": result.context_evicted,
            "summary": result.summary,
            "hops": [asdict(h) for h in result.hops],
        }

    @app.get("/api/v1/mtls/compare")
    def compare_mtls(request: Request, risk_score: int = 15, seed: int = 42):
        auth_error = _api_auth_error(request)
        if auth_error:
            return auth_error
        return mtls_sim.run_profile_comparison(risk_score=risk_score, seed=seed)

    @app.post("/api/v1/mtls/calibrate")
    def calibrate_mtls(request: Request):
        auth_error = _api_auth_error(request)
        if auth_error:
            return auth_error
        return mtls_sim.run_local_tls_calibration()

    @app.post("/api/v1/mtls/export-evidence")
    async def export_mtls_evidence(request: Request):
        auth_error = _api_auth_error(request)
        if auth_error:
            return auth_error
        service, error_response = service_or_error()
        if error_response:
            return error_response
        assert service is not None

        try:
            body = await request.json()
        except Exception:
            body = {}
        profile = body.get("profile", "adaptive")
        risk_score = int(body.get("risk_score", 15))
        mismatch = bool(body.get("inject_cert_mismatch", False))
        seed = int(body.get("seed", 42))

        sim_res = mtls_sim.run_simulation(
            profile=profile,
            risk_score=risk_score,
            inject_cert_mismatch=mismatch,
            seed=seed,
        )
        jsonl_data = mtls_sim.export_telemetry_to_jsonl(sim_res).encode("utf-8")

        staging_dir = service.vault_dir / ".staging"
        staging_dir.mkdir(parents=True, exist_ok=True)
        fname = f"mtls_telemetry_{sim_res.run_id}.jsonl"
        tfile = staging_dir / fname
        tfile.write_bytes(jsonl_data)

        meta, _ = service.ingest(tfile)
        tfile.unlink(missing_ok=True)

        recovery_store.create_recovery_copy(meta.evidence_id)

        analysis_service = EvidenceAnalysisService(service)
        try:
            analysis_service.analyze(meta.evidence_id, "json_event")
        except Exception as p_err:
            logger.warning("mTLS analysis parsing warning: %s", p_err)

        return {
            "evidence_id": meta.evidence_id,
            "filename": fname,
            "sha256": meta.sha256,
            "run_id": sim_res.run_id,
            "message": "mTLS simulation telemetry ingested as evidence and parsed.",
        }

    # Recovery Centre routes
    @app.get("/api/v1/recovery/status")
    def get_recovery_status(request: Request):
        auth_error = _api_auth_error(request)
        if auth_error:
            return auth_error
        return recovery_store.get_recovery_status()

    @app.post("/api/v1/recovery/bootstrap")
    def bootstrap_recovery(request: Request):
        auth_error = _api_auth_error(request)
        if auth_error:
            return auth_error
        return recovery_store.bootstrap_recovery_store()

    @app.post("/api/v1/recovery/{evidence_id}/restore")
    def restore_evidence_endpoint(request: Request, evidence_id: str):
        auth_error = _api_auth_error(request)
        if auth_error:
            return auth_error
        return recovery_store.restore_evidence(evidence_id)

    @app.post("/api/v1/recovery/{evidence_id}/simulate-tamper")
    def simulate_tamper_endpoint(request: Request, evidence_id: str):
        auth_error = _api_auth_error(request)
        if auth_error:
            return auth_error
        return recovery_store.simulate_tamper(evidence_id)

    @app.post("/api/v1/recovery/{evidence_id}/simulate-missing")
    def simulate_missing_endpoint(request: Request, evidence_id: str):
        auth_error = _api_auth_error(request)
        if auth_error:
            return auth_error
        return recovery_store.simulate_missing(evidence_id)

    @app.post("/api/v1/recovery/demo-disposable")
    def demo_disposable_vault(request: Request):
        auth_error = _api_auth_error(request)
        if auth_error:
            return auth_error
        return RecoveryStore.run_disposable_vault_demo()

    def _collect_all_events() -> list[dict[str, Any]]:
        service, _ = service_or_error()
        if not service:
            return []
        analysis_service = EvidenceAnalysisService(service)
        all_events = []
        try:
            records = list(service.vault.records_dir.glob("*.json"))
            for rf in records:
                eid = rf.stem
                analyses, _ = analysis_service.list_analyses(eid, limit=5)
                for an in analyses:
                    an_id = an.get("analysis_id")
                    if an_id:
                        try:
                            full = analysis_service.load_analysis(eid, an_id)
                            ev_list = full.get("events", [])
                            for ev in ev_list:
                                ev["evidence_id"] = eid
                            all_events.extend(ev_list)
                        except Exception:
                            pass
        except Exception as e:
            logger.warning("Event collection warning: %s", e)
        return all_events

    @app.get("/api/v1/investigation/risk-score")
    def get_investigation_risk_score(request: Request):
        auth_error = _api_auth_error(request)
        if auth_error:
            return auth_error
        events = _collect_all_events()
        res = risk_engine.evaluate_incident(events)
        return asdict(res)

    @app.get("/api/v1/investigation/correlation-graph")
    def get_correlation_graph(request: Request, max_nodes: int = 12):
        auth_error = _api_auth_error(request)
        if auth_error:
            return auth_error
        events = _collect_all_events()
        return correlator.build_correlation_graph(events, max_nodes=max_nodes)


    ui_directory = Path(__file__).resolve().parents[2] / "ui"
    if ui_directory.is_dir():
        app.mount("/", StaticFiles(directory=ui_directory, html=True), name="ui")

    return app


app = create_app()
