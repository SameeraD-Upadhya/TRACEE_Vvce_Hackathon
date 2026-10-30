"""
TRACEE Event and Observation Models.

Defines immutable records for source observations, timestamp information,
temporal extents, and normalized events.

This module performs data validation only. It does not parse evidence,
store evidence, infer causality, or reconstruct incident timelines.
"""

from __future__ import annotations

import math
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from types import MappingProxyType
from typing import Any, Mapping

from .ids import is_valid_evidence_id
from .models import ModelValidationError


OBSERVATION_SCHEMA_VERSION = "1.0"
EVENT_SCHEMA_VERSION = "1.0"


class ParseStatus(str, Enum):
    """Outcome of processing a source record."""

    PARSED = "parsed"
    PARTIAL = "partial"
    FAILED = "failed"
    UNSUPPORTED = "unsupported"


class TimezoneStatus(str, Enum):
    """Knowledge about the timezone of the original timestamp."""

    KNOWN = "known"
    UNKNOWN = "unknown"
    NOT_PRESENT = "not_present"


class TimestampPrecision(str, Enum):
    """Known precision of an original timestamp."""

    YEAR = "year"
    MONTH = "month"
    DAY = "day"
    HOUR = "hour"
    MINUTE = "minute"
    SECOND = "second"
    MILLISECOND = "millisecond"
    MICROSECOND = "microsecond"
    UNKNOWN = "unknown"


def _require_text(value: str, field_name: str) -> None:
    """Reject empty or whitespace-only required strings."""

    if not isinstance(value, str) or not value.strip():
        raise ModelValidationError(
            f"{field_name} must be a non-empty string"
        )


def _freeze_json(value: Any, path: str = "attributes") -> Any:
    """
    Validate JSON-compatible data and recursively freeze containers.

    Objects become read-only mappings and arrays become tuples. This prevents
    callers from changing nested attribute values after model creation.
    """

    if isinstance(value, Mapping):
        frozen: dict[str, Any] = {}

        for key, item in value.items():
            if not isinstance(key, str):
                raise ModelValidationError(
                    f"{path} keys must be strings"
                )

            frozen[key] = _freeze_json(item, f"{path}.{key}")

        return MappingProxyType(frozen)

    if isinstance(value, (list, tuple)):
        return tuple(
            _freeze_json(item, f"{path}[{index}]")
            for index, item in enumerate(value)
        )

    if value is None or isinstance(value, (str, bool, int)):
        return value

    if isinstance(value, float) and math.isfinite(value):
        return value

    raise ModelValidationError(
        f"{path} contains a value that is not valid JSON data"
    )


def _thaw_json(value: Any) -> Any:
    """Convert frozen attribute containers into ordinary JSON structures."""

    if isinstance(value, Mapping):
        return {
            key: _thaw_json(item)
            for key, item in value.items()
        }

    if isinstance(value, tuple):
        return [_thaw_json(item) for item in value]

    return value


def _datetime_to_iso(value: datetime | None) -> str | None:
    """Serialize a normalized timestamp as an ISO-8601 UTC string."""

    if value is None:
        return None

    return (
        value.astimezone(timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )


@dataclass(frozen=True)
class TemporalExtent:
    """
    A time point or bounded time interval represented in UTC.

    Either bound may be unknown. A present bound must be timezone-aware.
    Two absent bounds represent unresolved timing.

    These bounds express temporal information, not causality.
    """

    earliest_utc: datetime | None = None
    latest_utc: datetime | None = None

    def __post_init__(self) -> None:
        earliest = self.earliest_utc
        latest = self.latest_utc

        for name, value in (
            ("earliest_utc", earliest),
            ("latest_utc", latest),
        ):
            if value is None:
                continue

            if not isinstance(value, datetime):
                raise ModelValidationError(
                    f"{name} must be a datetime or None"
                )

            if value.tzinfo is None or value.utcoffset() is None:
                raise ModelValidationError(
                    f"{name} must be timezone-aware; "
                    "naive timestamps cannot be treated as UTC"
                )

        if earliest is not None:
            object.__setattr__(
                self,
                "earliest_utc",
                earliest.astimezone(timezone.utc),
            )

        if latest is not None:
            object.__setattr__(
                self,
                "latest_utc",
                latest.astimezone(timezone.utc),
            )

        if (
            self.earliest_utc is not None
            and self.latest_utc is not None
            and self.latest_utc < self.earliest_utc
        ):
            raise ModelValidationError(
                "latest_utc must not precede earliest_utc"
            )

    def to_dict(self) -> dict[str, str | None]:
        """Return a JSON-compatible representation."""

        return {
            "earliest_utc": _datetime_to_iso(self.earliest_utc),
            "latest_utc": _datetime_to_iso(self.latest_utc),
        }


@dataclass(frozen=True)
class TimestampInfo:
    """
    Preserve an original timestamp and any justified normalized bounds.

    The original timestamp is retained even when its timezone or precision
    is unknown. Normalized bounds must be explicitly supplied and timezone
    aware; this model never guesses a timezone.
    """

    raw_value: str | None = None
    raw_format: str | None = None
    timezone_status: TimezoneStatus = TimezoneStatus.NOT_PRESENT
    precision: TimestampPrecision = TimestampPrecision.UNKNOWN
    normalized_extent: TemporalExtent = field(
        default_factory=TemporalExtent
    )

    def __post_init__(self) -> None:
        if not isinstance(self.timezone_status, TimezoneStatus):
            raise ModelValidationError(
                "timezone_status must be a TimezoneStatus value"
            )

        if not isinstance(self.precision, TimestampPrecision):
            raise ModelValidationError(
                "precision must be a TimestampPrecision value"
            )

        if not isinstance(self.normalized_extent, TemporalExtent):
            raise ModelValidationError(
                "normalized_extent must be a TemporalExtent"
            )

        if self.raw_value is not None:
            _require_text(self.raw_value, "raw_value")

            if self.timezone_status == TimezoneStatus.NOT_PRESENT:
                raise ModelValidationError(
                    "A present raw timestamp must have timezone_status "
                    "KNOWN or UNKNOWN"
                )

        else:
            if self.raw_format is not None:
                raise ModelValidationError(
                    "raw_format cannot be supplied without raw_value"
                )

            if self.timezone_status != TimezoneStatus.NOT_PRESENT:
                raise ModelValidationError(
                    "A missing raw timestamp must use "
                    "timezone_status NOT_PRESENT"
                )

            if self.precision != TimestampPrecision.UNKNOWN:
                raise ModelValidationError(
                    "A missing raw timestamp must use UNKNOWN precision"
                )

            if (
                self.normalized_extent.earliest_utc is not None
                or self.normalized_extent.latest_utc is not None
            ):
                raise ModelValidationError(
                    "A source timestamp without a raw value cannot "
                    "supply normalized bounds in TimestampInfo"
                )

        if self.raw_format is not None:
            _require_text(self.raw_format, "raw_format")

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible timestamp representation."""

        return {
            "raw_value": self.raw_value,
            "raw_format": self.raw_format,
            "timezone_status": self.timezone_status.value,
            "precision": self.precision.value,
            "normalized_extent": self.normalized_extent.to_dict(),
        }


@dataclass(frozen=True)
class SourceObservation:
    """
    One observation extracted from a particular evidence location.

    evidence_id and source_locator provide the reference back to preserved
    evidence. Attributes contain extracted values, not inferred conclusions.
    """

    observation_id: str
    evidence_id: str
    source_type: str
    source_locator: str
    parser_name: str
    parser_version: str

    timestamp: TimestampInfo = field(default_factory=TimestampInfo)
    attributes: Mapping[str, Any] = field(default_factory=dict)
    parse_status: ParseStatus = ParseStatus.PARSED
    parse_errors: tuple[str, ...] = ()
    schema_version: str = OBSERVATION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        required_strings = (
            ("observation_id", self.observation_id),
            ("source_type", self.source_type),
            ("source_locator", self.source_locator),
            ("parser_name", self.parser_name),
            ("parser_version", self.parser_version),
            ("schema_version", self.schema_version),
        )

        for name, value in required_strings:
            _require_text(value, name)

        if not is_valid_evidence_id(self.evidence_id):
            raise ModelValidationError(
                f"Invalid evidence ID: {self.evidence_id!r}"
            )

        if not isinstance(self.timestamp, TimestampInfo):
            raise ModelValidationError(
                "timestamp must be a TimestampInfo instance"
            )

        if not isinstance(self.parse_status, ParseStatus):
            raise ModelValidationError(
                "parse_status must be a ParseStatus value"
            )

        if not isinstance(self.attributes, Mapping):
            raise ModelValidationError(
                "attributes must be a mapping"
            )

        frozen_attributes = _freeze_json(self.attributes)

        object.__setattr__(self, "attributes", frozen_attributes)

        if isinstance(self.parse_errors, str):
            raise ModelValidationError(
                "parse_errors must be a sequence of strings"
            )

        try:
            errors = tuple(self.parse_errors)
        except TypeError as exc:
            raise ModelValidationError(
                "parse_errors must be a sequence of strings"
            ) from exc

        for error in errors:
            _require_text(error, "parse_errors entry")

        object.__setattr__(self, "parse_errors", errors)

        if (
            self.parse_status in (ParseStatus.FAILED, ParseStatus.UNSUPPORTED)
            and not self.parse_errors
        ):
            raise ModelValidationError(
                "FAILED and UNSUPPORTED observations require "
                "at least one explanatory parse error"
            )

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible observation record."""

        return {
            "schema_version": self.schema_version,
            "observation_id": self.observation_id,
            "evidence_id": self.evidence_id,
            "source_type": self.source_type,
            "source_locator": self.source_locator,
            "parser_name": self.parser_name,
            "parser_version": self.parser_version,
            "timestamp": self.timestamp.to_dict(),
            "attributes": _thaw_json(self.attributes),
            "parse_status": self.parse_status.value,
            "parse_errors": list(self.parse_errors),
        }


@dataclass(frozen=True)
class NormalizedEvent:
    """
    A normalized event linked to one or more source observations.

    This model represents a normalized event record. It does not by itself
    assert that an inferred high-level event occurred or establish causality.
    """

    event_id: str
    event_type: str
    source_observation_ids: tuple[str, ...]
    normalizer_name: str
    normalizer_version: str

    attributes: Mapping[str, Any] = field(default_factory=dict)
    temporal_extent: TemporalExtent = field(
        default_factory=TemporalExtent
    )
    schema_version: str = EVENT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        required_strings = (
            ("event_id", self.event_id),
            ("event_type", self.event_type),
            ("normalizer_name", self.normalizer_name),
            ("normalizer_version", self.normalizer_version),
            ("schema_version", self.schema_version),
        )

        for name, value in required_strings:
            _require_text(value, name)

        if isinstance(self.source_observation_ids, str):
            raise ModelValidationError(
                "source_observation_ids must be a sequence of identifiers"
            )

        try:
            observation_ids = tuple(self.source_observation_ids)
        except TypeError as exc:
            raise ModelValidationError(
                "source_observation_ids must be a sequence of identifiers"
            ) from exc

        if not observation_ids:
            raise ModelValidationError(
                "A normalized event requires at least one source observation"
            )

        for observation_id in observation_ids:
            _require_text(observation_id, "source observation ID")

        if len(set(observation_ids)) != len(observation_ids):
            raise ModelValidationError(
                "source_observation_ids must not contain duplicates"
            )

        object.__setattr__(
            self,
            "source_observation_ids",
            observation_ids,
        )

        if not isinstance(self.attributes, Mapping):
            raise ModelValidationError(
                "attributes must be a mapping"
            )

        object.__setattr__(
            self,
            "attributes",
            _freeze_json(self.attributes),
        )

        if not isinstance(self.temporal_extent, TemporalExtent):
            raise ModelValidationError(
                "temporal_extent must be a TemporalExtent instance"
            )

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible normalized event."""

        return {
            "schema_version": self.schema_version,
            "event_id": self.event_id,
            "event_type": self.event_type,
            "source_observation_ids": list(self.source_observation_ids),
            "normalizer_name": self.normalizer_name,
            "normalizer_version": self.normalizer_version,
            "attributes": _thaw_json(self.attributes),
            "temporal_extent": self.temporal_extent.to_dict(),
        }
