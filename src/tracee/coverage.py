
"""
TRACEE Source Coverage and Observation Availability Models.

Defines explicit source-coverage intervals and conservative assessments
of whether an expected artifact was observed.

This module does not infer malicious intent or prove that an artifact
was deliberately deleted.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
import math
from types import MappingProxyType
from typing import Any, Iterable, Mapping

from .events import TemporalExtent
from .ids import is_valid_evidence_id
from .models import ModelValidationError


COVERAGE_SCHEMA_VERSION = "1.0"
ASSESSMENT_SCHEMA_VERSION = "1.0"


class CoverageStatus(str, Enum):
    """Known state of a source's coverage."""

    KNOWN_COVERAGE = "known_coverage"
    PARTIAL_COVERAGE = "partial_coverage"
    COVERAGE_UNKNOWN = "coverage_unknown"
    SOURCE_UNAVAILABLE = "source_unavailable"


class ObservationAvailability(str, Enum):
    """Outcome of assessing an expected observation."""

    OBSERVED = "observed"
    NOT_OBSERVED_WITH_KNOWN_COVERAGE = (
        "not_observed_with_known_coverage"
    )
    NOT_OBSERVED_WITH_UNKNOWN_COVERAGE = (
        "not_observed_with_unknown_coverage"
    )
    SOURCE_UNAVAILABLE = "source_unavailable"
    POSSIBLE_REMOVAL_WITH_SUPPORTING_INDICATORS = (
        "possible_removal_with_supporting_indicators"
    )


def _require_text(value: str, field_name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ModelValidationError(
            f"{field_name} must be a non-empty string"
        )


def _utc_datetime(value: datetime, field_name: str) -> datetime:
    if not isinstance(value, datetime):
        raise ModelValidationError(
            f"{field_name} must be a datetime"
        )

    if value.tzinfo is None or value.utcoffset() is None:
        raise ModelValidationError(
            f"{field_name} must be timezone-aware"
        )

    return value.astimezone(timezone.utc)


def _iso_utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace(
        "+00:00", "Z"
    )


def _freeze_json(value: Any, path: str = "scope_attributes") -> Any:
    """Validate and recursively freeze JSON-compatible scope data."""
    if isinstance(value, Mapping):
        frozen = {}
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
    """Convert frozen scope data to dictionaries and lists."""
    if isinstance(value, Mapping):
        return {
            key: _thaw_json(item)
            for key, item in value.items()
        }
    if isinstance(value, tuple):
        return [_thaw_json(item) for item in value]
    return value


def _unique_text_tuple(
    values: Iterable[str],
    field_name: str,
) -> tuple[str, ...]:
    if isinstance(values, str):
        raise ModelValidationError(
            f"{field_name} must be a sequence of strings"
        )

    try:
        result = tuple(values)
    except TypeError as exc:
        raise ModelValidationError(
            f"{field_name} must be a sequence of strings"
        ) from exc

    for value in result:
        _require_text(value, f"{field_name} entry")

    if len(result) != len(set(result)):
        raise ModelValidationError(
            f"{field_name} must not contain duplicate entries"
        )

    return result


@dataclass(frozen=True)
class CoverageInterval:
    """
    A bounded interval during which source coverage is documented.

    The endpoints are inclusive and normalized to UTC. These intervals
    represent declared coverage, not proof that every conceivable event
    would have generated an artifact.
    """

    start_utc: datetime
    end_utc: datetime

    def __post_init__(self) -> None:
        start = _utc_datetime(self.start_utc, "start_utc")
        end = _utc_datetime(self.end_utc, "end_utc")

        if end < start:
            raise ModelValidationError(
                "end_utc must not precede start_utc"
            )

        object.__setattr__(self, "start_utc", start)
        object.__setattr__(self, "end_utc", end)

    def to_dict(self) -> dict[str, str]:
        return {
            "start_utc": _iso_utc(self.start_utc),
            "end_utc": _iso_utc(self.end_utc),
        }


@dataclass(frozen=True)
class SourceCoverage:
    """
    A documented coverage declaration for one evidence source.

    KNOWN_COVERAGE means the listed intervals are declared fully covered
    within the relevant scope. PARTIAL_COVERAGE means only the listed
    intervals are known to be covered. Gaps are not assumed to be covered.
    """

    coverage_id: str
    evidence_id: str
    source_type: str
    source_locator: str
    status: CoverageStatus

    intervals: tuple[CoverageInterval, ...] = ()
    basis: str = ""
    limitations: tuple[str, ...] = ()
    schema_version: str = COVERAGE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        for name in (
            "coverage_id",
            "source_type",
            "source_locator",
            "basis",
            "schema_version",
        ):
            _require_text(getattr(self, name), name)

        if not is_valid_evidence_id(self.evidence_id):
            raise ModelValidationError(
                f"Invalid evidence ID: {self.evidence_id!r}"
            )

        if not isinstance(self.status, CoverageStatus):
            raise ModelValidationError(
                "status must be a CoverageStatus value"
            )

        if isinstance(self.intervals, (str, bytes)):
            raise ModelValidationError(
                "intervals must be a sequence of CoverageInterval values"
            )

        try:
            intervals = tuple(self.intervals)
        except TypeError as exc:
            raise ModelValidationError(
                "intervals must be a sequence of CoverageInterval values"
            ) from exc

        for interval in intervals:
            if not isinstance(interval, CoverageInterval):
                raise ModelValidationError(
                    "Every interval must be a CoverageInterval"
                )

        if self.status in (
            CoverageStatus.KNOWN_COVERAGE,
            CoverageStatus.PARTIAL_COVERAGE,
        ) and not intervals:
            raise ModelValidationError(
                f"{self.status.value} requires at least one "
                "documented interval"
            )

        if self.status in (
            CoverageStatus.COVERAGE_UNKNOWN,
            CoverageStatus.SOURCE_UNAVAILABLE,
        ) and intervals:
            raise ModelValidationError(
                f"{self.status.value} must not claim covered intervals"
            )

        object.__setattr__(
            self,
            "intervals",
            tuple(sorted(intervals, key=lambda item: item.start_utc)),
        )

        object.__setattr__(
            self,
            "limitations",
            _unique_text_tuple(self.limitations, "limitations"),
        )

    def covers_extent(self, extent: TemporalExtent) -> bool:
        """
        Return whether documented intervals cover the entire time extent.

        Unknown time bounds, unknown coverage, and unavailable sources
        never count as sufficient coverage.
        """

        if not isinstance(extent, TemporalExtent):
            raise ModelValidationError(
                "extent must be a TemporalExtent"
            )

        if self.status not in (
            CoverageStatus.KNOWN_COVERAGE,
            CoverageStatus.PARTIAL_COVERAGE,
        ):
            return False

        earliest = extent.earliest_utc
        latest = extent.latest_utc

        if earliest is None or latest is None:
            return False

        cursor = earliest

        for interval in self.intervals:
            if interval.end_utc < cursor:
                continue

            if interval.start_utc > cursor:
                return False

            if interval.end_utc >= latest:
                return True

            cursor = interval.end_utc

        return False

    def to_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "coverage_id": self.coverage_id,
            "evidence_id": self.evidence_id,
            "source_type": self.source_type,
            "source_locator": self.source_locator,
            "status": self.status.value,
            "intervals": [
                interval.to_dict() for interval in self.intervals
            ],
            "basis": self.basis,
            "limitations": list(self.limitations),
        }


@dataclass(frozen=True)
class ObservationAssessment:
    """A traceable assessment of an expected artifact."""

    assessment_id: str
    expected_artifact_type: str
    coverage_id: str
    expected_extent: TemporalExtent
    availability: ObservationAvailability
    scope_attributes: Mapping[str, Any] = field(default_factory=dict)

    found_observation_ids: tuple[str, ...] = ()
    supporting_indicator_observation_ids: tuple[str, ...] = ()
    explanation: str = ""
    schema_version: str = ASSESSMENT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        for name in (
            "assessment_id",
            "expected_artifact_type",
            "coverage_id",
            "explanation",
            "schema_version",
        ):
            _require_text(getattr(self, name), name)

        if not isinstance(self.expected_extent, TemporalExtent):
            raise ModelValidationError(
                "expected_extent must be a TemporalExtent"
            )

        if not isinstance(self.availability, ObservationAvailability):
            raise ModelValidationError(
                "availability must be an ObservationAvailability value"
            )

        if not isinstance(self.scope_attributes, Mapping):
            raise ModelValidationError(
                "scope_attributes must be a mapping"
            )

        object.__setattr__(
            self,
            "scope_attributes",
            _freeze_json(self.scope_attributes),
        )

        found = _unique_text_tuple(
            self.found_observation_ids,
            "found_observation_ids",
        )
        indicators = _unique_text_tuple(
            self.supporting_indicator_observation_ids,
            "supporting_indicator_observation_ids",
        )

        if self.availability == ObservationAvailability.OBSERVED:
            if not found:
                raise ModelValidationError(
                    "OBSERVED requires at least one observation ID"
                )
        elif found:
            raise ModelValidationError(
                "A not-observed assessment must not contain found IDs"
            )

        if (
            self.availability
            == ObservationAvailability.POSSIBLE_REMOVAL_WITH_SUPPORTING_INDICATORS
            and not indicators
        ):
            raise ModelValidationError(
                "Possible removal requires positive indicator observation IDs"
            )

        object.__setattr__(self, "found_observation_ids", found)
        object.__setattr__(
            self,
            "supporting_indicator_observation_ids",
            indicators,
        )

    def to_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "assessment_id": self.assessment_id,
            "expected_artifact_type": self.expected_artifact_type,
            "coverage_id": self.coverage_id,
            "expected_extent": self.expected_extent.to_dict(),
            "scope_attributes": _thaw_json(self.scope_attributes),
            "availability": self.availability.value,
            "found_observation_ids": list(self.found_observation_ids),
            "supporting_indicator_observation_ids": list(
                self.supporting_indicator_observation_ids
            ),
            "explanation": self.explanation,
        }


def assess_observation_availability(
    *,
    assessment_id: str,
    expected_artifact_type: str,
    coverage: SourceCoverage,
    expected_extent: TemporalExtent,
    found_observation_ids: Iterable[str] = (),
    supporting_indicator_observation_ids: Iterable[str] = (),
    explanation: str,
) -> ObservationAssessment:
    """
    Build an assessment using conservative, explicit rules.

    Missing data alone never generates a possible-removal assessment.
    A possible-removal result requires indicator observation IDs and a
    documented coverage interval spanning the expected time extent.
    """

    found = _unique_text_tuple(
        found_observation_ids,
        "found_observation_ids",
    )
    indicators = _unique_text_tuple(
        supporting_indicator_observation_ids,
        "supporting_indicator_observation_ids",
    )

    if found:
        availability = ObservationAvailability.OBSERVED
    elif coverage.status == CoverageStatus.SOURCE_UNAVAILABLE:
        availability = ObservationAvailability.SOURCE_UNAVAILABLE
    elif coverage.covers_extent(expected_extent):
        if indicators:
            availability = (
                ObservationAvailability
                .POSSIBLE_REMOVAL_WITH_SUPPORTING_INDICATORS
            )
        else:
            availability = (
                ObservationAvailability.NOT_OBSERVED_WITH_KNOWN_COVERAGE
            )
    else:
        availability = (
            ObservationAvailability.NOT_OBSERVED_WITH_UNKNOWN_COVERAGE
        )

    return ObservationAssessment(
        assessment_id=assessment_id,
        expected_artifact_type=expected_artifact_type,
        coverage_id=coverage.coverage_id,
        expected_extent=expected_extent,
        availability=availability,
        found_observation_ids=found,
        supporting_indicator_observation_ids=indicators,
        explanation=explanation,
    )
