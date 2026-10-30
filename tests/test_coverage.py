
"""Tests for TRACEE source coverage and missing-observation assessment."""

from datetime import datetime, timedelta, timezone

import pytest

from tracee.coverage import (
    CoverageInterval,
    CoverageStatus,
    ObservationAvailability,
    ObservationAssessment,
    SourceCoverage,
    assess_observation_availability,
)
from tracee.events import TemporalExtent
from tracee.models import ModelValidationError


EVIDENCE_ID = "TRACE-EV-000001"
UTC = timezone.utc


def instant(hour, minute=0):
    return datetime(2026, 10, 2, hour, minute, tzinfo=UTC)


def extent(start=1, end=2):
    return TemporalExtent(
        earliest_utc=instant(start),
        latest_utc=instant(end),
    )


def interval(start=0, end=4):
    return CoverageInterval(
        start_utc=instant(start),
        end_utc=instant(end),
    )


def make_coverage(**overrides):
    values = {
        "coverage_id": "coverage-001",
        "evidence_id": EVIDENCE_ID,
        "source_type": "linux_auth",
        "source_locator": "/var/log/auth.log",
        "status": CoverageStatus.KNOWN_COVERAGE,
        "intervals": (interval(),),
        "basis": "Documented acquisition and logging interval",
        "limitations": (),
    }
    values.update(overrides)
    return SourceCoverage(**values)


def assess(coverage, **overrides):
    values = {
        "assessment_id": "assessment-001",
        "expected_artifact_type": "authentication_record",
        "coverage": coverage,
        "expected_extent": extent(),
        "explanation": "Controlled test scenario",
    }
    values.update(overrides)
    return assess_observation_availability(**values)


def test_coverage_interval_normalizes_to_utc():
    offset = timezone(timedelta(hours=5, minutes=30))
    item = CoverageInterval(
        datetime(2026, 10, 2, 5, 30, tzinfo=offset),
        datetime(2026, 10, 2, 9, 30, tzinfo=offset),
    )

    assert item.start_utc == instant(0)
    assert item.end_utc == instant(4)


def test_naive_coverage_datetime_is_rejected():
    with pytest.raises(ModelValidationError):
        CoverageInterval(
            datetime(2026, 10, 2, 0),
            instant(4),
        )


def test_end_before_start_is_rejected():
    with pytest.raises(ModelValidationError):
        interval(start=4, end=0)


def test_known_coverage_requires_intervals():
    with pytest.raises(ModelValidationError):
        make_coverage(intervals=())


def test_unknown_coverage_cannot_claim_intervals():
    with pytest.raises(ModelValidationError):
        make_coverage(
            status=CoverageStatus.COVERAGE_UNKNOWN,
            intervals=(interval(),),
        )


def test_invalid_evidence_id_is_rejected():
    with pytest.raises(ModelValidationError):
        make_coverage(evidence_id="invalid")


def test_known_coverage_covers_extent():
    coverage = make_coverage()

    assert coverage.covers_extent(extent(1, 2))


def test_extent_outside_coverage_is_not_covered():
    coverage = make_coverage()

    assert not coverage.covers_extent(extent(5, 6))


def test_multiple_adjacent_intervals_cover_extent():
    coverage = make_coverage(
        status=CoverageStatus.PARTIAL_COVERAGE,
        intervals=(interval(0, 2), interval(2, 4)),
    )

    assert coverage.covers_extent(extent(1, 3))


def test_gap_between_intervals_does_not_count_as_coverage():
    coverage = make_coverage(
        status=CoverageStatus.PARTIAL_COVERAGE,
        intervals=(interval(0, 1), interval(3, 4)),
    )

    assert not coverage.covers_extent(extent(0, 4))


def test_unknown_time_extent_is_not_covered():
    coverage = make_coverage()

    assert not coverage.covers_extent(TemporalExtent())


def test_unknown_coverage_never_counts_as_covered():
    coverage = make_coverage(
        status=CoverageStatus.COVERAGE_UNKNOWN,
        intervals=(),
    )

    assert not coverage.covers_extent(extent())


def test_unavailable_source_never_counts_as_covered():
    coverage = make_coverage(
        status=CoverageStatus.SOURCE_UNAVAILABLE,
        intervals=(),
    )

    assert not coverage.covers_extent(extent())


def test_missing_record_with_known_coverage_is_not_observed():
    result = assess(make_coverage())

    assert (
        result.availability
        == ObservationAvailability.NOT_OBSERVED_WITH_KNOWN_COVERAGE
    )


def test_missing_record_with_unknown_coverage_is_unresolved():
    coverage = make_coverage(
        status=CoverageStatus.COVERAGE_UNKNOWN,
        intervals=(),
    )

    result = assess(coverage)

    assert (
        result.availability
        == ObservationAvailability.NOT_OBSERVED_WITH_UNKNOWN_COVERAGE
    )


def test_partial_coverage_outside_expected_interval_is_unresolved():
    coverage = make_coverage(
        status=CoverageStatus.PARTIAL_COVERAGE,
        intervals=(interval(0, 1),),
    )

    result = assess(coverage, expected_extent=extent(2, 3))

    assert (
        result.availability
        == ObservationAvailability.NOT_OBSERVED_WITH_UNKNOWN_COVERAGE
    )


def test_unavailable_source_has_distinct_result():
    coverage = make_coverage(
        status=CoverageStatus.SOURCE_UNAVAILABLE,
        intervals=(),
    )

    result = assess(coverage)

    assert (
        result.availability
        == ObservationAvailability.SOURCE_UNAVAILABLE
    )


def test_found_observation_is_recorded_as_observed():
    result = assess(
        make_coverage(),
        found_observation_ids=("obs-123",),
    )

    assert result.availability == ObservationAvailability.OBSERVED
    assert result.found_observation_ids == ("obs-123",)


def test_missing_record_alone_never_implies_removal():
    result = assess(make_coverage())

    assert (
        result.availability
        != ObservationAvailability
        .POSSIBLE_REMOVAL_WITH_SUPPORTING_INDICATORS
    )
    assert result.supporting_indicator_observation_ids == ()


def test_removal_assessment_requires_positive_indicator_ids():
    with pytest.raises(ModelValidationError):
        ObservationAssessment(
            assessment_id="assessment-001",
            expected_artifact_type="authentication_record",
            coverage_id="coverage-001",
            expected_extent=extent(),
            availability=(
                ObservationAvailability
                .POSSIBLE_REMOVAL_WITH_SUPPORTING_INDICATORS
            ),
            explanation="No independent indicators supplied",
        )


def test_possible_removal_requires_covered_interval_and_indicators():
    result = assess(
        make_coverage(),
        supporting_indicator_observation_ids=("obs-truncation-1",),
    )

    assert (
        result.availability
        == ObservationAvailability
        .POSSIBLE_REMOVAL_WITH_SUPPORTING_INDICATORS
    )
    assert result.supporting_indicator_observation_ids == (
        "obs-truncation-1",
    )


def test_indicators_do_not_override_unknown_coverage():
    coverage = make_coverage(
        status=CoverageStatus.COVERAGE_UNKNOWN,
        intervals=(),
    )

    result = assess(
        coverage,
        supporting_indicator_observation_ids=("obs-truncation-1",),
    )

    assert (
        result.availability
        == ObservationAvailability.NOT_OBSERVED_WITH_UNKNOWN_COVERAGE
    )


def test_assessment_serialization_preserves_state_and_references():
    result = assess(
        make_coverage(),
        supporting_indicator_observation_ids=("obs-indicator-1",),
    )

    serialized = result.to_dict()

    assert serialized["coverage_id"] == "coverage-001"
    assert serialized["availability"] == (
        "possible_removal_with_supporting_indicators"
    )
    assert serialized["supporting_indicator_observation_ids"] == [
        "obs-indicator-1"
    ]
def test_assessment_scope_attributes_are_preserved():
    result = ObservationAssessment(
        assessment_id="assessment-scope-1",
        expected_artifact_type="authentication_record",
        coverage_id="coverage-001",
        expected_extent=extent(),
        availability=ObservationAvailability.OBSERVED,
        scope_attributes={"user": "alice", "host": "server-01"},
        found_observation_ids=("obs-123",),
        explanation="Scoped authentication record",
    )

    assert result.scope_attributes["user"] == "alice"
    assert result.scope_attributes["host"] == "server-01"
    assert result.to_dict()["scope_attributes"] == {
        "user": "alice",
        "host": "server-01",
    }


def test_assessment_scope_attributes_are_immutable():
    result = ObservationAssessment(
        assessment_id="assessment-scope-2",
        expected_artifact_type="authentication_record",
        coverage_id="coverage-001",
        expected_extent=extent(),
        availability=ObservationAvailability.OBSERVED,
        scope_attributes={"user": "alice"},
        found_observation_ids=("obs-123",),
        explanation="Scoped authentication record",
    )

    with pytest.raises(TypeError):
        result.scope_attributes["user"] = "mallory"


def test_assessment_scope_rejects_non_string_keys():
    with pytest.raises(ModelValidationError):
        ObservationAssessment(
            assessment_id="assessment-scope-3",
            expected_artifact_type="authentication_record",
            coverage_id="coverage-001",
            expected_extent=extent(),
            availability=ObservationAvailability.OBSERVED,
            scope_attributes={1: "alice"},
            found_observation_ids=("obs-123",),
            explanation="Invalid scope",
        )
