"""Tests for TRACEE event and observation models."""

from datetime import datetime, timedelta, timezone

import pytest

from tracee.events import (
    NormalizedEvent,
    ParseStatus,
    SourceObservation,
    TemporalExtent,
    TimestampInfo,
    TimestampPrecision,
    TimezoneStatus,
)
from tracee.models import ModelValidationError


EVIDENCE_ID = "TRACE-EV-000001"


def make_timestamp(**overrides):
    values = {
        "raw_value": "2026-10-02T04:35:22Z",
        "raw_format": "ISO-8601",
        "timezone_status": TimezoneStatus.KNOWN,
        "precision": TimestampPrecision.SECOND,
        "normalized_extent": TemporalExtent(),
    }
    values.update(overrides)
    return TimestampInfo(**values)


def make_observation(**overrides):
    values = {
        "observation_id": "obs-001",
        "evidence_id": EVIDENCE_ID,
        "source_type": "linux_auth",
        "source_locator": "auth.log:42",
        "parser_name": "auth_log",
        "parser_version": "1.0",
        "timestamp": make_timestamp(),
        "attributes": {
            "user": "alice",
            "process": {"pid": 1234},
            "tags": ["ssh", "authentication"],
        },
        "parse_status": ParseStatus.PARSED,
        "parse_errors": (),
    }
    values.update(overrides)
    return SourceObservation(**values)


def make_event(**overrides):
    values = {
        "event_id": "event-001",
        "event_type": "authentication_attempt",
        "source_observation_ids": ("obs-001",),
        "normalizer_name": "linux_auth_normalizer",
        "normalizer_version": "1.0",
        "attributes": {"user": "alice"},
        "temporal_extent": TemporalExtent(),
    }
    values.update(overrides)
    return NormalizedEvent(**values)


def test_unknown_temporal_extent_is_preserved():
    extent = TemporalExtent()

    assert extent.earliest_utc is None
    assert extent.latest_utc is None


def test_naive_datetime_is_rejected():
    with pytest.raises(ModelValidationError):
        TemporalExtent(
            earliest_utc=datetime(2026, 10, 2, 4, 35, 22)
        )


def test_timezone_aware_datetime_is_normalized_to_utc():
    original = datetime(
        2026, 10, 2, 10, 5, 22,
        tzinfo=timezone(timedelta(hours=5, minutes=30)),
    )

    extent = TemporalExtent(original, original)

    expected = datetime(
        2026, 10, 2, 4, 35, 22,
        tzinfo=timezone.utc,
    )

    assert extent.earliest_utc == expected
    assert extent.latest_utc == expected


def test_latest_time_cannot_precede_earliest_time():
    with pytest.raises(ModelValidationError):
        TemporalExtent(
            earliest_utc=datetime(
                2026, 10, 2, 5, tzinfo=timezone.utc
            ),
            latest_utc=datetime(
                2026, 10, 2, 4, tzinfo=timezone.utc
            ),
        )


def test_missing_timestamp_does_not_assume_timezone():
    timestamp = TimestampInfo()

    assert timestamp.raw_value is None
    assert timestamp.timezone_status is TimezoneStatus.NOT_PRESENT
    assert timestamp.precision is TimestampPrecision.UNKNOWN


def test_unknown_timezone_is_preserved():
    timestamp = make_timestamp(
        raw_value="2026-10-02 04:35:22",
        timezone_status=TimezoneStatus.UNKNOWN,
    )

    assert timestamp.raw_value == "2026-10-02 04:35:22"
    assert timestamp.timezone_status is TimezoneStatus.UNKNOWN


def test_inconsistent_missing_timestamp_is_rejected():
    with pytest.raises(ModelValidationError):
        TimestampInfo(timezone_status=TimezoneStatus.KNOWN)


def test_valid_observation_is_created():
    observation = make_observation()

    assert observation.observation_id == "obs-001"
    assert observation.evidence_id == EVIDENCE_ID
    assert observation.parse_status is ParseStatus.PARSED


def test_invalid_evidence_id_is_rejected():
    with pytest.raises(ModelValidationError):
        make_observation(evidence_id="invalid-id")


def test_failed_parse_requires_explanation():
    with pytest.raises(ModelValidationError):
        make_observation(
            parse_status=ParseStatus.FAILED,
            parse_errors=(),
        )


def test_failed_parse_preserves_error():
    observation = make_observation(
        parse_status=ParseStatus.FAILED,
        parse_errors=("Invalid record format",),
    )

    assert observation.parse_errors == ("Invalid record format",)
    assert observation.to_dict()["parse_errors"] == [
        "Invalid record format"
    ]


def test_unsupported_parse_requires_explanation():
    with pytest.raises(ModelValidationError):
        make_observation(parse_status=ParseStatus.UNSUPPORTED)


def test_invalid_attribute_values_are_rejected():
    with pytest.raises(ModelValidationError):
        make_observation(attributes={"value": float("nan")})

    with pytest.raises(ModelValidationError):
        make_observation(attributes={"value": {1, 2, 3}})


def test_observation_attributes_are_immutable():
    observation = make_observation()

    with pytest.raises(TypeError):
        observation.attributes["user"] = "mallory"

    with pytest.raises(TypeError):
        observation.attributes["process"]["pid"] = 9999

    with pytest.raises(AttributeError):
        observation.attributes["tags"].append("modified")


def test_serialization_returns_independent_attribute_data():
    observation = make_observation()
    result = observation.to_dict()

    assert result["attributes"]["process"]["pid"] == 1234

    result["attributes"]["user"] = "mallory"

    assert observation.attributes["user"] == "alice"


def test_normalized_event_requires_observation_reference():
    with pytest.raises(ModelValidationError):
        make_event(source_observation_ids=())


def test_duplicate_observation_references_are_rejected():
    with pytest.raises(ModelValidationError):
        make_event(
            source_observation_ids=("obs-001", "obs-001")
        )


def test_normalized_event_preserves_provenance():
    event = make_event()
    result = event.to_dict()

    assert result["source_observation_ids"] == ["obs-001"]
    assert result["event_type"] == "authentication_attempt"


def test_normalized_event_attributes_are_immutable():
    event = make_event(attributes={"process": {"pid": 1234}})

    with pytest.raises(TypeError):
        event.attributes["process"]["pid"] = 9999
