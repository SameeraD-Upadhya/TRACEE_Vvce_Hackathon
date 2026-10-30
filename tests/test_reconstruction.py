"""Tests for TRACEE's deterministic reconstruction engine."""

from datetime import datetime, timedelta, timezone

import pytest

from tracee.coverage import (
    CoverageInterval,
    CoverageStatus,
    ObservationAssessment,
    ObservationAvailability,
    SourceCoverage,
)
from tracee.events import (
    ParseStatus,
    SourceObservation,
    TemporalExtent,
    TimestampInfo,
    TimestampPrecision,
    TimezoneStatus,
)
from tracee.hypotheses import InferenceRule, InterpretationState
from tracee.inference import evaluate_candidate_hypothesis
from tracee.models import ModelValidationError
from tracee.reconstruction import reconstruct


EVIDENCE_ID = "TRACE-EV-000001"
UTC = timezone.utc


def timestamp(hour=None, minute=0, second=0, precision=TimestampPrecision.MINUTE):
    if hour is None:
        return TimestampInfo()

    instant = datetime(
        2026, 10, 2, hour, minute, second, tzinfo=UTC
    )
    return TimestampInfo(
        raw_value=instant.isoformat(),
        raw_format="ISO-8601",
        timezone_status=TimezoneStatus.KNOWN,
        precision=precision,
        normalized_extent=TemporalExtent(instant, instant),
    )


def observation(
    identifier,
    *,
    user="alice",
    hour=1,
    minute=0,
    second=0,
    timestamp_precision=TimestampPrecision.MINUTE,
    source_type="linux_auth",
    parse_status=ParseStatus.PARSED,
    parse_errors=(),
    extra_attributes=None,
):
    attributes = {"user": user}
    if extra_attributes:
        attributes.update(extra_attributes)

    return SourceObservation(
        observation_id=identifier,
        evidence_id=EVIDENCE_ID,
        source_type=source_type,
        source_locator=f"test-source:{identifier}",
        parser_name="test_parser",
        parser_version="1.0",
        timestamp=timestamp(
            hour, minute, second, precision=timestamp_precision
        ),
        attributes=attributes,
        parse_status=parse_status,
        parse_errors=parse_errors,
    )


def rule(
    *,
    expected_artifacts=(),
    require_coverage=False,
    required_observation_attributes=None,
    candidate_partition_attributes=(),
):
    return InferenceRule(
        rule_id="authentication-rule",
        version="1.0",
        event_type="authentication_activity",
        description="Group and evaluate authentication observations.",
        required_observation_types=("linux_auth",),
        required_attributes=("user",),
        required_observation_attributes=(
            required_observation_attributes or {}
        ),
        candidate_partition_attributes=candidate_partition_attributes,
        expected_artifact_types=expected_artifacts,
        minimum_supporting_observations=1,
        requires_source_coverage=require_coverage,
    )


def coverage():
    return SourceCoverage(
        coverage_id="coverage-001",
        evidence_id=EVIDENCE_ID,
        source_type="linux_auth",
        source_locator="/var/log/auth.log",
        status=CoverageStatus.KNOWN_COVERAGE,
        intervals=(
            CoverageInterval(
                datetime(2026, 10, 2, 0, tzinfo=UTC),
                datetime(2026, 10, 2, 4, tzinfo=UTC),
            ),
        ),
        basis="Controlled test fixture",
    )


def assessment(
    *,
    availability=ObservationAvailability.OBSERVED,
    found_ids=("obs-001",),
    scope=None,
):
    return ObservationAssessment(
        assessment_id="assessment-001",
        expected_artifact_type="authentication_record",
        coverage_id="coverage-001",
        expected_extent=TemporalExtent(
            datetime(2026, 10, 2, 1, tzinfo=UTC),
            datetime(2026, 10, 2, 2, tzinfo=UTC),
        ),
        availability=availability,
        scope_attributes=(
            {"user": "alice"} if scope is None else scope
        ),
        found_observation_ids=found_ids,
        explanation="Controlled test fixture",
    )


def test_one_observation_generates_one_hypothesis():
    result = reconstruct(
        observations=(observation("obs-001"),),
        rules=(rule(),),
    )

    assert len(result.hypotheses) == 1
    assert result.hypotheses[0].interpretation is (
        InterpretationState.CORROBORATED
    )


def test_same_entity_observations_within_window_are_grouped():
    result = reconstruct(
        observations=(
            observation("obs-001", minute=0),
            observation("obs-002", minute=2),
        ),
        rules=(rule(),),
        candidate_window_seconds=300,
    )

    assert len(result.hypotheses) == 1
    assert result.hypotheses[0].supporting_observation_ids == (
        "obs-001",
        "obs-002",
    )


def test_corroborated_means_rule_support_passed_not_independent_sources():
    observations = (
        observation("obs-001", minute=0),
        observation("obs-002", minute=2),
    )
    configured_rule = rule()
    hypothesis = reconstruct(
        observations=observations,
        rules=(configured_rule,),
        candidate_window_seconds=300,
    ).hypotheses[0]

    assert hypothesis.interpretation is InterpretationState.CORROBORATED
    assert len(hypothesis.supporting_observation_ids) >= (
        configured_rule.minimum_supporting_observations
    )
    assert not hypothesis.contradicting_observation_ids
    assert not hypothesis.unresolved_conditions
    assert {item.evidence_id for item in observations} == {EVIDENCE_ID}


def test_missing_partition_attribute_keeps_observations_separate():
    result = reconstruct(
        observations=(
            observation("obs-001", minute=0),
            observation("obs-002", minute=2),
        ),
        rules=(
            rule(candidate_partition_attributes=("session_id",)),
        ),
        candidate_window_seconds=300,
    )

    assert len(result.hypotheses) == 2
    assert {
        hypothesis.supporting_observation_ids
        for hypothesis in result.hypotheses
    } == {
        ("obs-001",),
        ("obs-002",),
    }


def test_observations_outside_window_form_separate_candidates():
    result = reconstruct(
        observations=(
            observation("obs-001", hour=1, minute=0),
            observation("obs-002", hour=1, minute=20),
        ),
        rules=(rule(),),
        candidate_window_seconds=300,
    )

    assert len(result.hypotheses) == 2


def test_different_users_are_never_grouped_together():
    result = reconstruct(
        observations=(
            observation("obs-001", user="alice"),
            observation("obs-002", user="bob"),
        ),
        rules=(rule(),),
    )

    assert len(result.hypotheses) == 2
    users = {
        hypothesis.attributes["user"]
        for hypothesis in result.hypotheses
    }
    assert users == {"alice", "bob"}


def test_unknown_timestamps_are_not_assumed_to_be_simultaneous():
    result = reconstruct(
        observations=(
            observation("obs-001", hour=None),
            observation("obs-002", hour=None),
        ),
        rules=(rule(),),
    )

    assert len(result.hypotheses) == 2
    assert all(
        hypothesis.temporal_extent.earliest_utc is None
        for hypothesis in result.hypotheses
    )


def test_candidate_grouping_does_not_claim_causality():
    result = reconstruct(
        observations=(
            observation("obs-001", minute=0),
            observation("obs-002", minute=2),
        ),
        rules=(rule(),),
    )

    assumptions = result.hypotheses[0].assumptions
    assert any(
        "does not establish causality" in item
        for item in assumptions
    )


def test_duplicate_observation_ids_are_rejected():
    with pytest.raises(ModelValidationError):
        reconstruct(
            observations=(
                observation("obs-001"),
                observation("obs-001", minute=1),
            ),
            rules=(rule(),),
        )


def test_duplicate_rule_versions_are_rejected():
    with pytest.raises(ModelValidationError):
        reconstruct(
            observations=(observation("obs-001"),),
            rules=(rule(), rule()),
        )


def test_rule_without_identity_attributes_is_rejected():
    no_identity_rule = InferenceRule(
        rule_id="unscoped",
        version="1.0",
        event_type="activity",
        description="No entity identity.",
        required_observation_types=("linux_auth",),
    )

    with pytest.raises(ModelValidationError):
        reconstruct(
            observations=(observation("obs-001"),),
            rules=(no_identity_rule,),
        )


def test_invalid_window_is_rejected():
    with pytest.raises(ModelValidationError):
        reconstruct(
            observations=(observation("obs-001"),),
            rules=(rule(),),
            candidate_window_seconds=-1,
        )


def test_missing_identity_attribute_is_reported_as_skipped():
    item = SourceObservation(
        observation_id="obs-no-user",
        evidence_id=EVIDENCE_ID,
        source_type="linux_auth",
        source_locator="test-source:missing-user",
        parser_name="test_parser",
        parser_version="1.0",
        attributes={},
    )

    result = reconstruct(
        observations=(item,),
        rules=(rule(),),
    )

    assert result.hypotheses == ()
    assert len(result.skipped_inputs) == 1
    assert "user" in result.skipped_inputs[0].reason


def test_failed_parse_is_reported_as_skipped():
    item = observation(
        "obs-bad",
        parse_status=ParseStatus.FAILED,
        parse_errors=("Malformed record",),
    )

    result = reconstruct(
        observations=(item,),
        rules=(rule(),),
    )

    assert result.hypotheses == ()
    assert result.skipped_inputs[0].observation_id == "obs-bad"


def test_reconstruction_is_deterministic_for_input_order():
    first = reconstruct(
        observations=(
            observation("obs-002", minute=2),
            observation("obs-001", minute=0),
        ),
        rules=(rule(),),
    ).to_dict()

    second = reconstruct(
        observations=(
            observation("obs-001", minute=0),
            observation("obs-002", minute=2),
        ),
        rules=(rule(),),
    ).to_dict()

    assert first == second


def test_hypothesis_id_is_stable_for_identical_inputs():
    args = {
        "observations": (observation("obs-001"),),
        "rules": (rule(),),
    }

    first = reconstruct(**args).hypotheses[0].hypothesis_id
    second = reconstruct(**args).hypotheses[0].hypothesis_id

    assert first == second


def test_missing_artifact_assessment_must_match_candidate_scope():
    item = assessment(
        availability=(
            ObservationAvailability.NOT_OBSERVED_WITH_KNOWN_COVERAGE
        ),
        found_ids=(),
        scope={"user": "bob"},
    )

    result = reconstruct(
        observations=(observation("obs-001", user="alice"),),
        rules=(
            rule(
                expected_artifacts=("authentication_record",),
                require_coverage=True,
            ),
        ),
        coverage_records=(coverage(),),
        observation_assessments=(item,),
        absence_counterevidence_types_by_rule={
            "authentication-rule@1.0": ("authentication_record",)
        },
    )

    hypothesis = result.hypotheses[0]
    assert hypothesis.interpretation is InterpretationState.INSUFFICIENT_INPUT
    assert hypothesis.contradicting_assessment_ids == ()


def test_matching_missing_artifact_can_challenge_candidate():
    item = assessment(
        availability=(
            ObservationAvailability.NOT_OBSERVED_WITH_KNOWN_COVERAGE
        ),
        found_ids=(),
        scope={"user": "alice"},
    )

    result = reconstruct(
        observations=(observation("obs-001", user="alice"),),
        rules=(
            rule(
                expected_artifacts=("authentication_record",),
                require_coverage=True,
            ),
        ),
        coverage_records=(coverage(),),
        observation_assessments=(item,),
        absence_counterevidence_types_by_rule={
            "authentication-rule@1.0": ("authentication_record",)
        },
    )

    hypothesis = result.hypotheses[0]
    assert hypothesis.interpretation is InterpretationState.CHALLENGED
    assert hypothesis.contradicting_assessment_ids == (
        "assessment-001",
    )


def test_result_serialization_includes_rules_and_skipped_inputs():
    result = reconstruct(
        observations=(
            observation(
                "obs-bad",
                parse_status=ParseStatus.FAILED,
                parse_errors=("Malformed record",),
            ),
        ),
        rules=(rule(),),
    ).to_dict()

    assert result["rule_versions"] == [
        {"rule_id": "authentication-rule", "version": "1.0"}
    ]
    assert len(result["skipped_inputs"]) == 1
    assert result["hypotheses"] == []


def test_predicate_filters_candidate_seeds():
    authentication = observation(
        "obs-auth",
        extra_attributes={"action": "authentication_success"},
    )
    activity = observation(
        "obs-activity",
        extra_attributes={"action": "session_activity"},
    )

    result = reconstruct(
        observations=(authentication, activity),
        rules=(rule(
            required_observation_attributes={
                "action": "authentication_success",
            }
        ),),
    )

    assert len(result.hypotheses) == 1
    assert result.hypotheses[0].input_observation_ids == ("obs-auth",)
    assert any(
        item.observation_id == "obs-activity"
        and "attribute conditions" in item.reason
        for item in result.skipped_inputs
    )


def test_predicate_prevents_candidate_without_matching_observation():
    activity = observation(
        "obs-activity",
        extra_attributes={"action": "session_activity"},
    )

    result = reconstruct(
        observations=(activity,),
        rules=(rule(
            required_observation_attributes={
                "action": "authentication_success",
            }
        ),),
    )

    assert result.hypotheses == ()
    assert result.skipped_inputs[0].observation_id == "obs-activity"


def test_hypothesis_evaluator_only_counts_matching_observations_as_support():
    authentication = observation(
        "obs-auth",
        extra_attributes={"action": "authentication_success"},
    )
    activity = observation(
        "obs-activity",
        extra_attributes={"action": "session_activity"},
    )

    hypothesis = evaluate_candidate_hypothesis(
        hypothesis_id="test-auth-hypothesis",
        rule=rule(
            required_observation_attributes={
                "action": "authentication_success",
            }
        ),
        observations=(authentication, activity),
        candidate_attributes={"user": "alice"},
    )

    assert hypothesis.supporting_observation_ids == ("obs-auth",)
    assert set(hypothesis.input_observation_ids) == {
        "obs-auth",
        "obs-activity",
    }


@pytest.mark.parametrize(
    ("gap_seconds", "expected_correlated_ids"),
    [
        (299, ("obs-endpoint",)),
        (300, ("obs-endpoint",)),
        (301, ()),
    ],
)
def test_correlated_observation_window_boundary(
    gap_seconds, expected_correlated_ids
):
    auth_time = datetime(2026, 10, 2, 1, 0, 0, tzinfo=UTC)
    endpoint_time = auth_time + timedelta(seconds=gap_seconds)

    auth = observation(
        "obs-auth",
        hour=auth_time.hour,
        minute=auth_time.minute,
        second=auth_time.second,
        timestamp_precision=TimestampPrecision.SECOND,
        extra_attributes={
            "action": "authentication_success",
            "session_id": "session-001",
        },
    )
    endpoint = observation(
        "obs-endpoint",
        hour=endpoint_time.hour,
        minute=endpoint_time.minute,
        second=endpoint_time.second,
        timestamp_precision=TimestampPrecision.SECOND,
        source_type="endpoint_audit",
        extra_attributes={
            "action": "session_created",
            "session_id": "session-001",
        },
    )

    correlation_rule = InferenceRule(
        rule_id="auth-endpoint-boundary-test",
        version="1.0",
        event_type="authentication_activity",
        description="Test inclusive temporal correlation boundaries.",
        required_observation_types=("linux_auth",),
        required_attributes=("user",),
        required_observation_attributes={
            "action": "authentication_success",
        },
        candidate_partition_attributes=("session_id",),
        correlated_observation_types=("endpoint_audit",),
        correlated_observation_attributes={
            "action": "session_created",
        },
        correlated_observation_correlation_attribute="session_id",
    )

    result = reconstruct(
        observations=(auth, endpoint),
        rules=(correlation_rule,),
        candidate_window_seconds=300,
    )

    assert len(result.hypotheses) == 1
    hypothesis = result.hypotheses[0]

    # The direct authentication evidence must remain the only direct support.
    assert hypothesis.supporting_observation_ids == ("obs-auth",)

    # Correlation includes the exact boundary but rejects one second beyond it.
    assert (
        hypothesis.correlated_observation_ids
        == expected_correlated_ids
    )


@pytest.mark.parametrize(
    (
        "endpoint_user",
        "endpoint_session_id",
        "missing_endpoint_attribute",
        "missing_auth_attribute",
        "expected_correlated_ids",
    ),
    [
        ("alice", "session-001", None, None, ("obs-endpoint",)),
        ("alice", "session-other", None, None, ()),
        ("bob", "session-001", None, None, ()),
        ("alice", "session-001", "user", None, ()),
        ("alice", "session-001", "session_id", None, ()),
        ("alice", "session-001", None, "session_id", ()),
    ],
)
def test_correlated_observation_identity_matching(
    endpoint_user,
    endpoint_session_id,
    missing_endpoint_attribute,
    missing_auth_attribute,
    expected_correlated_ids,
):
    from dataclasses import replace

    auth = observation(
        "obs-auth",
        extra_attributes={
            "action": "authentication_success",
            "session_id": "session-001",
        },
        timestamp_precision=TimestampPrecision.SECOND,
    )
    if missing_auth_attribute is not None:
        auth_attributes = dict(auth.attributes)
        auth_attributes.pop(missing_auth_attribute)
        auth = replace(auth, attributes=auth_attributes)

    endpoint = observation(
        "obs-endpoint",
        user=endpoint_user,
        second=30,
        source_type="endpoint_audit",
        extra_attributes={
            "action": "session_created",
            "session_id": endpoint_session_id,
        },
        timestamp_precision=TimestampPrecision.SECOND,
    )
    if missing_endpoint_attribute is not None:
        endpoint_attributes = dict(endpoint.attributes)
        endpoint_attributes.pop(missing_endpoint_attribute)
        endpoint = replace(endpoint, attributes=endpoint_attributes)

    correlation_rule = InferenceRule(
        rule_id="auth-endpoint-identity-test",
        version="1.0",
        event_type="authentication_activity",
        description="Test endpoint correlation identity requirements.",
        required_observation_types=("linux_auth",),
        required_attributes=("user",),
        required_observation_attributes={
            "action": "authentication_success",
        },
        candidate_partition_attributes=("session_id",),
        correlated_observation_types=("endpoint_audit",),
        correlated_observation_attributes={
            "action": "session_created",
        },
        correlated_observation_correlation_attribute="session_id",
    )

    result = reconstruct(
        observations=(auth, endpoint),
        rules=(correlation_rule,),
        candidate_window_seconds=300,
    )

    assert len(result.hypotheses) == 1
    hypothesis = result.hypotheses[0]
    assert hypothesis.supporting_observation_ids == ("obs-auth",)
    assert (
        hypothesis.correlated_observation_ids
        == expected_correlated_ids
    )

def test_shared_session_id_does_not_cross_correlate_users():
    observations = (
        observation(
            "auth-alice",
            user="alice",
            second=0,
            timestamp_precision=TimestampPrecision.SECOND,
            extra_attributes={
                "action": "authentication_success",
                "session_id": "reused-session",
            },
        ),
        observation(
            "auth-bob",
            user="bob",
            second=30,
            timestamp_precision=TimestampPrecision.SECOND,
            extra_attributes={
                "action": "authentication_success",
                "session_id": "reused-session",
            },
        ),
        observation(
            "endpoint-alice",
            user="alice",
            minute=1,
            second=0,
            source_type="endpoint_audit",
            timestamp_precision=TimestampPrecision.SECOND,
            extra_attributes={
                "action": "session_created",
                "session_id": "reused-session",
            },
        ),
        observation(
            "endpoint-bob",
            user="bob",
            minute=1,
            second=30,
            source_type="endpoint_audit",
            timestamp_precision=TimestampPrecision.SECOND,
            extra_attributes={
                "action": "session_created",
                "session_id": "reused-session",
            },
        ),
    )

    correlation_rule = InferenceRule(
        rule_id="cross-user-isolation-test",
        version="1.0",
        event_type="authentication_activity",
        description="Ensure shared session IDs do not cross user identities.",
        required_observation_types=("linux_auth",),
        required_attributes=("user",),
        required_observation_attributes={
            "action": "authentication_success",
        },
        candidate_partition_attributes=("session_id",),
        correlated_observation_types=("endpoint_audit",),
        correlated_observation_attributes={
            "action": "session_created",
        },
        correlated_observation_correlation_attribute="session_id",
    )

    result = reconstruct(
        observations=observations,
        rules=(correlation_rule,),
        candidate_window_seconds=300,
    )

    assert len(result.hypotheses) == 2
    by_user = {
        hypothesis.attributes["user"]: hypothesis
        for hypothesis in result.hypotheses
    }
    assert set(by_user) == {"alice", "bob"}

    assert by_user["alice"].supporting_observation_ids == ("auth-alice",)
    assert by_user["alice"].correlated_observation_ids == ("endpoint-alice",)

    assert by_user["bob"].supporting_observation_ids == ("auth-bob",)
    assert by_user["bob"].correlated_observation_ids == ("endpoint-bob",)
