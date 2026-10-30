"""Tests for baseline reconstruction methods."""

import pytest

from benchmarks.baselines import (
    chronology_only_predictions,
    rule_correlation_predictions,
)
from benchmarks.models import ScenarioFamily
from benchmarks.tracee_adapter import tracee_predictions
from benchmarks.scenario_generator import generate_scenario
from tracee.models import ModelValidationError


def _scenario(family, seed=42):
    return generate_scenario(seed, family)


def test_chronology_baseline_predicts_only_explicit_authentication():
    scenario = _scenario(ScenarioFamily.COMPLETE_RECORDS)

    predictions = chronology_only_predictions(scenario.method_input)

    assert len(predictions) == 1
    assert predictions[0].event_type == "authentication_success"
    assert predictions[0].interpretation_state == "observed"
    assert len(predictions[0].source_observation_ids) == 1


def test_chronology_baseline_orders_multiple_authentication_events():
    scenario = _scenario(ScenarioFamily.MULTIPLE_ENTITIES)

    predictions = chronology_only_predictions(scenario.method_input)

    times = [item.temporal_extent.earliest_utc for item in predictions]
    assert len(predictions) == 2
    assert times == sorted(times)


@pytest.mark.parametrize(
    "family",
    [
        ScenarioFamily.MISSING_RECORD,
        ScenarioFamily.LOGGING_DISABLED,
        ScenarioFamily.AMBIGUOUS_EVIDENCE,
    ],
)
def test_chronology_baseline_does_not_infer_from_session_activity(family):
    scenario = _scenario(family)

    assert chronology_only_predictions(scenario.method_input) == ()


def test_rule_baseline_correlates_nearby_login_and_session():
    scenario = _scenario(ScenarioFamily.COMPLETE_RECORDS)

    predictions = rule_correlation_predictions(scenario.method_input)

    assert len(predictions) == 1
    prediction = predictions[0]
    assert prediction.event_type == "authentication_success"
    assert len(prediction.source_observation_ids) == 2
    assert prediction.inference_rule_id == "basic-auth-session-correlation"
    assert prediction.interpretation_state == "rule_correlated"


def test_rule_baseline_keeps_distant_authentication_records_separate():
    scenario = _scenario(ScenarioFamily.CONFLICTING_TIMESTAMPS)

    predictions = rule_correlation_predictions(scenario.method_input)

    assert len(predictions) == 2
    assert all(
        item.event_type == "authentication_success"
        for item in predictions
    )
    assert all(
        len(item.source_observation_ids) == 1
        for item in predictions
    )


@pytest.mark.parametrize(
    "family",
    [
        ScenarioFamily.MISSING_RECORD,
        ScenarioFamily.LOGGING_DISABLED,
        ScenarioFamily.AMBIGUOUS_EVIDENCE,
    ],
)
def test_rule_baseline_does_not_infer_login_from_session_activity(family):
    scenario = _scenario(family)

    assert rule_correlation_predictions(scenario.method_input) == ()


def test_negative_control_failure_record_does_not_predict_success():
    scenario = _scenario(ScenarioFamily.NEGATIVE_CONTROL)
    method_input = scenario.method_input

    assert scenario.ground_truth.events == ()
    assert chronology_only_predictions(method_input) == ()
    assert rule_correlation_predictions(method_input) == ()

    predictions = tracee_predictions(method_input)
    target_predictions = tuple(
        prediction
        for prediction in predictions
        if prediction.event_type == "authentication_success"
    )
    assert target_predictions == ()

def test_rule_baseline_keeps_multiple_entities_separate():
    scenario = _scenario(ScenarioFamily.MULTIPLE_ENTITIES)

    predictions = rule_correlation_predictions(scenario.method_input)

    assert len(predictions) == 2
    assert {
        (item.entity_attributes["user"], item.entity_attributes["host"])
        for item in predictions
    } == {
        (event.entity_attributes["user"], event.entity_attributes["host"])
        for event in scenario.ground_truth.events
    }


def test_baseline_outputs_are_deterministic():
    scenario = _scenario(ScenarioFamily.COMPLETE_RECORDS)

    assert chronology_only_predictions(scenario.method_input) == (
        chronology_only_predictions(scenario.method_input)
    )
    assert rule_correlation_predictions(scenario.method_input) == (
        rule_correlation_predictions(scenario.method_input)
    )


@pytest.mark.parametrize(
    "method",
    [chronology_only_predictions, rule_correlation_predictions],
)
def test_baselines_reject_non_benchmark_input(method):
    with pytest.raises(ModelValidationError):
        method(None)


@pytest.mark.parametrize("window", [-1, True, 1.5, "300"])
def test_rule_baseline_rejects_invalid_window(window):
    scenario = _scenario(ScenarioFamily.COMPLETE_RECORDS)

    with pytest.raises(ModelValidationError):
        rule_correlation_predictions(
            scenario.method_input,
            correlation_window_seconds=window,
        )


def test_tracee_keeps_explicitly_distinct_sessions_separate():
    from benchmarks.scenario_generator import generate_scenario
    from benchmarks.tracee_adapter import tracee_predictions

    scenario = generate_scenario(
        42,
        ScenarioFamily.COMPLETE_RECORDS,
        profile_id="DEV-COMP-02",
    )

    auth_ids = {
        item.observation_id
        for item in scenario.method_input.observations
        if item.attributes.get("action") == "authentication_success"
    }
    assert len(auth_ids) == 2

    predictions = tracee_predictions(scenario.method_input)

    assert len(predictions) == 2
    assert {
        prediction.source_observation_ids[0]
        for prediction in predictions
        if len(prediction.source_observation_ids) == 1
    } == auth_ids
    assert all(
        len(prediction.source_observation_ids) == 1
        for prediction in predictions
    )


def test_session_partition_configuration_is_serialized():
    from benchmarks.tracee_adapter import benchmark_inference_rules

    rules = benchmark_inference_rules()
    explicit = next(
        rule for rule in rules
        if rule.rule_id == "explicit-authentication-success"
    )

    assert explicit.candidate_partition_attributes == ("session_id",)
    assert explicit.to_dict()["candidate_partition_attributes"] == [
        "session_id"
    ]

def test_tracee_correlates_endpoint_records_only_within_window():
    from benchmarks.scenario_generator import generate_scenario
    from benchmarks.tracee_adapter import tracee_predictions

    scenario = generate_scenario(
        42,
        ScenarioFamily.COMPLETE_RECORDS,
        profile_id="DEV-COMP-02",
    )
    observations = scenario.method_input.observations

    auth_by_session = {
        item.attributes["session_id"]: item
        for item in observations
        if item.attributes.get("action") == "authentication_success"
    }
    endpoint_by_session = {
        item.attributes["session_id"]: item
        for item in observations
        if (
            item.source_type == "endpoint_audit"
            and item.attributes.get("action") == "session_created"
        )
    }

    assert len(auth_by_session) == 2
    assert len(endpoint_by_session) == 2
    assert set(auth_by_session) == set(endpoint_by_session)

    auth_ids = {
        item.observation_id for item in auth_by_session.values()
    }

    # Both endpoint gaps straddle the 60-second window but fit the
    # 300-second window. The evidence itself is unchanged between runs.
    for session_id, auth in auth_by_session.items():
        endpoint = endpoint_by_session[session_id]
        gap_seconds = (
            endpoint.timestamp.normalized_extent.earliest_utc
            - auth.timestamp.normalized_extent.earliest_utc
        ).total_seconds()
        assert 60 < gap_seconds <= 300

    def direct_auth_predictions(window_seconds):
        predictions = tracee_predictions(
            scenario.method_input,
            candidate_window_seconds=window_seconds,
        )
        matching = [
            prediction for prediction in predictions
            if set(prediction.source_observation_ids) & auth_ids
        ]

        by_source_id = {}
        for prediction in matching:
            assert len(prediction.source_observation_ids) == 1
            source_id = prediction.source_observation_ids[0]
            assert source_id in auth_ids
            assert source_id not in by_source_id
            by_source_id[source_id] = prediction

        assert set(by_source_id) == auth_ids
        return by_source_id

    wide = direct_auth_predictions(300)
    narrow = direct_auth_predictions(60)

    # Candidate generation and direct support must stay stable.
    for auth_id in auth_ids:
        wide_prediction = wide[auth_id]
        narrow_prediction = narrow[auth_id]

        assert (
            wide_prediction.source_observation_ids
            == narrow_prediction.source_observation_ids
        )
        assert wide_prediction.event_type == narrow_prediction.event_type
        assert (
            wide_prediction.entity_attributes
            == narrow_prediction.entity_attributes
        )
        assert wide_prediction.temporal_extent == narrow_prediction.temporal_extent
        assert (
            wide_prediction.interpretation_state
            == narrow_prediction.interpretation_state
        )
        assert (
            wide_prediction.inference_rule_id
            == narrow_prediction.inference_rule_id
        )

        auth = next(
            item for item in auth_by_session.values()
            if item.observation_id == auth_id
        )
        expected_endpoint_id = endpoint_by_session[
            auth.attributes["session_id"]
        ].observation_id

        assert wide_prediction.correlated_observation_ids == (
            expected_endpoint_id,
        )
        assert narrow_prediction.correlated_observation_ids == ()


def test_negative_control_profiles_do_not_confirm_session_candidates():
    from benchmarks.models import ScenarioFamily
    from benchmarks.scenario_generator import generate_scenario
    from benchmarks.tracee_adapter import tracee_predictions

    baseline = generate_scenario(42, ScenarioFamily.NEGATIVE_CONTROL)
    assert baseline.ground_truth.profile_id is None
    assert baseline.ground_truth.events == ()
    assert len(baseline.method_input.observations) == 1

    profiles = ("NEG-CTRL-01", "NEG-CTRL-02", "NEG-CTRL-03")

    for profile_id in profiles:
        scenario = generate_scenario(
            42,
            ScenarioFamily.NEGATIVE_CONTROL,
            profile_id=profile_id,
        )
        observations = scenario.method_input.observations

        assert scenario.ground_truth.profile_id == profile_id
        assert scenario.ground_truth.events == ()
        assert len(observations) == 2

        failures = [
            item for item in observations
            if item.attributes.get("action") == "authentication_failure"
        ]
        endpoints = [
            item for item in observations
            if item.source_type == "endpoint_audit"
            and item.attributes.get("action") == "session_created"
        ]
        assert len(failures) == 1
        assert len(endpoints) == 1

        failure = failures[0]
        endpoint = endpoints[0]

        assert failure.attributes["host"] == endpoint.attributes["host"]
        assert failure.attributes.get("session_id")
        assert endpoint.attributes.get("session_id")

        gap_seconds = (
            endpoint.timestamp.normalized_extent.earliest_utc
            - failure.timestamp.normalized_extent.earliest_utc
        ).total_seconds()

        if profile_id == "NEG-CTRL-01":
            assert failure.attributes["user"] == endpoint.attributes["user"]
            assert failure.attributes["session_id"] != endpoint.attributes["session_id"]
            assert 0 < gap_seconds <= 300

        elif profile_id == "NEG-CTRL-02":
            assert failure.attributes["user"] != endpoint.attributes["user"]
            assert failure.attributes["session_id"] != endpoint.attributes["session_id"]
            assert 0 < gap_seconds <= 300

        else:
            assert failure.attributes["user"] == endpoint.attributes["user"]
            assert failure.attributes["session_id"] == endpoint.attributes["session_id"]
            assert gap_seconds > 300

        predictions = tuple(
            prediction
            for prediction in tracee_predictions(scenario.method_input)
            if prediction.event_type == "authentication_success"
        )

        # Endpoint activity may generate an investigative candidate,
        # but it must not be treated as a confirmed authentication.
        assert len(predictions) == 1
        prediction = predictions[0]
        assert prediction.interpretation_state == "insufficient_input"
        assert prediction.source_observation_ids == (endpoint.observation_id,)
        assert prediction.correlated_observation_ids == ()


def test_negative_control_profiles_reject_wrong_scenario_family():
    import pytest
    from benchmarks.models import ModelValidationError, ScenarioFamily
    from benchmarks.scenario_generator import generate_scenario

    with pytest.raises(ModelValidationError):
        generate_scenario(
            42,
            ScenarioFamily.COMPLETE_RECORDS,
            profile_id="NEG-CTRL-01",
        )
