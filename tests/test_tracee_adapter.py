"""Tests for the TRACEE benchmark adapter."""

import pytest

from benchmarks.models import ScenarioFamily
from benchmarks.scenario_generator import generate_scenario
from benchmarks.tracee_adapter import (
    benchmark_inference_rules,
    hypotheses_to_predictions,
    run_tracee_reconstruction,
    tracee_predictions,
)
from tracee.hypotheses import InterpretationState
from tracee.models import ModelValidationError
from tracee.reconstruction import ReconstructionResult


def _scenario(family, seed=42):
    return generate_scenario(seed, family)


def test_adapter_invokes_reconstruction_engine():
    scenario = _scenario(ScenarioFamily.COMPLETE_RECORDS)

    result = run_tracee_reconstruction(scenario.method_input)

    assert isinstance(result, ReconstructionResult)
    assert result.rule_versions == tuple(sorted(
        (rule.rule_id, rule.version)
        for rule in benchmark_inference_rules()
    ))


def test_explicit_authentication_produces_a_corroborated_hypothesis():
    scenario = _scenario(ScenarioFamily.COMPLETE_RECORDS)

    predictions = tracee_predictions(scenario.method_input)

    authentication_predictions = [
        item for item in predictions
        if item.inference_rule_id == "explicit-authentication-success"
    ]

    assert len(authentication_predictions) == 1
    assert authentication_predictions[0].event_type == "authentication_success"
    assert authentication_predictions[0].interpretation_state == (
        InterpretationState.CORROBORATED.value
    )
    assert authentication_predictions[0].source_observation_ids


@pytest.mark.parametrize(
    "family",
    [
        ScenarioFamily.MISSING_RECORD,
        ScenarioFamily.LOGGING_DISABLED,
        ScenarioFamily.AMBIGUOUS_EVIDENCE,
    ],
)
def test_session_activity_is_not_treated_as_corroborated_authentication(family):
    scenario = _scenario(family)

    predictions = tracee_predictions(scenario.method_input)
    expected_rule_id = (
        "auth-candidate-from-session-creation"
        if family is ScenarioFamily.MISSING_RECORD
        else "auth-candidate-from-session-activity"
    )
    session_predictions = [
        item for item in predictions
        if item.inference_rule_id == expected_rule_id
    ]

    assert len(session_predictions) == 1
    assert session_predictions[0].event_type == "authentication_success"
    assert session_predictions[0].interpretation_state != (
        InterpretationState.CORROBORATED.value
    )
    assert session_predictions[0].source_observation_ids


def test_timestamp_conflict_exposes_duplicate_hypotheses():
    scenario = _scenario(ScenarioFamily.CONFLICTING_TIMESTAMPS)

    result = run_tracee_reconstruction(scenario.method_input)

    assert len(result.hypotheses) == 2
    assert all(
        item.event_type == "authentication_success"
        for item in result.hypotheses
    )
    assert all(
        item.interpretation is InterpretationState.CORROBORATED
        for item in result.hypotheses
    )
    assert len({
        item.temporal_extent.earliest_utc
        for item in result.hypotheses
    }) == 2


def test_multiple_entities_remain_separate():
    scenario = _scenario(ScenarioFamily.MULTIPLE_ENTITIES)

    predictions = tracee_predictions(scenario.method_input)

    assert len(predictions) == 2
    assert {
        (item.entity_attributes["user"], item.entity_attributes["host"])
        for item in predictions
    } == {
        (event.entity_attributes["user"], event.entity_attributes["host"])
        for event in scenario.ground_truth.events
    }


def test_prediction_source_ids_are_input_observations():
    scenario = _scenario(ScenarioFamily.COMPLETE_RECORDS)
    supplied_ids = {
        item.observation_id for item in scenario.method_input.observations
    }

    predictions = tracee_predictions(scenario.method_input)

    for prediction in predictions:
        assert set(prediction.source_observation_ids) <= supplied_ids


def test_adapter_is_deterministic():
    scenario = _scenario(ScenarioFamily.COMPLETE_RECORDS)

    first = tracee_predictions(scenario.method_input)
    second = tracee_predictions(scenario.method_input)

    assert first == second


def test_adapter_rejects_ground_truth_wrapper_as_method_input():
    scenario = _scenario(ScenarioFamily.COMPLETE_RECORDS)

    with pytest.raises(ModelValidationError):
        tracee_predictions(scenario)


def test_hypothesis_conversion_rejects_invalid_result():
    with pytest.raises(ModelValidationError):
        hypotheses_to_predictions(None)
