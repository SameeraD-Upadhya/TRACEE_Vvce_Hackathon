"""Tests for TRACEE benchmark scoring and event matching."""

from datetime import datetime, timezone

import pytest

from benchmarks.evaluate import (
    BenchmarkPrediction,
    EvaluationConfig,
    evaluate_predictions,
    prediction_matches_truth,
)
from benchmarks.models import GroundTruthEvent, ScenarioFamily
from benchmarks.scenario_generator import generate_scenario
from benchmarks.tracee_adapter import tracee_predictions
from tracee.events import TemporalExtent
from tracee.models import ModelValidationError


UTC = timezone.utc


def point(hour, minute=0):
    return datetime(2026, 10, 2, hour, minute, tzinfo=UTC)


def truth(
    event_id="truth-001",
    *,
    event_type="authentication_success",
    user="alice",
    host="host-01",
    start=None,
    end=None,
    expected_interpretation_state=None,
    expected_record_ids=None,
):
    start = point(1) if start is None else start
    end = start if end is None else end

    return GroundTruthEvent(
        event_id=event_id,
        event_type=event_type,
        entity_attributes={"user": user, "host": host},
        temporal_extent=TemporalExtent(start, end),
        expected_record_ids=(
            (f"record-{event_id}",)
            if expected_record_ids is None
            else expected_record_ids
        ),
        expected_interpretation_state=expected_interpretation_state,
    )


def prediction(
    prediction_id="prediction-001",
    *,
    event_type="authentication_success",
    user="alice",
    host="host-01",
    start=None,
    end=None,
    state="corroborated",
    source_ids=("obs-001",),
    correlated_ids=(),
):
    start = point(1) if start is None else start
    end = start if end is None else end

    return BenchmarkPrediction(
        prediction_id=prediction_id,
        event_type=event_type,
        entity_attributes={"user": user, "host": host},
        temporal_extent=TemporalExtent(start, end),
        source_observation_ids=source_ids,
        correlated_observation_ids=correlated_ids,
        interpretation_state=state,
        inference_rule_id="test-rule",
        inference_rule_version="1.0",
    )


def test_exact_event_match():
    assert prediction_matches_truth(
        prediction(), truth(), EvaluationConfig()
    )


def test_wrong_event_type_does_not_match():
    assert not prediction_matches_truth(
        prediction(event_type="file_modification"),
        truth(),
        EvaluationConfig(),
    )


def test_wrong_entity_does_not_match():
    assert not prediction_matches_truth(
        prediction(user="bob"),
        truth(user="alice"),
        EvaluationConfig(),
    )


def test_missing_entity_key_does_not_match():
    item = BenchmarkPrediction(
        prediction_id="prediction-001",
        event_type="authentication_success",
        entity_attributes={"user": "alice"},
        temporal_extent=TemporalExtent(point(1), point(1)),
    )

    assert not prediction_matches_truth(
        item, truth(), EvaluationConfig()
    )


def test_time_outside_tolerance_does_not_match():
    config = EvaluationConfig(time_tolerance_seconds=30)

    assert not prediction_matches_truth(
        prediction(start=point(1, 10)),
        truth(start=point(1, 0)),
        config,
    )


def test_time_within_tolerance_matches():
    config = EvaluationConfig(time_tolerance_seconds=60)

    assert prediction_matches_truth(
        prediction(start=point(1, 1)),
        truth(start=point(1, 0)),
        config,
    )


def test_unknown_time_matches_when_policy_allows_it():
    unknown = prediction(
        start=None,
        end=None,
    )

    # Explicitly construct a genuinely unknown prediction time.
    unknown = BenchmarkPrediction(
        prediction_id=unknown.prediction_id,
        event_type=unknown.event_type,
        entity_attributes=unknown.entity_attributes,
        temporal_extent=TemporalExtent(),
        source_observation_ids=unknown.source_observation_ids,
        interpretation_state=unknown.interpretation_state,
    )

    assert prediction_matches_truth(
        unknown,
        truth(),
        EvaluationConfig(allow_unknown_time_for_event_match=True),
    )


def test_unknown_time_does_not_match_when_policy_disallows_it():
    unknown = BenchmarkPrediction(
        prediction_id="prediction-unknown",
        event_type="authentication_success",
        entity_attributes={"user": "alice", "host": "host-01"},
        temporal_extent=TemporalExtent(),
    )

    assert not prediction_matches_truth(
        unknown,
        truth(),
        EvaluationConfig(allow_unknown_time_for_event_match=False),
    )


def test_duplicate_predictions_cannot_match_one_truth_twice():
    report = evaluate_predictions(
        (
            prediction("prediction-a"),
            prediction("prediction-b"),
        ),
        (truth(),),
    )

    assert report.true_positives == 1
    assert report.false_positives == 1
    assert report.false_negatives == 0
    assert len(report.matched_pairs) == 1


def test_matching_uses_maximum_one_to_one_assignment():
    # The first prediction matches either truth; the second can match only
    # truth-001. The evaluator should assign the first prediction to
    # truth-002 so both ground-truth events can be matched.
    truths = (
        truth("truth-001", start=point(1, 0)),
        truth("truth-002", start=point(1, 2)),
    )
    predictions = (
        prediction(
            "prediction-a",
            start=point(1, 0),
            end=point(1, 2),
        ),
        prediction(
            "prediction-b",
            start=point(1, 0),
        ),
    )

    report = evaluate_predictions(
        predictions,
        truths,
        EvaluationConfig(time_tolerance_seconds=0),
    )

    assert report.true_positives == 2
    assert set(report.matched_pairs) == {
        ("prediction-a", "truth-002"),
        ("prediction-b", "truth-001"),
    }


def test_precision_recall_and_f1_are_calculated_correctly():
    report = evaluate_predictions(
        (
            prediction("prediction-correct"),
            prediction("prediction-false", user="mallory"),
        ),
        (
            truth("truth-correct"),
            truth("truth-missed", user="bob"),
        ),
    )

    assert report.true_positives == 1
    assert report.false_positives == 1
    assert report.false_negatives == 1
    assert report.precision == pytest.approx(0.5)
    assert report.recall == pytest.approx(0.5)
    assert report.f1 == pytest.approx(0.5)


def test_empty_predictions_produce_zero_metrics():
    report = evaluate_predictions((), (truth(),))

    assert report.precision == 0.0
    assert report.recall == 0.0
    assert report.f1 == 0.0
    assert report.false_negatives == 1


def test_empty_prediction_and_truth_sets_produce_zero_metrics():
    report = evaluate_predictions((), ())

    assert report.precision == 0.0
    assert report.recall == 0.0
    assert report.f1 == 0.0


def test_unsupported_definitive_rate_ignores_unresolved_predictions():
    predictions = (
        prediction("matched", user="alice"),
        prediction("unsupported", user="mallory"),
        prediction(
            "unresolved",
            user="carol",
            state="underdetermined",
        ),
    )

    report = evaluate_predictions(predictions, (truth(),))

    assert report.definitive_prediction_count == 2
    assert report.unsupported_definitive_count == 1
    assert report.unsupported_definitive_rate == pytest.approx(0.5)


def test_provenance_completeness_is_reported():
    report = evaluate_predictions(
        (
            prediction("with-source", source_ids=("obs-001",)),
            prediction("without-source", source_ids=()),
        ),
        (truth(),),
        available_observation_ids=("obs-001",),
    )

    assert report.predictions_with_source_provenance == 1
    assert report.source_provenance_completeness == pytest.approx(0.5)
    assert report.provenance_validation_performed is True
    assert report.invalid_source_reference_count == 0


def test_unknown_source_observation_ids_are_not_valid_provenance():
    report = evaluate_predictions(
        (prediction(source_ids=("obs-not-supplied",)),),
        (truth(),),
        available_observation_ids=("obs-001",),
    )

    assert report.predictions_with_source_provenance == 0
    assert report.source_provenance_completeness == 0.0
    assert report.invalid_source_reference_count == 1


def test_provenance_is_not_claimed_when_input_ids_are_unavailable():
    report = evaluate_predictions((prediction(),), (truth(),))

    assert report.provenance_validation_performed is False
    assert report.predictions_with_source_provenance == 0
    assert report.source_provenance_completeness == 0.0


def test_dev_comp_02_preserves_session_alignment_in_evidence_scoring():
    scenario = generate_scenario(
        42,
        ScenarioFamily.COMPLETE_RECORDS,
        profile_id="DEV-COMP-02",
    )
    predictions = tuple(tracee_predictions(scenario.method_input))
    available_ids = tuple(
        item.observation_id
        for item in scenario.method_input.observations
    )

    report = evaluate_predictions(
        predictions,
        scenario.ground_truth.events,
        config=EvaluationConfig(time_tolerance_seconds=60),
        available_observation_ids=available_ids,
    )

    expected_by_event = {
        event.event_id: set(event.expected_record_ids)
        for event in scenario.ground_truth.events
    }
    prediction_by_id = {
        item.prediction_id: item for item in predictions
    }
    observations_by_id = {
        item.observation_id: item
        for item in scenario.method_input.observations
    }

    assert report.true_positives == 2
    assert report.false_positives == 0
    assert report.false_negatives == 0
    assert len(report.matched_pairs) == 2

    # Direct support and correlated endpoint context must remain separate.
    for prediction_id, event_id in report.matched_pairs:
        item = prediction_by_id[prediction_id]
        direct_ids = set(item.source_observation_ids)
        correlated_ids = set(item.correlated_observation_ids)
        expected_ids = expected_by_event[event_id]

        assert direct_ids
        assert direct_ids.isdisjoint(correlated_ids)
        assert direct_ids <= expected_ids
        assert correlated_ids <= expected_ids

        assert direct_ids == {
            identifier for identifier in expected_ids
            if observations_by_id[identifier].attributes.get("action")
            == "authentication_success"
        }
        assert correlated_ids == {
            identifier for identifier in expected_ids
            if observations_by_id[identifier].attributes.get("action")
            == "session_created"
        }

    # The two authentication records remain direct support; the two
    # endpoint records are linked separately by explicit session identity.
    assert report.evidence_correlation_scoring_performed is True
    assert report.evidence_correlation_true_positives == 4
    assert report.evidence_correlation_false_positives == 0
    assert report.evidence_correlation_false_negatives == 0
    assert report.evidence_correlation_precision == pytest.approx(1.0)
    assert report.evidence_correlation_recall == pytest.approx(1.0)
    assert report.evidence_correlation_f1 == pytest.approx(1.0)


def test_evidence_correlation_is_scored_separately_from_event_detection():
    event = truth(
        expected_record_ids=("obs-001", "obs-002", "obs-003"),
    )
    item = prediction(
        source_ids=("obs-001", "obs-unrelated"),
    )

    report = evaluate_predictions(
        (item,),
        (event,),
        available_observation_ids=(
            "obs-001",
            "obs-002",
            "obs-003",
            "obs-unrelated",
        ),
    )

    # Event detection still succeeds independently of evidence alignment.
    assert report.true_positives == 1
    assert report.false_positives == 0
    assert report.evidence_correlation_scoring_performed is True
    assert report.evidence_correlation_evaluated_event_count == 1
    assert report.evidence_correlation_true_positives == 1
    assert report.evidence_correlation_false_positives == 1
    assert report.evidence_correlation_false_negatives == 2
    assert report.evidence_correlation_precision == pytest.approx(0.5)
    assert report.evidence_correlation_recall == pytest.approx(1 / 3)
    assert report.evidence_correlation_f1 == pytest.approx(0.4)

    serialized = report.to_dict()
    assert serialized["evidence_correlation_scoring_performed"] is True
    assert serialized["evidence_correlation_f1"] == pytest.approx(0.4)


def test_omitted_expected_records_are_not_counted_as_missing_evidence():
    event = truth(
        expected_record_ids=("obs-001", "obs-omitted"),
    )
    report = evaluate_predictions(
        (prediction(source_ids=("obs-001",)),),
        (event,),
        available_observation_ids=("obs-001",),
    )

    assert report.true_positives == 1
    assert report.evidence_correlation_scoring_performed is True
    assert report.evidence_correlation_true_positives == 1
    assert report.evidence_correlation_false_positives == 0
    assert report.evidence_correlation_false_negatives == 0
    assert report.evidence_correlation_recall == 1.0


def test_evidence_metrics_are_unavailable_when_expected_records_are_absent():
    event = truth(expected_record_ids=("obs-omitted",))
    report = evaluate_predictions(
        (prediction(source_ids=("obs-001",)),),
        (event,),
        available_observation_ids=("obs-001",),
    )

    assert report.true_positives == 1
    assert report.evidence_correlation_scoring_performed is False
    assert report.evidence_correlation_evaluated_event_count == 0
    assert report.evidence_correlation_precision is None
    assert report.evidence_correlation_recall is None
    assert report.evidence_correlation_f1 is None


def test_evidence_metrics_are_unavailable_without_input_ids():
    event = truth(expected_record_ids=("obs-001",))
    report = evaluate_predictions(
        (prediction(source_ids=("obs-001",)),),
        (event,),
    )

    assert report.evidence_correlation_scoring_performed is False
    assert report.evidence_correlation_precision is None
    assert report.evidence_correlation_recall is None
    assert report.evidence_correlation_f1 is None


def test_state_mismatch_is_separate_from_event_matching():
    event = truth(expected_interpretation_state="corroborated")
    candidate = prediction(state="underdetermined")

    report = evaluate_predictions((candidate,), (event,))

    assert report.true_positives == 1
    assert report.false_positives == 0
    assert report.interpretation_state_evaluated_count == 1
    assert report.interpretation_state_correct_count == 0
    assert report.interpretation_state_incorrect_count == 1
    assert report.interpretation_state_accuracy == 0.0
    assert report.interpretation_state_mismatches == (
        ("prediction-001", "truth-001", "underdetermined", "corroborated"),
    )


def test_correct_interpretation_state_scores_one():
    event = truth(expected_interpretation_state="corroborated")
    report = evaluate_predictions((prediction(),), (event,))

    assert report.interpretation_state_evaluated_count == 1
    assert report.interpretation_state_correct_count == 1
    assert report.interpretation_state_incorrect_count == 0
    assert report.interpretation_state_accuracy == 1.0


def test_negative_control_prediction_remains_a_false_positive():
    report = evaluate_predictions(
        (prediction(state="insufficient_input"),),
        (),
    )

    assert report.false_positives == 1
    assert report.interpretation_state_evaluated_count == 0
    assert report.interpretation_state_accuracy is None


def test_unmatched_truth_is_reported_separately():
    event = truth(expected_interpretation_state="corroborated")
    report = evaluate_predictions((), (event,))

    assert report.false_negatives == 1
    assert report.interpretation_state_evaluated_count == 0
    assert report.interpretation_state_accuracy is None
    assert report.interpretation_state_unmatched_ground_truth_count == 1


def test_unknown_expected_state_is_not_scored():
    event = truth(expected_interpretation_state=None)
    report = evaluate_predictions((prediction(),), (event,))

    assert report.true_positives == 1
    assert report.interpretation_state_evaluated_count == 0
    assert report.interpretation_state_unscored_ground_truth_count == 1


def test_duplicate_prediction_ids_are_rejected():
    with pytest.raises(ModelValidationError):
        evaluate_predictions(
            (prediction("duplicate"), prediction("duplicate")),
            (truth(),),
        )


def test_result_serialization_contains_scoring_configuration():
    report = evaluate_predictions(
        (prediction(),),
        (truth(),),
        EvaluationConfig(time_tolerance_seconds=120),
    )

    output = report.to_dict()

    assert output["config"]["time_tolerance_seconds"] == 120
    assert output["true_positives"] == 1
    assert output["matched_pairs"] == [
        {
            "prediction_id": "prediction-001",
            "ground_truth_event_id": "truth-001",
        }
    ]

def test_prediction_serializes_correlated_observation_ids_separately():
    item = prediction(correlated_ids=("obs-002",))
    assert item.source_observation_ids == ("obs-001",)
    assert item.correlated_observation_ids == ("obs-002",)
    assert item.to_dict()["correlated_observation_ids"] == ["obs-002"]

def test_prediction_rejects_overlap_between_direct_and_correlated_ids():
    with pytest.raises(ModelValidationError):
        prediction(correlated_ids=("obs-001",))

def test_evidence_metrics_count_correlated_observations():
    event = truth(expected_record_ids=("obs-001", "obs-002"))
    item = prediction(correlated_ids=("obs-002",))
    report = evaluate_predictions(
        (item,),
        (event,),
        available_observation_ids=("obs-001", "obs-002"),
    )
    assert report.evidence_correlation_true_positives == 2
    assert report.evidence_correlation_false_positives == 0
    assert report.evidence_correlation_false_negatives == 0
    assert report.evidence_correlation_f1 == pytest.approx(1.0)
