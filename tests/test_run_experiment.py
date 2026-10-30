"""Tests for the benchmark experiment runner."""

import json

from benchmarks.models import ScenarioFamily
from benchmarks.run_experiment import run_experiment


def test_experiment_runs_all_methods_on_same_scenario_count():
    result = run_experiment(root_seed=23, scenarios_per_family=1)

    assert result["experiment"]["scenario_count"] == len(ScenarioFamily)
    assert set(result["methods"]) == {
        "chronology_only",
        "rule_correlation",
        "tracee",
    }

    for method_result in result["methods"].values():
        assert method_result["overall"]["scenario_count"] == (
            result["experiment"]["event_matching_eligible_scenario_count"]
        )
        assert len(method_result["scenarios"]) == len(ScenarioFamily)
        assert set(method_result["by_family"]) == {
            family.value for family in ScenarioFamily
        }


def test_experiment_records_predictions_and_evaluation_details():
    result = run_experiment(root_seed=31, scenarios_per_family=1)

    for method_result in result["methods"].values():
        for scenario in method_result["scenarios"]:
            assert scenario["scenario_id"]
            assert scenario["family"] in {
                family.value for family in ScenarioFamily
            }
            assert isinstance(scenario["predictions"], list)
            assert "true_positives" in scenario["evaluation"]
            assert "matched_pairs" in scenario["evaluation"]


def test_experiment_is_reproducible():
    first = run_experiment(root_seed=91, scenarios_per_family=1)
    second = run_experiment(root_seed=91, scenarios_per_family=1)

    assert first == second


def test_candidate_and_definitive_metrics_are_reported_separately():
    result = run_experiment(root_seed=42, scenarios_per_family=1)
    tracee = result["methods"]["tracee"]

    assert "candidate_matching" in tracee
    assert "definitive_prediction_detection" in tracee
    assert "interpretation_state_counts" in tracee
    assert tracee["definitive_states_used"] == ["corroborated"]

    missing = next(
        item for item in tracee["scenarios"]
        if item["family"] == "missing_record"
    )
    assert missing["evaluation"]["true_positives"] == 1
    assert missing["definitive_prediction_evaluation"]["true_positives"] == 0
    assert missing["interpretation_state_counts"] == {
        "challenged": 1
    }


def test_evidence_correlation_metrics_are_aggregated_separately():
    result = run_experiment(root_seed=42, scenarios_per_family=1)

    count_fields = (
        "evidence_correlation_evaluated_event_count",
        "evidence_correlation_true_positives",
        "evidence_correlation_false_positives",
        "evidence_correlation_false_negatives",
    )

    for method_result in result["methods"].values():
        overall = method_result["overall"]
        scored = [
            item for item in method_result["scenarios"]
            if item["event_matching_included_in_aggregate"]
        ]

        assert overall["evidence_correlation_scoring_performed"] is True
        assert overall["evidence_correlation_evaluated_event_count"] > 0

        for field in count_fields:
            assert overall[field] == sum(
                item["evaluation"][field] for item in scored
            )

        assert overall["evidence_correlation_precision"] is not None
        assert overall["evidence_correlation_recall"] is not None
        assert overall["evidence_correlation_f1"] is not None


def test_empty_family_summary_marks_unavailable_metrics_as_null():
    result = run_experiment(root_seed=42, scenarios_per_family=1)
    empty = result["methods"]["tracee"]["by_family"][
        "conflicting_timestamps"
    ]

    assert empty["scenario_count"] == 0
    assert empty["interpretation_state_scoring_performed"] is False
    assert empty["interpretation_state_accuracy"] is None
    assert empty["evidence_correlation_scoring_performed"] is False
    assert empty["evidence_correlation_precision"] is None
    assert empty["evidence_correlation_recall"] is None
    assert empty["evidence_correlation_f1"] is None


def test_timestamp_conflict_is_retained_as_diagnostic():
    result = run_experiment(root_seed=42, scenarios_per_family=1)
    tracee = result["methods"]["tracee"]
    metrics = tracee["by_family_detail"]["conflicting_timestamps"]

    assert metrics["event_matching_included_in_aggregate"] is False
    assert metrics["scored_scenario_count"] == 0
    assert metrics["excluded_scenario_count"] == 1

    diagnostic = metrics["diagnostic_only_candidate_matching"]
    assert diagnostic["true_positives"] == 1
    assert diagnostic["false_positives"] == 1
    assert diagnostic["false_negatives"] == 0

    definitive = metrics["diagnostic_only_definitive_prediction_detection"]
    assert definitive["false_positives"] == 1

    scenario = next(
        item for item in tracee["scenarios"]
        if item["family"] == "conflicting_timestamps"
    )
    assert scenario["event_matching_included_in_aggregate"] is False
    assert scenario["evaluation"]["false_positives"] == 1


def test_report_declares_timestamp_conflict_exclusion():
    result = run_experiment(root_seed=42, scenarios_per_family=2)
    experiment = result["experiment"]

    assert experiment["scenario_count"] == len(ScenarioFamily) * 2
    assert experiment["event_matching_excluded_scenario_count"] == 2
    assert experiment["event_matching_eligible_scenario_count"] == (
        len(experiment["event_matching_eligible_scenario_families"]) * 2
    )
    assert "conflicting_timestamps" not in (
        experiment["event_matching_eligible_scenario_families"]
    )


def test_family_details_include_definitive_metrics_and_states():
    result = run_experiment(root_seed=42, scenarios_per_family=1)
    tracee = result["methods"]["tracee"]
    missing = tracee["by_family_detail"]["missing_record"]

    assert missing["candidate_matching"]["true_positives"] == 1
    assert missing["definitive_prediction_detection"]["false_negatives"] == 1
    assert missing["interpretation_state_counts"] == {
        "challenged": 1
    }


def test_experiment_report_is_json_serializable():
    result = run_experiment(root_seed=17, scenarios_per_family=1)

    encoded = json.dumps(result, allow_nan=False)
    decoded = json.loads(encoded)

    assert decoded["schema_version"] == "1.5"
    assert len(decoded["methods"]) == 3


def test_interpretation_state_metrics_and_primary_time_policy_are_reported():
    result = run_experiment(root_seed=42, scenarios_per_family=1)

    assert result["experiment"]["evaluation_config"][
        "allow_unknown_time_for_event_match"
    ] is False

    for method_result in result["methods"].values():
        overall = method_result["overall"]
        assert overall["interpretation_state_scoring_performed"] is True
        assert "interpretation_state_accuracy" in overall
        assert "interpretation_state_evaluated_count" in overall
        assert "interpretation_state_unmatched_ground_truth_count" in overall
        assert "interpretation_state_unscored_ground_truth_count" in overall

    chronology = result["methods"]["chronology_only"]
    complete = next(
        item for item in chronology["scenarios"]
        if item["family"] == "complete_records"
    )

    assert complete["evaluation"]["config"][
        "interpretation_state_aliases"
    ] == {
        "observed": "corroborated",
        "rule_correlated": "corroborated",
    }

    assert complete["predictions"][0]["interpretation_state"] == "observed"


def test_aggregate_counts_cover_primary_scored_scenarios():
    result = run_experiment(root_seed=11, scenarios_per_family=2)
    expected_scenarios = result["experiment"][
        "event_matching_eligible_scenario_count"
    ]

    for method_result in result["methods"].values():
        overall = method_result["overall"]
        assert overall["scenario_count"] == expected_scenarios

        scored = [
            item for item in method_result["scenarios"]
            if item["event_matching_included_in_aggregate"]
        ]
        assert overall["prediction_count"] == sum(
            item["evaluation"]["prediction_count"] for item in scored
        )
        assert overall["ground_truth_count"] == sum(
            item["evaluation"]["ground_truth_count"] for item in scored
        )

def test_negative_control_profiles_are_opt_in_and_reported_separately():
    profiles = ("NEG-CTRL-01", "NEG-CTRL-02", "NEG-CTRL-03")

    baseline = run_experiment(root_seed=23, scenarios_per_family=2)
    extended = run_experiment(
        root_seed=23,
        scenarios_per_family=2,
        include_negative_control_profiles=True,
    )

    baseline_meta = baseline["experiment"]
    extended_meta = extended["experiment"]

    assert baseline_meta["negative_control_profiles_included"] is False
    assert baseline_meta["included_profile_ids"] == []
    assert baseline_meta["profile_scenario_count"] == 0
    assert baseline_meta["scenario_count"] == len(ScenarioFamily) * 2

    assert extended_meta["negative_control_profiles_included"] is True
    assert extended_meta["included_profile_ids"] == list(profiles)
    assert extended_meta["profile_scenario_count"] == len(profiles) * 2
    assert extended_meta["scenario_count"] == (
        len(ScenarioFamily) * 2 + len(profiles) * 2
    )

    # Compare full per-scenario results, not only IDs, for every method.
    for method_name in baseline["methods"]:
        baseline_scenarios = baseline["methods"][method_name]["scenarios"]
        extended_scenarios = extended["methods"][method_name]["scenarios"]
        extended_baseline_scenarios = [
            item for item in extended_scenarios
            if item["profile_id"] is None
        ]
        assert baseline_scenarios == extended_baseline_scenarios

    for method_result in extended["methods"].values():
        assert set(method_result["by_profile"]) == set(profiles)
        assert len(method_result["scenarios"]) == extended_meta["scenario_count"]

        for profile_id in profiles:
            metrics = method_result["by_profile"][profile_id]
            assert metrics["candidate_matching"]["scenario_count"] == 2
            assert (
                metrics["definitive_prediction_detection"]["scenario_count"]
                == 2
            )

    tracee = extended["methods"]["tracee"]

    for profile_id in profiles:
        metrics = tracee["by_profile"][profile_id]
        assert metrics["candidate_matching"]["false_positives"] == 2
        assert metrics["candidate_matching"]["true_positives"] == 0
        assert metrics["candidate_matching"]["false_negatives"] == 0
        assert (
            metrics["definitive_prediction_detection"]["prediction_count"]
            == 0
        )

        profile_scenarios = [
            item for item in tracee["scenarios"]
            if item["profile_id"] == profile_id
        ]
        assert len(profile_scenarios) == 2
        assert all(
            item["evaluation"]["false_positives"] == 1
            for item in profile_scenarios
        )
        assert all(
            any(
                prediction["interpretation_state"] == "insufficient_input"
                for prediction in item["predictions"]
            )
            for item in profile_scenarios
        )
