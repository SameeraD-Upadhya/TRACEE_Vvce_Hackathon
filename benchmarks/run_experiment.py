"""Run and report the reconstruction benchmark."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from dataclasses import replace
from pathlib import Path
from typing import Callable

from benchmarks.baselines import (
    chronology_only_predictions,
    rule_correlation_predictions,
)
from benchmarks.evaluate import (
    BenchmarkPrediction,
    EvaluationConfig,
    EvaluationReport,
    evaluate_predictions,
)
from benchmarks.models import (
    BenchmarkInput,
    GeneratedScenario,
    ScenarioFamily,
)
from benchmarks.scenario_generator import (
    NEGATIVE_CONTROL_PROFILE_IDS,
    generate_dataset,
)
from benchmarks.tracee_adapter import tracee_predictions
from tracee.models import ModelValidationError


PredictionMethod = Callable[
    [BenchmarkInput],
    tuple[BenchmarkPrediction, ...],
]

METHODS: tuple[tuple[str, PredictionMethod], ...] = (
    ("chronology_only", chronology_only_predictions),
    ("rule_correlation", rule_correlation_predictions),
    ("tracee", tracee_predictions),
)

DEFINITIVE_STATES = {
    "chronology_only": ("observed",),
    "rule_correlation": ("observed", "rule_correlated"),
    "tracee": ("corroborated",),
}

# These aliases affect evaluation only. Original method states remain
# unchanged in predictions and interpretation_state_counts.
STATE_ALIASES = (
    ("observed", "corroborated"),
    ("rule_correlated", "corroborated"),
)


def _summarize(reports: list[EvaluationReport]) -> dict:
    if not reports:
        return {
            "scenario_count": 0,
            "prediction_count": 0,
            "ground_truth_count": 0,
            "true_positives": 0,
            "false_positives": 0,
            "false_negatives": 0,
            "precision": 0.0,
            "recall": 0.0,
            "f1": 0.0,
            "definitive_prediction_count": 0,
            "unsupported_definitive_count": 0,
            "unsupported_definitive_rate": 0.0,
            "predictions_with_source_provenance": 0,
            "source_provenance_completeness": 0.0,
            "evidence_correlation_scoring_performed": False,
            "evidence_correlation_evaluated_event_count": 0,
            "evidence_correlation_true_positives": 0,
            "evidence_correlation_false_positives": 0,
            "evidence_correlation_false_negatives": 0,
            "evidence_correlation_precision": None,
            "evidence_correlation_recall": None,
            "evidence_correlation_f1": None,
            "interpretation_state_scoring_performed": False,
            "interpretation_state_evaluated_count": 0,
            "interpretation_state_correct_count": 0,
            "interpretation_state_incorrect_count": 0,
            "interpretation_state_accuracy": None,
            "interpretation_state_unmatched_ground_truth_count": 0,
            "interpretation_state_unscored_ground_truth_count": 0,
        }

    tp = sum(report.true_positives for report in reports)
    fp = sum(report.false_positives for report in reports)
    fn = sum(report.false_negatives for report in reports)

    prediction_count = sum(report.prediction_count for report in reports)
    truth_count = sum(report.ground_truth_count for report in reports)
    definitive_count = sum(
        report.definitive_prediction_count for report in reports
    )
    unsupported_count = sum(
        report.unsupported_definitive_count for report in reports
    )
    provenance_count = sum(
        report.predictions_with_source_provenance for report in reports
    )

    evidence_evaluated = sum(
        report.evidence_correlation_evaluated_event_count
        for report in reports
    )
    evidence_tp = sum(
        report.evidence_correlation_true_positives for report in reports
    )
    evidence_fp = sum(
        report.evidence_correlation_false_positives for report in reports
    )
    evidence_fn = sum(
        report.evidence_correlation_false_negatives for report in reports
    )

    if evidence_evaluated:
        evidence_precision = (
            evidence_tp / (evidence_tp + evidence_fp)
            if evidence_tp + evidence_fp
            else 0.0
        )
        evidence_recall = (
            evidence_tp / (evidence_tp + evidence_fn)
            if evidence_tp + evidence_fn
            else 0.0
        )
        evidence_f1 = (
            2 * evidence_precision * evidence_recall
            / (evidence_precision + evidence_recall)
            if evidence_precision + evidence_recall
            else 0.0
        )
    else:
        evidence_precision = None
        evidence_recall = None
        evidence_f1 = None

    state_evaluated = sum(
        report.interpretation_state_evaluated_count for report in reports
    )
    state_correct = sum(
        report.interpretation_state_correct_count for report in reports
    )
    state_incorrect = sum(
        report.interpretation_state_incorrect_count for report in reports
    )
    state_unmatched = sum(
        report.interpretation_state_unmatched_ground_truth_count
        for report in reports
    )
    state_unscored = sum(
        report.interpretation_state_unscored_ground_truth_count
        for report in reports
    )

    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision + recall
        else 0.0
    )

    return {
        "scenario_count": len(reports),
        "prediction_count": prediction_count,
        "ground_truth_count": truth_count,
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "definitive_prediction_count": definitive_count,
        "unsupported_definitive_count": unsupported_count,
        "unsupported_definitive_rate": (
            unsupported_count / definitive_count
            if definitive_count
            else 0.0
        ),
        "predictions_with_source_provenance": provenance_count,
        "source_provenance_completeness": (
            provenance_count / prediction_count
            if prediction_count
            else 0.0
        ),
        "evidence_correlation_scoring_performed": evidence_evaluated > 0,
        "evidence_correlation_evaluated_event_count": evidence_evaluated,
        "evidence_correlation_true_positives": evidence_tp,
        "evidence_correlation_false_positives": evidence_fp,
        "evidence_correlation_false_negatives": evidence_fn,
        "evidence_correlation_precision": evidence_precision,
        "evidence_correlation_recall": evidence_recall,
        "evidence_correlation_f1": evidence_f1,
        "interpretation_state_scoring_performed": all(
            report.interpretation_state_scoring_performed
            for report in reports
        ),
        "interpretation_state_evaluated_count": state_evaluated,
        "interpretation_state_correct_count": state_correct,
        "interpretation_state_incorrect_count": state_incorrect,
        "interpretation_state_accuracy": (
            state_correct / state_evaluated
            if state_evaluated
            else None
        ),
        "interpretation_state_unmatched_ground_truth_count": state_unmatched,
        "interpretation_state_unscored_ground_truth_count": state_unscored,
    }


def run_experiment(
    root_seed: int = 42,
    scenarios_per_family: int = 10,
    evaluation_config: EvaluationConfig | None = None,
    *,
    include_negative_control_profiles: bool = False,
) -> dict:
    """Evaluate each method against the same generated dataset."""

    scenarios = generate_dataset(
        seed=root_seed,
        scenarios_per_family=scenarios_per_family,
        include_negative_control_profiles=include_negative_control_profiles,
    )
    config = (
        evaluation_config
        if evaluation_config is not None
        else EvaluationConfig(allow_unknown_time_for_event_match=False)
    )

    if not isinstance(config, EvaluationConfig):
        raise ModelValidationError(
            "evaluation_config must be an EvaluationConfig"
        )

    method_results = {}

    for method_name, method in METHODS:
        reports: list[EvaluationReport] = []
        definitive_reports: list[EvaluationReport] = []
        state_counts: Counter[str] = Counter()
        scenario_results = []
        definitive_states = DEFINITIVE_STATES[method_name]
        method_config = replace(
            config,
            definitive_states=definitive_states,
            interpretation_state_aliases=STATE_ALIASES,
        )

        for scenario in scenarios:
            if not isinstance(scenario, GeneratedScenario):
                raise ModelValidationError(
                    "Dataset must contain GeneratedScenario values"
                )

            method_input = scenario.method_input
            predictions = tuple(method(method_input))

            available_ids = tuple(
                observation.observation_id
                for observation in method_input.observations
            )
            report = evaluate_predictions(
                predictions,
                scenario.ground_truth.events,
                config=method_config,
                available_observation_ids=available_ids,
            )
            reports.append(report)

            definitive_predictions = tuple(
                prediction for prediction in predictions
                if prediction.interpretation_state in definitive_states
            )
            definitive_report = evaluate_predictions(
                definitive_predictions,
                scenario.ground_truth.events,
                config=method_config,
                available_observation_ids=available_ids,
            )
            definitive_reports.append(definitive_report)

            counts = Counter(
                prediction.interpretation_state
                for prediction in predictions
            )
            state_counts.update(counts)
            scenario_results.append({
                "scenario_id": method_input.scenario_id,
                "family": scenario.ground_truth.family.value,
                "profile_id": scenario.ground_truth.profile_id,
                "event_matching_included_in_aggregate": (
                    scenario.ground_truth.event_matching_eligible
                ),
                "event_matching_exclusion_reason": (
                    None
                    if scenario.ground_truth.event_matching_eligible
                    else "Timestamp conflict is ambiguous because the clock offset is hidden."
                ),
                "predictions": [
                    prediction.to_dict() for prediction in predictions
                ],
                "evaluation": report.to_dict(),
                "definitive_prediction_evaluation": (
                    definitive_report.to_dict()
                ),
                "interpretation_state_counts": dict(sorted(counts.items())),
            })

        by_family = {}
        by_family_detail = {}

        for family in ScenarioFamily:
            family_items = [
                (scenario, report, definitive_report)
                for scenario, report, definitive_report in zip(
                    scenarios, reports, definitive_reports
                )
                if scenario.ground_truth.family is family
            ]
            scored_items = [
                item for item in family_items
                if item[0].ground_truth.event_matching_eligible
            ]
            diagnostic_items = [
                item for item in family_items
                if not item[0].ground_truth.event_matching_eligible
            ]

            family_reports = [item[1] for item in scored_items]
            family_definitive_reports = [item[2] for item in scored_items]
            by_family[family.value] = _summarize(family_reports)

            family_scenarios = [
                item for item in scenario_results
                if item["family"] == family.value
            ]
            family_states: Counter[str] = Counter()
            for item in family_scenarios:
                family_states.update(item["interpretation_state_counts"])

            details = {
                "event_matching_included_in_aggregate": bool(scored_items),
                "scored_scenario_count": len(scored_items),
                "excluded_scenario_count": len(diagnostic_items),
                "candidate_matching": _summarize(family_reports),
                "definitive_prediction_detection": _summarize(
                    family_definitive_reports
                ),
                "interpretation_state_counts": dict(
                    sorted(family_states.items())
                ),
            }

            if diagnostic_items:
                details["diagnostic_only_candidate_matching"] = (
                    _summarize([item[1] for item in diagnostic_items])
                )
                details["diagnostic_only_definitive_prediction_detection"] = (
                    _summarize([item[2] for item in diagnostic_items])
                )

            by_family_detail[family.value] = details

        by_profile = {}
        for profile_id in NEGATIVE_CONTROL_PROFILE_IDS:
            profile_items = [
                (scenario, report, definitive_report)
                for scenario, report, definitive_report in zip(
                    scenarios, reports, definitive_reports
                )
                if (
                    scenario.ground_truth.profile_id == profile_id
                    and scenario.ground_truth.event_matching_eligible
                )
            ]
            if profile_items:
                by_profile[profile_id] = {
                    "candidate_matching": _summarize(
                        [item[1] for item in profile_items]
                    ),
                    "definitive_prediction_detection": _summarize(
                        [item[2] for item in profile_items]
                    ),
                }

        scored_pairs = [
            (scenario, report, definitive_report)
            for scenario, report, definitive_report in zip(
                scenarios, reports, definitive_reports
            )
            if scenario.ground_truth.event_matching_eligible
        ]
        scored_reports = [item[1] for item in scored_pairs]
        scored_definitive_reports = [item[2] for item in scored_pairs]
        candidate_summary = _summarize(scored_reports)

        method_results[method_name] = {
            "overall": candidate_summary,
            "candidate_matching": candidate_summary,
            "definitive_prediction_detection": _summarize(
                scored_definitive_reports
            ),
            "interpretation_state_counts": dict(sorted(state_counts.items())),
            "definitive_states_used": list(definitive_states),
            "by_family": by_family,
            "by_family_detail": by_family_detail,
            "by_profile": by_profile,
            "scenarios": scenario_results,
        }

    return {
        "schema_version": "1.5",
        "experiment": {
            "root_seed": root_seed,
            "scenarios_per_family": scenarios_per_family,
            "negative_control_profiles_included": (
                include_negative_control_profiles
            ),
            "included_profile_ids": (
                list(NEGATIVE_CONTROL_PROFILE_IDS)
                if include_negative_control_profiles
                else []
            ),
            "profile_scenario_count": sum(
                scenario.ground_truth.profile_id is not None
                for scenario in scenarios
            ),
            "scenario_count": len(scenarios),
            "event_matching_eligible_scenario_count": sum(
                scenario.ground_truth.event_matching_eligible
                for scenario in scenarios
            ),
            "event_matching_excluded_scenario_count": sum(
                not scenario.ground_truth.event_matching_eligible
                for scenario in scenarios
            ),
            "event_matching_eligible_scenario_families": [
                family.value for family in ScenarioFamily
                if any(
                    scenario.ground_truth.family is family
                    and scenario.ground_truth.event_matching_eligible
                    for scenario in scenarios
                )
            ],
            "event_matching_exclusion_policy": (
                "Ineligible scenarios remain in per-scenario results "
                "and diagnostic metrics, but are excluded from primary "
                "aggregate event-matching scores."
            ),
            "scenario_families": [
                family.value for family in ScenarioFamily
            ],
            "evaluation_config": config.to_dict(),
            "definitive_state_policy": {
                name: list(states)
                for name, states in DEFINITIVE_STATES.items()
            },
            "metric_definitions": {
                "candidate_matching": (
                    "Scores all method predictions against ground truth, "
                    "regardless of interpretation state."
                ),
                "definitive_prediction_detection": (
                    "Scores only predictions selected by the declared "
                    "method-specific definitive-state policy."
                ),
                "interpretation_state_accuracy": (
                    "Compares normalized predicted states with explicit "
                    "expected states for matched ground-truth events. "
                    "Unmatched and unscored events are reported "
                    "separately."
                ),
                "interpretation_state_aliases": (
                    "Baseline states are mapped to canonical evaluation "
                    "states; original prediction labels are preserved."
                ),
            },
            "scope": (
                "Synthetic benchmark results; they do not establish "
                "performance on real-world investigations."
            ),
        },
        "methods": method_results,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Compare TRACEE reconstruction methods."
    )
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument(
        "--scenarios-per-family", type=int, default=10
    )
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--include-negative-control-profiles",
        action="store_true",
        help="Append exploratory NEG-CTRL profiles to the baseline dataset.",
    )

    args = parser.parse_args()

    try:
        report = run_experiment(
            root_seed=args.seed,
            scenarios_per_family=args.scenarios_per_family,
            include_negative_control_profiles=(
                args.include_negative_control_profiles
            ),
        )
        encoded = json.dumps(
            report,
            indent=2,
            sort_keys=True,
            allow_nan=False,
        )

        if args.output is None:
            print(encoded)
        else:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(encoded + "\n", encoding="utf-8")
            print(f"[PASS] Report written to {args.output}")

        return 0

    except (ModelValidationError, OSError, TypeError, ValueError) as exc:
        parser.exit(1, f"[ERROR] {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
