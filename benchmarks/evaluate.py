
"""Evaluation rules for TRACEE's synthetic reconstruction benchmark."""

from __future__ import annotations

from collections.abc import Iterable

from dataclasses import dataclass
from datetime import timedelta
from types import MappingProxyType
from typing import Any, Mapping

from tracee.events import TemporalExtent
from tracee.models import ModelValidationError

from .models import GroundTruthEvent


def _require_text(value: str, name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ModelValidationError(f"{name} must be a non-empty string")


def _freeze_json(value: Any, path: str = "attributes") -> Any:
    if isinstance(value, Mapping):
        frozen = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise ModelValidationError(f"{path} keys must be strings")
            frozen[key] = _freeze_json(item, f"{path}.{key}")
        return MappingProxyType(frozen)

    if isinstance(value, (list, tuple)):
        return tuple(
            _freeze_json(item, f"{path}[{index}]")
            for index, item in enumerate(value)
        )

    if value is None or isinstance(value, (str, bool, int)):
        return value

    if isinstance(value, float):
        import math
        if math.isfinite(value):
            return value

    raise ModelValidationError(
        f"{path} contains a value that is not valid JSON data"
    )


def _plain(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    return value


@dataclass(frozen=True)
class BenchmarkPrediction:
    """A method's claim that a particular event occurred."""

    prediction_id: str
    event_type: str
    entity_attributes: Mapping[str, Any]
    temporal_extent: TemporalExtent
    source_observation_ids: tuple[str, ...] = ()
    interpretation_state: str = "unclassified"
    inference_rule_id: str | None = None
    inference_rule_version: str | None = None
    correlated_observation_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _require_text(self.prediction_id, "prediction_id")
        _require_text(self.event_type, "event_type")
        _require_text(self.interpretation_state, "interpretation_state")

        if not isinstance(self.entity_attributes, Mapping):
            raise ModelValidationError(
                "entity_attributes must be a mapping"
            )

        object.__setattr__(
            self,
            "entity_attributes",
            _freeze_json(self.entity_attributes, "entity_attributes"),
        )

        if not isinstance(self.temporal_extent, TemporalExtent):
            raise ModelValidationError(
                "temporal_extent must be a TemporalExtent"
            )

        if isinstance(self.source_observation_ids, str):
            raise ModelValidationError(
                "source_observation_ids must be a sequence"
            )

        try:
            source_ids = tuple(self.source_observation_ids)
        except TypeError as exc:
            raise ModelValidationError(
                "source_observation_ids must be a sequence"
            ) from exc

        for source_id in source_ids:
            _require_text(source_id, "source observation ID")

        if len(source_ids) != len(set(source_ids)):
            raise ModelValidationError(
                "source_observation_ids must not contain duplicates"
            )

        object.__setattr__(self, "source_observation_ids", source_ids)

        if isinstance(self.correlated_observation_ids, str):
            raise ModelValidationError(
                "correlated_observation_ids must be a sequence"
            )
        try:
            correlated_ids = tuple(self.correlated_observation_ids)
        except TypeError as exc:
            raise ModelValidationError(
                "correlated_observation_ids must be a sequence"
            ) from exc

        for correlated_id in correlated_ids:
            _require_text(correlated_id, "correlated observation ID")

        if len(correlated_ids) != len(set(correlated_ids)):
            raise ModelValidationError(
                "correlated_observation_ids must not contain duplicates"
            )
        if set(correlated_ids) & set(source_ids):
            raise ModelValidationError(
                "Direct and correlated observation IDs must be distinct"
            )
        object.__setattr__(
            self, "correlated_observation_ids", correlated_ids
        )

        if self.inference_rule_id is not None:
            _require_text(self.inference_rule_id, "inference_rule_id")

        if self.inference_rule_version is not None:
            _require_text(
                self.inference_rule_version, "inference_rule_version"
            )

        if (
            self.inference_rule_version is not None
            and self.inference_rule_id is None
        ):
            raise ModelValidationError(
                "A rule version requires an inference_rule_id"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "prediction_id": self.prediction_id,
            "event_type": self.event_type,
            "entity_attributes": _plain(self.entity_attributes),
            "temporal_extent": self.temporal_extent.to_dict(),
            "source_observation_ids": list(self.source_observation_ids),
            "correlated_observation_ids": list(
                self.correlated_observation_ids
            ),
            "interpretation_state": self.interpretation_state,
            "inference_rule_id": self.inference_rule_id,
            "inference_rule_version": self.inference_rule_version,
        }


@dataclass(frozen=True)
class EvaluationConfig:
    """Pre-declared event-matching and metric rules."""

    entity_key_attributes: tuple[str, ...] = ("user", "host")
    time_tolerance_seconds: int = 60
    allow_unknown_time_for_event_match: bool = False
    definitive_states: tuple[str, ...] = ("corroborated",)
    interpretation_state_aliases: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        if isinstance(self.entity_key_attributes, str):
            raise ModelValidationError(
                "entity_key_attributes must be a sequence"
            )

        keys = tuple(self.entity_key_attributes)
        for key in keys:
            _require_text(key, "entity key attribute")

        if not keys:
            raise ModelValidationError(
                "At least one entity key attribute is required"
            )
        if len(keys) != len(set(keys)):
            raise ModelValidationError(
                "Entity key attributes must be unique"
            )
        object.__setattr__(self, "entity_key_attributes", keys)

        tolerance = self.time_tolerance_seconds
        if (
            not isinstance(tolerance, int)
            or isinstance(tolerance, bool)
            or tolerance < 0
        ):
            raise ModelValidationError(
                "time_tolerance_seconds must be a non-negative integer"
            )

        if not isinstance(self.allow_unknown_time_for_event_match, bool):
            raise ModelValidationError(
                "allow_unknown_time_for_event_match must be a boolean"
            )

        if isinstance(self.definitive_states, str):
            raise ModelValidationError(
                "definitive_states must be a sequence"
            )

        states = tuple(self.definitive_states)
        for state in states:
            _require_text(state, "definitive state")
        if len(states) != len(set(states)):
            raise ModelValidationError(
                "definitive_states must not contain duplicates"
            )
        object.__setattr__(self, "definitive_states", states)

        raw_aliases = self.interpretation_state_aliases
        if isinstance(raw_aliases, (str, bytes)):
            raise ModelValidationError(
                "interpretation_state_aliases must be a sequence of pairs"
            )
        try:
            raw_aliases = tuple(raw_aliases)
        except TypeError as exc:
            raise ModelValidationError(
                "interpretation_state_aliases must be iterable"
            ) from exc

        allowed_states = {
            "corroborated",
            "challenged",
            "underdetermined",
            "insufficient_input",
        }
        aliases = []
        alias_sources = set()

        for pair in raw_aliases:
            if (
                isinstance(pair, (str, bytes))
                or not isinstance(pair, (tuple, list))
                or len(pair) != 2
            ):
                raise ModelValidationError(
                    "Each interpretation-state alias must be a pair"
                )

            source, target = pair
            _require_text(source, "interpretation-state alias source")
            _require_text(target, "interpretation-state alias target")

            if source in alias_sources:
                raise ModelValidationError(
                    "Interpretation-state alias sources must be unique"
                )
            if target not in allowed_states:
                raise ModelValidationError(
                    "Interpretation-state alias targets must be supported "
                    "canonical states"
                )

            alias_sources.add(source)
            aliases.append((source, target))

        object.__setattr__(
            self, "interpretation_state_aliases", tuple(aliases)
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "entity_key_attributes": list(self.entity_key_attributes),
            "time_tolerance_seconds": self.time_tolerance_seconds,
            "allow_unknown_time_for_event_match": (
                self.allow_unknown_time_for_event_match
            ),
            "definitive_states": list(self.definitive_states),
            "interpretation_state_aliases": {
                source: target
                for source, target in self.interpretation_state_aliases
            },
        }


@dataclass(frozen=True)
class EvaluationReport:
    """Auditable scoring results for one method on one scenario."""

    config: EvaluationConfig
    prediction_count: int
    ground_truth_count: int
    true_positives: int
    false_positives: int
    false_negatives: int
    precision: float
    recall: float
    f1: float
    definitive_prediction_count: int
    unsupported_definitive_count: int
    unsupported_definitive_rate: float
    predictions_with_source_provenance: int
    source_provenance_completeness: float
    provenance_validation_performed: bool
    invalid_source_reference_count: int
    evidence_correlation_scoring_performed: bool
    evidence_correlation_evaluated_event_count: int
    evidence_correlation_true_positives: int
    evidence_correlation_false_positives: int
    evidence_correlation_false_negatives: int
    evidence_correlation_precision: float | None
    evidence_correlation_recall: float | None
    evidence_correlation_f1: float | None
    interpretation_state_scoring_performed: bool
    interpretation_state_evaluated_count: int
    interpretation_state_correct_count: int
    interpretation_state_incorrect_count: int
    interpretation_state_accuracy: float | None
    interpretation_state_unmatched_ground_truth_count: int
    interpretation_state_unscored_ground_truth_count: int
    interpretation_state_mismatches: tuple[
        tuple[str, str, str, str], ...
    ]
    matched_pairs: tuple[tuple[str, str], ...]
    unmatched_prediction_ids: tuple[str, ...]
    unmatched_ground_truth_ids: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "config": self.config.to_dict(),
            "prediction_count": self.prediction_count,
            "ground_truth_count": self.ground_truth_count,
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "false_negatives": self.false_negatives,
            "precision": self.precision,
            "recall": self.recall,
            "f1": self.f1,
            "definitive_prediction_count": self.definitive_prediction_count,
            "unsupported_definitive_count": self.unsupported_definitive_count,
            "unsupported_definitive_rate": self.unsupported_definitive_rate,
            "predictions_with_source_provenance": (
                self.predictions_with_source_provenance
            ),
            "source_provenance_completeness": (
                self.source_provenance_completeness
            ),
            "provenance_validation_performed": (
                self.provenance_validation_performed
            ),
            "invalid_source_reference_count": (
                self.invalid_source_reference_count
            ),
            "evidence_correlation_scoring_performed": (
                self.evidence_correlation_scoring_performed
            ),
            "evidence_correlation_evaluated_event_count": (
                self.evidence_correlation_evaluated_event_count
            ),
            "evidence_correlation_true_positives": (
                self.evidence_correlation_true_positives
            ),
            "evidence_correlation_false_positives": (
                self.evidence_correlation_false_positives
            ),
            "evidence_correlation_false_negatives": (
                self.evidence_correlation_false_negatives
            ),
            "evidence_correlation_precision": (
                self.evidence_correlation_precision
            ),
            "evidence_correlation_recall": (
                self.evidence_correlation_recall
            ),
            "evidence_correlation_f1": (
                self.evidence_correlation_f1
            ),
            "interpretation_state_scoring_performed": (
                self.interpretation_state_scoring_performed
            ),
            "interpretation_state_evaluated_count": (
                self.interpretation_state_evaluated_count
            ),
            "interpretation_state_correct_count": (
                self.interpretation_state_correct_count
            ),
            "interpretation_state_incorrect_count": (
                self.interpretation_state_incorrect_count
            ),
            "interpretation_state_accuracy": (
                self.interpretation_state_accuracy
            ),
            "interpretation_state_unmatched_ground_truth_count": (
                self.interpretation_state_unmatched_ground_truth_count
            ),
            "interpretation_state_unscored_ground_truth_count": (
                self.interpretation_state_unscored_ground_truth_count
            ),
            "interpretation_state_mismatches": [
                {
                    "prediction_id": item[0],
                    "ground_truth_event_id": item[1],
                    "predicted_state": item[2],
                    "expected_state": item[3],
                }
                for item in self.interpretation_state_mismatches
            ],
            "matched_pairs": [
                {
                    "prediction_id": prediction_id,
                    "ground_truth_event_id": event_id,
                }
                for prediction_id, event_id in self.matched_pairs
            ],
            "unmatched_prediction_ids": list(
                self.unmatched_prediction_ids
            ),
            "unmatched_ground_truth_ids": list(
                self.unmatched_ground_truth_ids
            ),
        }


def _event_time_matches(
    prediction: TemporalExtent,
    truth: TemporalExtent,
    config: EvaluationConfig,
) -> bool:
    p_start = prediction.earliest_utc
    p_end = prediction.latest_utc
    t_start = truth.earliest_utc
    t_end = truth.latest_utc

    if None in (p_start, p_end, t_start, t_end):
        return config.allow_unknown_time_for_event_match

    tolerance = timedelta(seconds=config.time_tolerance_seconds)

    return (
        p_start <= t_end + tolerance
        and t_start <= p_end + tolerance
    )


def prediction_matches_truth(
    prediction: BenchmarkPrediction,
    truth: GroundTruthEvent,
    config: EvaluationConfig,
) -> bool:
    """Apply the pre-declared event type, identity, and time criteria."""

    if prediction.event_type != truth.event_type:
        return False

    for key in config.entity_key_attributes:
        if key not in prediction.entity_attributes:
            return False
        if key not in truth.entity_attributes:
            return False
        if prediction.entity_attributes[key] != truth.entity_attributes[key]:
            return False

    return _event_time_matches(
        prediction.temporal_extent,
        truth.temporal_extent,
        config,
    )


def evaluate_predictions(
    predictions: tuple[BenchmarkPrediction, ...],
    ground_truth_events: tuple[GroundTruthEvent, ...],
    config: EvaluationConfig | None = None,
    *,
    available_observation_ids: Iterable[str] | None = None,
) -> EvaluationReport:
    """Score predictions with deterministic one-to-one event matching."""

    if config is None:
        config = EvaluationConfig()
    if not isinstance(config, EvaluationConfig):
        raise ModelValidationError("config must be an EvaluationConfig")

    predictions = tuple(predictions)
    ground_truth_events = tuple(ground_truth_events)
    available_ids = None

    if available_observation_ids is not None:
        if isinstance(available_observation_ids, (str, bytes)):
            raise ModelValidationError(
                "available_observation_ids must be a sequence of IDs"
            )
        try:
            supplied_ids = tuple(available_observation_ids)
        except TypeError as exc:
            raise ModelValidationError(
                "available_observation_ids must be iterable"
            ) from exc
        if any(
            not isinstance(item, str) or not item.strip()
            for item in supplied_ids
        ):
            raise ModelValidationError(
                "available observation IDs must be non-empty strings"
            )
        if len(supplied_ids) != len(set(supplied_ids)):
            raise ModelValidationError(
                "available observation IDs must be unique"
            )
        available_ids = set(supplied_ids)

    if any(
        not isinstance(item, BenchmarkPrediction)
        for item in predictions
    ):
        raise ModelValidationError(
            "predictions must contain BenchmarkPrediction values"
        )
    if any(
        not isinstance(item, GroundTruthEvent)
        for item in ground_truth_events
    ):
        raise ModelValidationError(
            "ground_truth_events must contain GroundTruthEvent values"
        )

    prediction_ids = [item.prediction_id for item in predictions]
    truth_ids = [item.event_id for item in ground_truth_events]

    if len(prediction_ids) != len(set(prediction_ids)):
        raise ModelValidationError("Prediction IDs must be unique")
    if len(truth_ids) != len(set(truth_ids)):
        raise ModelValidationError("Ground-truth event IDs must be unique")

    predictions = tuple(sorted(predictions, key=lambda item: item.prediction_id))
    ground_truth_events = tuple(
        sorted(ground_truth_events, key=lambda item: item.event_id)
    )

    edges = {
        index: tuple(
            truth_index
            for truth_index, truth in enumerate(ground_truth_events)
            if prediction_matches_truth(prediction, truth, config)
        )
        for index, prediction in enumerate(predictions)
    }

    # Deterministic maximum bipartite matching prevents duplicate
    # predictions from receiving credit for the same ground-truth event.
    truth_to_prediction: dict[int, int] = {}

    def try_match(
        prediction_index: int,
        visited_truth: set[int],
    ) -> bool:
        for truth_index in edges[prediction_index]:
            if truth_index in visited_truth:
                continue

            visited_truth.add(truth_index)
            existing_prediction = truth_to_prediction.get(truth_index)

            if existing_prediction is None or try_match(
                existing_prediction,
                visited_truth,
            ):
                truth_to_prediction[truth_index] = prediction_index
                return True

        return False

    for prediction_index in range(len(predictions)):
        try_match(prediction_index, set())

    matched_prediction_indices = set(truth_to_prediction.values())
    matched_truth_indices = set(truth_to_prediction)

    matched_pairs = tuple(sorted(
        (
            predictions[prediction_index].prediction_id,
            ground_truth_events[truth_index].event_id,
        )
        for truth_index, prediction_index in truth_to_prediction.items()
    ))

    unmatched_predictions = tuple(
        predictions[index].prediction_id
        for index in range(len(predictions))
        if index not in matched_prediction_indices
    )
    unmatched_truth = tuple(
        ground_truth_events[index].event_id
        for index in range(len(ground_truth_events))
        if index not in matched_truth_indices
    )

    state_mismatches = []
    state_evaluated = 0
    state_correct = 0
    state_unmatched_truth = sum(
        1 for index, item in enumerate(ground_truth_events)
        if index not in matched_truth_indices
        and item.expected_interpretation_state is not None
    )
    state_unscored_truth = sum(
        1 for item in ground_truth_events
        if item.expected_interpretation_state is None
    )

    for truth_index, prediction_index in sorted(
        truth_to_prediction.items()
    ):
        truth_event = ground_truth_events[truth_index]
        expected_state = truth_event.expected_interpretation_state
        if expected_state is None:
            continue
        item = predictions[prediction_index]
        state_evaluated += 1
        normalized_state = dict(
            config.interpretation_state_aliases
        ).get(item.interpretation_state, item.interpretation_state)
        if normalized_state == expected_state:
            state_correct += 1
        else:
            state_mismatches.append((
                item.prediction_id,
                truth_event.event_id,
                item.interpretation_state,
                expected_state,
            ))

    state_incorrect = len(state_mismatches)
    state_accuracy = (
        state_correct / state_evaluated if state_evaluated else None
    )

    true_positives = len(matched_pairs)
    false_positives = len(predictions) - true_positives
    false_negatives = len(ground_truth_events) - true_positives

    precision = (
        true_positives / len(predictions) if predictions else 0.0
    )
    recall = (
        true_positives / len(ground_truth_events)
        if ground_truth_events else 0.0
    )
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision + recall else 0.0
    )

    definitive_indices = {
        index
        for index, prediction in enumerate(predictions)
        if prediction.interpretation_state in config.definitive_states
    }
    unsupported_definitive_count = len(
        definitive_indices - matched_prediction_indices
    )
    unsupported_definitive_rate = (
        unsupported_definitive_count / len(definitive_indices)
        if definitive_indices else 0.0
    )

    provenance_validation_performed = available_ids is not None
    invalid_source_reference_count = 0
    provenance_count = 0

    if available_ids is not None:
        for prediction in predictions:
            source_ids = (
                set(prediction.source_observation_ids)
                | set(prediction.correlated_observation_ids)
            )
            if source_ids and source_ids <= available_ids:
                provenance_count += 1
            elif source_ids - available_ids:
                invalid_source_reference_count += 1

    provenance_completeness = (
        provenance_count / len(predictions) if predictions else 0.0
    )

    # Score source-to-event evidence alignment only when the supplied input
    # allows at least one expected record for a matched event to be checked.
    # Expected records omitted from the input are deliberately excluded.
    evidence_evaluated_event_count = 0
    evidence_tp = 0
    evidence_fp = 0
    evidence_fn = 0

    if available_ids is not None:
        for truth_index, prediction_index in truth_to_prediction.items():
            expected_available = (
                set(ground_truth_events[truth_index].expected_record_ids)
                & available_ids
            )
            if not expected_available:
                continue

            prediction = predictions[prediction_index]
            cited_ids = (
                set(prediction.source_observation_ids)
                | set(prediction.correlated_observation_ids)
            )
            correct_ids = cited_ids & expected_available

            evidence_evaluated_event_count += 1
            evidence_tp += len(correct_ids)
            evidence_fp += len(cited_ids - correct_ids)
            evidence_fn += len(expected_available - correct_ids)

    evidence_scoring_performed = evidence_evaluated_event_count > 0

    if evidence_scoring_performed:
        evidence_precision = (
            evidence_tp / (evidence_tp + evidence_fp)
            if evidence_tp + evidence_fp
            else 0.0
        )
        evidence_recall = evidence_tp / (evidence_tp + evidence_fn)
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

    return EvaluationReport(
        config=config,
        prediction_count=len(predictions),
        ground_truth_count=len(ground_truth_events),
        true_positives=true_positives,
        false_positives=false_positives,
        false_negatives=false_negatives,
        precision=precision,
        recall=recall,
        f1=f1,
        definitive_prediction_count=len(definitive_indices),
        unsupported_definitive_count=unsupported_definitive_count,
        unsupported_definitive_rate=unsupported_definitive_rate,
        predictions_with_source_provenance=provenance_count,
        source_provenance_completeness=provenance_completeness,
        provenance_validation_performed=provenance_validation_performed,
        invalid_source_reference_count=invalid_source_reference_count,
        evidence_correlation_scoring_performed=evidence_scoring_performed,
        evidence_correlation_evaluated_event_count=(
            evidence_evaluated_event_count
        ),
        evidence_correlation_true_positives=evidence_tp,
        evidence_correlation_false_positives=evidence_fp,
        evidence_correlation_false_negatives=evidence_fn,
        evidence_correlation_precision=evidence_precision,
        evidence_correlation_recall=evidence_recall,
        evidence_correlation_f1=evidence_f1,
        interpretation_state_scoring_performed=True,
        interpretation_state_evaluated_count=state_evaluated,
        interpretation_state_correct_count=state_correct,
        interpretation_state_incorrect_count=state_incorrect,
        interpretation_state_accuracy=state_accuracy,
        interpretation_state_unmatched_ground_truth_count=(
            state_unmatched_truth
        ),
        interpretation_state_unscored_ground_truth_count=(
            state_unscored_truth
        ),
        interpretation_state_mismatches=tuple(state_mismatches),
        matched_pairs=matched_pairs,
        unmatched_prediction_ids=unmatched_predictions,
        unmatched_ground_truth_ids=unmatched_truth,
    )
