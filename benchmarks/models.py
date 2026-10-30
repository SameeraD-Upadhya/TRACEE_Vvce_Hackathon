
"""Data models for TRACEE's synthetic reconstruction benchmark.

Observable method inputs and hidden ground truth use separate models.
A reconstruction adapter must receive BenchmarkInput, never
ScenarioGroundTruth or GeneratedScenario.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Any, Mapping

from tracee.coverage import ObservationAssessment, SourceCoverage
from tracee.events import SourceObservation, TemporalExtent
from tracee.models import ModelValidationError


BENCHMARK_SCHEMA_VERSION = "1.0"


class ScenarioFamily(str, Enum):
    """Evaluation-only scenario categories; not passed to reconstruction."""

    COMPLETE_RECORDS = "complete_records"
    MISSING_RECORD = "missing_record"
    LOGGING_DISABLED = "logging_disabled"
    CONFLICTING_TIMESTAMPS = "conflicting_timestamps"
    MULTIPLE_ENTITIES = "multiple_entities"
    AMBIGUOUS_EVIDENCE = "ambiguous_evidence"
    NEGATIVE_CONTROL = "negative_control"


def _require_text(value: str, name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ModelValidationError(
            f"{name} must be a non-empty string"
        )


def _freeze_json(value: Any, path: str = "attributes") -> Any:
    """Validate and recursively freeze JSON-compatible attributes."""
    if isinstance(value, Mapping):
        result = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise ModelValidationError(
                    f"{path} keys must be strings"
                )
            result[key] = _freeze_json(item, f"{path}.{key}")
        return MappingProxyType(result)

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


@dataclass(frozen=True)
class BenchmarkInput:
    """Only information permitted to be passed to reconstruction methods."""

    scenario_id: str
    observations: tuple[SourceObservation, ...]
    coverage_records: tuple[SourceCoverage, ...] = ()
    observation_assessments: tuple[ObservationAssessment, ...] = ()
    schema_version: str = BENCHMARK_SCHEMA_VERSION

    def __post_init__(self) -> None:
        _require_text(self.scenario_id, "scenario_id")
        _require_text(self.schema_version, "schema_version")

        for name in (
            "observations",
            "coverage_records",
            "observation_assessments",
        ):
            values = getattr(self, name)
            if isinstance(values, (str, bytes)):
                raise ModelValidationError(
                    f"{name} must be a sequence"
                )
            try:
                values = tuple(values)
            except TypeError as exc:
                raise ModelValidationError(
                    f"{name} must be a sequence"
                ) from exc
            object.__setattr__(self, name, values)

        if any(
            not isinstance(item, SourceObservation)
            for item in self.observations
        ):
            raise ModelValidationError(
                "observations must contain SourceObservation values"
            )

        if any(
            not isinstance(item, SourceCoverage)
            for item in self.coverage_records
        ):
            raise ModelValidationError(
                "coverage_records must contain SourceCoverage values"
            )

        if any(
            not isinstance(item, ObservationAssessment)
            for item in self.observation_assessments
        ):
            raise ModelValidationError(
                "observation_assessments must contain "
                "ObservationAssessment values"
            )

        observation_ids = [
            item.observation_id for item in self.observations
        ]
        if len(observation_ids) != len(set(observation_ids)):
            raise ModelValidationError(
                "Benchmark observation IDs must be unique"
            )

        coverage_ids = [
            item.coverage_id for item in self.coverage_records
        ]
        if len(coverage_ids) != len(set(coverage_ids)):
            raise ModelValidationError(
                "Benchmark coverage IDs must be unique"
            )

        assessment_ids = [
            item.assessment_id for item in self.observation_assessments
        ]
        if len(assessment_ids) != len(set(assessment_ids)):
            raise ModelValidationError(
                "Benchmark assessment IDs must be unique"
            )

        observation_id_set = set(observation_ids)
        coverage_id_set = set(coverage_ids)

        for assessment in self.observation_assessments:
            if assessment.coverage_id not in coverage_id_set:
                raise ModelValidationError(
                    f"Assessment {assessment.assessment_id!r} references "
                    "coverage not included in benchmark input"
                )

            linked_ids = (
                set(assessment.found_observation_ids)
                | set(assessment.supporting_indicator_observation_ids)
            )
            missing = linked_ids - observation_id_set
            if missing:
                raise ModelValidationError(
                    f"Assessment {assessment.assessment_id!r} references "
                    f"observations missing from benchmark input: "
                    f"{sorted(missing)!r}"
                )


@dataclass(frozen=True)
class GroundTruthEvent:
    """Hidden description of one event that actually occurred."""

    event_id: str
    event_type: str
    entity_attributes: Mapping[str, Any]
    temporal_extent: TemporalExtent
    expected_record_ids: tuple[str, ...] = ()
    expected_interpretation_state: str | None = None

    def __post_init__(self) -> None:
        _require_text(self.event_id, "event_id")
        _require_text(self.event_type, "event_type")

        allowed_states = {
            "corroborated", "challenged",
            "underdetermined", "insufficient_input",
        }
        state = self.expected_interpretation_state
        if state is not None and (
            not isinstance(state, str) or state not in allowed_states
        ):
            raise ModelValidationError(
                "expected_interpretation_state must be a supported state "
                "or None"
            )

        if not isinstance(self.entity_attributes, Mapping):
            raise ModelValidationError(
                "entity_attributes must be a mapping"
            )

        if not isinstance(self.temporal_extent, TemporalExtent):
            raise ModelValidationError(
                "temporal_extent must be a TemporalExtent"
            )

        object.__setattr__(
            self,
            "entity_attributes",
            _freeze_json(self.entity_attributes, "entity_attributes"),
        )

        if isinstance(self.expected_record_ids, str):
            raise ModelValidationError(
                "expected_record_ids must be a sequence"
            )

        try:
            record_ids = tuple(self.expected_record_ids)
        except TypeError as exc:
            raise ModelValidationError(
                "expected_record_ids must be a sequence"
            ) from exc

        for record_id in record_ids:
            _require_text(record_id, "expected_record_ids entry")

        if len(record_ids) != len(set(record_ids)):
            raise ModelValidationError(
                "expected_record_ids must not contain duplicates"
            )

        object.__setattr__(self, "expected_record_ids", record_ids)


@dataclass(frozen=True)
class ScenarioGroundTruth:
    """Evaluation-only labels and generation conditions."""

    scenario_id: str
    seed: int
    family: ScenarioFamily
    events: tuple[GroundTruthEvent, ...]
    omitted_record_ids: tuple[str, ...] = ()
    ambiguous: bool = False
    event_matching_eligible: bool = True
    conditions: tuple[str, ...] = ()
    profile_id: str | None = None

    def __post_init__(self) -> None:
        _require_text(self.scenario_id, "scenario_id")
        if self.profile_id is not None:
            _require_text(self.profile_id, "profile_id")

        if (
            not isinstance(self.seed, int)
            or isinstance(self.seed, bool)
            or self.seed < 0
        ):
            raise ModelValidationError(
                "seed must be a non-negative integer"
            )

        if not isinstance(self.family, ScenarioFamily):
            raise ModelValidationError(
                "family must be a ScenarioFamily"
            )

        if not isinstance(self.ambiguous, bool):
            raise ModelValidationError(
                "ambiguous must be a boolean"
            )
        if not isinstance(self.event_matching_eligible, bool):
            raise ModelValidationError(
                "event_matching_eligible must be a boolean"
            )

        events = tuple(self.events)
        if any(not isinstance(item, GroundTruthEvent) for item in events):
            raise ModelValidationError(
                "events must contain GroundTruthEvent values"
            )

        event_ids = [item.event_id for item in events]
        if len(event_ids) != len(set(event_ids)):
            raise ModelValidationError(
                "Ground-truth event IDs must be unique"
            )

        object.__setattr__(self, "events", events)

        for name in ("omitted_record_ids", "conditions"):
            values = getattr(self, name)
            if isinstance(values, str):
                raise ModelValidationError(
                    f"{name} must be a sequence of strings"
                )
            values = tuple(values)
            for value in values:
                _require_text(value, f"{name} entry")
            if len(values) != len(set(values)):
                raise ModelValidationError(
                    f"{name} must not contain duplicate values"
                )
            object.__setattr__(self, name, values)


@dataclass(frozen=True)
class GeneratedScenario:
    """Container joining method input with separate evaluator-only truth.

    Pass only `method_input` into a reconstruction method. The wrapper
    exists for benchmark orchestration and must not be passed to an
    algorithm being evaluated.
    """

    method_input: BenchmarkInput
    ground_truth: ScenarioGroundTruth

    def __post_init__(self) -> None:
        if not isinstance(self.method_input, BenchmarkInput):
            raise ModelValidationError(
                "method_input must be a BenchmarkInput"
            )

        if not isinstance(self.ground_truth, ScenarioGroundTruth):
            raise ModelValidationError(
                "ground_truth must be a ScenarioGroundTruth"
            )

        if self.method_input.scenario_id != self.ground_truth.scenario_id:
            raise ModelValidationError(
                "Method input and ground truth scenario IDs must match"
            )
