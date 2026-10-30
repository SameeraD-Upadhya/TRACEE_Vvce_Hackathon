
"""
TRACEE Evidence-Backed Hypothesis Models.

Defines versioned inference rules and immutable event hypotheses.

This module validates hypothesis records. It does not execute inference
rules, determine historical truth, or assign statistical probabilities.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Any, Iterable, Mapping

from .events import TemporalExtent
from .models import ModelValidationError


HYPOTHESIS_SCHEMA_VERSION = "1.1"
RULE_SCHEMA_VERSION = "1.2"


class InterpretationState(str, Enum):
    """Interpretation of a candidate event under a documented rule."""

    CORROBORATED = "corroborated"
    CHALLENGED = "challenged"
    UNDERDETERMINED = "underdetermined"
    INSUFFICIENT_INPUT = "insufficient_input"


class ReviewStatus(str, Enum):
    """Investigator review state, independent of interpretation state."""

    NOT_REVIEWED = "not_reviewed"
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    NEEDS_MORE_EVIDENCE = "needs_more_evidence"


def _require_text(value: str, name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ModelValidationError(
            f"{name} must be a non-empty string"
        )


def _text_tuple(values: Iterable[str], name: str) -> tuple[str, ...]:
    """Validate and freeze a sequence of unique, non-empty strings."""

    if isinstance(values, (str, bytes)):
        raise ModelValidationError(
            f"{name} must be a sequence of strings"
        )

    try:
        result = tuple(values)
    except TypeError as exc:
        raise ModelValidationError(
            f"{name} must be a sequence of strings"
        ) from exc

    for value in result:
        _require_text(value, f"{name} entry")

    if len(result) != len(set(result)):
        raise ModelValidationError(
            f"{name} must not contain duplicates"
        )

    return result


def _freeze_json(value: Any, path: str = "attributes") -> Any:
    """Validate JSON-compatible values and freeze nested containers."""

    if isinstance(value, Mapping):
        frozen: dict[str, Any] = {}

        for key, item in value.items():
            if not isinstance(key, str):
                raise ModelValidationError(
                    f"{path} keys must be strings"
                )

            frozen[key] = _freeze_json(item, f"{path}.{key}")

        return MappingProxyType(frozen)

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


def _thaw_json(value: Any) -> Any:
    """Return regular dictionaries and lists for serialization."""

    if isinstance(value, Mapping):
        return {
            key: _thaw_json(item)
            for key, item in value.items()
        }

    if isinstance(value, tuple):
        return [_thaw_json(item) for item in value]

    return value


@dataclass(frozen=True)
class InferenceRule:
    """
    Metadata describing a versioned event-inference rule.

    This model describes a rule; it does not execute it.
    """

    rule_id: str
    version: str
    event_type: str
    description: str

    required_observation_types: tuple[str, ...] = ()
    required_attributes: tuple[str, ...] = ()
    required_observation_attributes: Mapping[str, Any] = field(
        default_factory=dict
    )
    expected_artifact_types: tuple[str, ...] = ()
    suppress_if_expected_artifact_observed: bool = False
    expected_artifact_correlation_attribute: str | None = None
    minimum_supporting_observations: int = 1
    requires_source_coverage: bool = False
    limitations: tuple[str, ...] = ()
    schema_version: str = RULE_SCHEMA_VERSION
    candidate_partition_attributes: tuple[str, ...] = ()
    correlated_observation_types: tuple[str, ...] = ()
    correlated_observation_attributes: Mapping[str, Any] = field(
        default_factory=dict
    )
    correlated_observation_correlation_attribute: str | None = None

    def __post_init__(self) -> None:
        for name in (
            "rule_id",
            "version",
            "event_type",
            "description",
            "schema_version",
        ):
            _require_text(getattr(self, name), name)

        minimum = self.minimum_supporting_observations
        if (
            not isinstance(minimum, int)
            or isinstance(minimum, bool)
            or minimum < 1
        ):
            raise ModelValidationError(
                "minimum_supporting_observations must be "
                "a positive integer"
            )

        if not isinstance(self.requires_source_coverage, bool):
            raise ModelValidationError(
                "requires_source_coverage must be a boolean"
            )
        if not isinstance(
            self.suppress_if_expected_artifact_observed, bool
        ):
            raise ModelValidationError(
                "suppress_if_expected_artifact_observed must be a boolean"
            )
        correlation_attribute = (
            self.expected_artifact_correlation_attribute
        )
        if correlation_attribute is not None:
            _require_text(
                correlation_attribute,
                "expected_artifact_correlation_attribute",
            )
        if (
            self.suppress_if_expected_artifact_observed
            and correlation_attribute is None
        ):
            raise ModelValidationError(
                "Artifact suppression requires a correlation attribute"
            )

        if not isinstance(self.required_observation_attributes, Mapping):
            raise ModelValidationError(
                "required_observation_attributes must be a mapping"
            )

        for name in self.required_observation_attributes:
            _require_text(name, "required observation attribute name")

        object.__setattr__(
            self,
            "required_observation_attributes",
            _freeze_json(
                self.required_observation_attributes,
                "required_observation_attributes",
            ),
        )

        if not isinstance(self.correlated_observation_attributes, Mapping):
            raise ModelValidationError(
                "correlated_observation_attributes must be a mapping"
            )
        for name in self.correlated_observation_attributes:
            _require_text(name, "correlated observation attribute name")
        object.__setattr__(
            self,
            "correlated_observation_attributes",
            _freeze_json(
                self.correlated_observation_attributes,
                "correlated_observation_attributes",
            ),
        )

        correlation_name = self.correlated_observation_correlation_attribute
        if correlation_name is not None:
            _require_text(
                correlation_name,
                "correlated_observation_correlation_attribute",
            )

        correlated_types = tuple(self.correlated_observation_types)
        has_correlation_config = (
            bool(correlated_types) or correlation_name is not None
            or bool(self.correlated_observation_attributes)
        )
        if has_correlation_config and (
            not correlated_types or correlation_name is None
        ):
            raise ModelValidationError(
                "Correlated observation types and a correlation attribute "
                "must be configured together"
            )
        if correlation_name is not None and (
            correlation_name not in self.candidate_partition_attributes
        ):
            raise ModelValidationError(
                "The correlated observation key must also be a candidate "
                "partition attribute"
            )

        for name in (
            "required_observation_types",
            "required_attributes",
            "expected_artifact_types",
            "candidate_partition_attributes",
            "correlated_observation_types",
            "limitations",
        ):
            object.__setattr__(
                self,
                name,
                _text_tuple(getattr(self, name), name),
            )

    def matches_observation_attributes(
        self, attributes: Mapping[str, Any]
    ) -> bool:
        if not isinstance(attributes, Mapping):
            return False

        for name, expected in self.required_observation_attributes.items():
            if name not in attributes:
                return False
            actual = _freeze_json(attributes[name], f"attributes.{name}")
            if actual != expected:
                return False

        return True

    def matches_correlated_observation_attributes(
        self, attributes: Mapping[str, Any]
    ) -> bool:
        if not isinstance(attributes, Mapping):
            return False

        for name, expected in self.correlated_observation_attributes.items():
            if name not in attributes:
                return False
            actual = _freeze_json(
                attributes[name],
                f"attributes.{name}",
            )
            if actual != expected:
                return False

        return True

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "rule_id": self.rule_id,
            "version": self.version,
            "event_type": self.event_type,
            "description": self.description,
            "required_observation_types": list(
                self.required_observation_types
            ),
            "required_attributes": list(self.required_attributes),
            "required_observation_attributes": _thaw_json(
                self.required_observation_attributes
            ),
            "expected_artifact_types": list(
                self.expected_artifact_types
            ),
            "suppress_if_expected_artifact_observed": (
                self.suppress_if_expected_artifact_observed
            ),
            "expected_artifact_correlation_attribute": (
                self.expected_artifact_correlation_attribute
            ),
            "candidate_partition_attributes": list(
                self.candidate_partition_attributes
            ),
            "correlated_observation_types": list(
                self.correlated_observation_types
            ),
            "correlated_observation_attributes": _thaw_json(
                self.correlated_observation_attributes
            ),
            "correlated_observation_correlation_attribute": (
                self.correlated_observation_correlation_attribute
            ),
            "minimum_supporting_observations": (
                self.minimum_supporting_observations
            ),
            "requires_source_coverage": self.requires_source_coverage,
            "limitations": list(self.limitations),
        }


@dataclass(frozen=True)
class EventHypothesis:
    """
    A candidate event interpretation linked to its evidence and rule.

    Supporting and contradictory observations must be members of the
    complete input-observation set. This model records an interpretation;
    it does not independently prove the event occurred.
    """

    hypothesis_id: str
    event_type: str
    inference_rule_id: str
    inference_rule_version: str
    input_observation_ids: tuple[str, ...]

    interpretation: InterpretationState
    supporting_observation_ids: tuple[str, ...] = ()
    contradicting_observation_ids: tuple[str, ...] = ()
    coverage_ids: tuple[str, ...] = ()
    observation_assessment_ids: tuple[str, ...] = ()
    contradicting_assessment_ids: tuple[str, ...] = ()

    attributes: Mapping[str, Any] = field(default_factory=dict)
    temporal_extent: TemporalExtent = field(
        default_factory=TemporalExtent
    )

    assumptions: tuple[str, ...] = ()
    unresolved_conditions: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()

    review_status: ReviewStatus = ReviewStatus.NOT_REVIEWED
    schema_version: str = HYPOTHESIS_SCHEMA_VERSION
    correlated_observation_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for name in (
            "hypothesis_id",
            "event_type",
            "inference_rule_id",
            "inference_rule_version",
            "schema_version",
        ):
            _require_text(getattr(self, name), name)

        if not isinstance(self.interpretation, InterpretationState):
            raise ModelValidationError(
                "interpretation must be an InterpretationState"
            )

        if not isinstance(self.review_status, ReviewStatus):
            raise ModelValidationError(
                "review_status must be a ReviewStatus"
            )

        if not isinstance(self.temporal_extent, TemporalExtent):
            raise ModelValidationError(
                "temporal_extent must be a TemporalExtent"
            )

        input_ids = _text_tuple(
            self.input_observation_ids,
            "input_observation_ids",
        )
        if not input_ids:
            raise ModelValidationError(
                "A hypothesis must reference at least one "
                "input observation"
            )

        supporting = _text_tuple(
            self.supporting_observation_ids,
            "supporting_observation_ids",
        )
        contradicting = _text_tuple(
            self.contradicting_observation_ids,
            "contradicting_observation_ids",
        )
        correlated = _text_tuple(
            self.correlated_observation_ids,
            "correlated_observation_ids",
        )
        assessment_ids = _text_tuple(
            self.observation_assessment_ids,
            "observation_assessment_ids",
        )
        contradicting_assessments = _text_tuple(
            self.contradicting_assessment_ids,
            "contradicting_assessment_ids",
        )

        if set(contradicting_assessments) - set(assessment_ids):
            raise ModelValidationError(
                "Contradicting assessments must belong to "
                "observation_assessment_ids"
            )

        if set(supporting) - set(input_ids):
            raise ModelValidationError(
                "Supporting observations must belong to "
                "input_observation_ids"
            )

        if set(correlated) - set(input_ids):
            raise ModelValidationError(
                "Correlated observations must belong to input_observation_ids"
            )

        if set(correlated) & (set(supporting) | set(contradicting)):
            raise ModelValidationError(
                "Correlated observations cannot also be directly supporting "
                "or contradicting observations"
            )

        if set(contradicting) - set(input_ids):
            raise ModelValidationError(
                "Contradictory observations must belong to "
                "input_observation_ids"
            )

        if set(supporting) & set(contradicting):
            raise ModelValidationError(
                "An observation cannot be both supporting and "
                "contradictory in the same hypothesis record"
            )

        if (
            self.interpretation == InterpretationState.CORROBORATED
            and not supporting
        ):
            raise ModelValidationError(
                "CORROBORATED requires supporting observations"
            )

        if (
            self.interpretation == InterpretationState.CHALLENGED
            and not contradicting
            and not contradicting_assessments
        ):
            raise ModelValidationError(
                "CHALLENGED requires contradictory observations"
            )

        unresolved = _text_tuple(
            self.unresolved_conditions,
            "unresolved_conditions",
        )

        if (
            self.interpretation
            in (
                InterpretationState.UNDERDETERMINED,
                InterpretationState.INSUFFICIENT_INPUT,
            )
            and not unresolved
        ):
            raise ModelValidationError(
                f"{self.interpretation.value} requires "
                "unresolved_conditions"
            )

        if not isinstance(self.attributes, Mapping):
            raise ModelValidationError(
                "attributes must be a mapping"
            )

        object.__setattr__(
            self,
            "attributes",
            _freeze_json(self.attributes),
        )

        object.__setattr__(self, "input_observation_ids", input_ids)
        object.__setattr__(self, "supporting_observation_ids", supporting)
        object.__setattr__(self, "correlated_observation_ids", correlated)
        object.__setattr__(
            self, "contradicting_observation_ids", contradicting
        )
        object.__setattr__(
            self,
            "coverage_ids",
            _text_tuple(self.coverage_ids, "coverage_ids"),
        )
        object.__setattr__(
            self,
            "observation_assessment_ids",
            assessment_ids,
        )
        object.__setattr__(
            self,
            "contradicting_assessment_ids",
            contradicting_assessments,
        )
        object.__setattr__(
            self, "assumptions", _text_tuple(self.assumptions, "assumptions")
        )
        object.__setattr__(self, "unresolved_conditions", unresolved)
        object.__setattr__(
            self, "limitations", _text_tuple(self.limitations, "limitations")
        )

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible hypothesis record."""

        from .events import _datetime_to_iso

        return {
            "schema_version": self.schema_version,
            "hypothesis_id": self.hypothesis_id,
            "event_type": self.event_type,
            "inference_rule_id": self.inference_rule_id,
            "inference_rule_version": self.inference_rule_version,
            "input_observation_ids": list(self.input_observation_ids),
            "interpretation": self.interpretation.value,
            "supporting_observation_ids": list(
                self.supporting_observation_ids
            ),
            "correlated_observation_ids": list(
                self.correlated_observation_ids
            ),
            "contradicting_observation_ids": list(
                self.contradicting_observation_ids
            ),
            "coverage_ids": list(self.coverage_ids),
            "observation_assessment_ids": list(
                self.observation_assessment_ids
            ),
            "contradicting_assessment_ids": list(
                self.contradicting_assessment_ids
            ),
            "attributes": _thaw_json(self.attributes),
            "temporal_extent": {
                "earliest_utc": _datetime_to_iso(
                    self.temporal_extent.earliest_utc
                ),
                "latest_utc": _datetime_to_iso(
                    self.temporal_extent.latest_utc
                ),
            },
            "assumptions": list(self.assumptions),
            "unresolved_conditions": list(self.unresolved_conditions),
            "limitations": list(self.limitations),
            "review_status": self.review_status.value,
        }
