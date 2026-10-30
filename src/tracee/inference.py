
"""
TRACEE Deterministic Hypothesis Evaluator.

Evaluates candidate events against versioned rules, observations,
source-coverage records, and expected-artifact assessments.

This module does not prove historical truth, infer attacker intent,
or calculate statistical confidence scores.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from .coverage import (
    ObservationAssessment,
    ObservationAvailability,
    SourceCoverage,
)
from .events import ParseStatus, SourceObservation, TemporalExtent
from .hypotheses import (
    EventHypothesis,
    InferenceRule,
    InterpretationState,
    ReviewStatus,
)
from .models import ModelValidationError


def _text_tuple(values: Iterable[str], field_name: str) -> tuple[str, ...]:
    """Validate and freeze unique, non-empty string values."""

    if isinstance(values, (str, bytes)):
        raise ModelValidationError(
            f"{field_name} must be a sequence of strings"
        )

    try:
        result = tuple(values)
    except TypeError as exc:
        raise ModelValidationError(
            f"{field_name} must be a sequence of strings"
        ) from exc

    for value in result:
        if not isinstance(value, str) or not value.strip():
            raise ModelValidationError(
                f"{field_name} entries must be non-empty strings"
            )

    if len(result) != len(set(result)):
        raise ModelValidationError(
            f"{field_name} must not contain duplicate entries"
        )

    return result


def _comparable(value: Any) -> Any:
    """Build a deterministic comparable representation of JSON data."""

    if isinstance(value, Mapping):
        return tuple(
            (key, _comparable(item))
            for key, item in sorted(value.items())
        )

    if isinstance(value, (list, tuple)):
        return tuple(_comparable(item) for item in value)

    return value


def _scope_matches(
    scope_attributes: Mapping[str, Any],
    candidate_attributes: Mapping[str, Any],
) -> bool:
    """
    Match a non-empty assessment scope against candidate attributes.

    An empty scope is ambiguous and must not be applied to every candidate.
    Scope matching checks every declared scope attribute, allowing candidate
    attributes to contain additional fields.
    """
    if not scope_attributes:
        return False

    return all(
        key in candidate_attributes
        and _comparable(candidate_attributes[key]) == _comparable(value)
        for key, value in scope_attributes.items()
    )


def evaluate_candidate_hypothesis(
    *,
    hypothesis_id: str,
    rule: InferenceRule,
    observations: Iterable[SourceObservation],
    candidate_attributes: Mapping[str, Any],
    temporal_extent: TemporalExtent | None = None,
    coverage_records: Iterable[SourceCoverage] = (),
    observation_assessments: Iterable[ObservationAssessment] = (),
    contradicting_observation_ids: Iterable[str] = (),
    absence_counterevidence_types: Iterable[str] = (),
    assumptions: Iterable[str] = (),
    limitations: Iterable[str] = (),
    review_status: ReviewStatus = ReviewStatus.NOT_REVIEWED,
    correlated_observation_ids: Iterable[str] = (),
) -> EventHypothesis:
    """
    Evaluate a candidate event using explicit deterministic rules.

    Required observation types must each have matching support.
    Required candidate attributes must match the observations exactly.

    Missing expected artifacts challenge a hypothesis only when:
    1. The rule declares that artifact type as absence counterevidence.
    2. The assessment reports that artifact was not observed under
       documented coverage for the expected time extent.

    Unknown coverage, unavailable sources, partial parsing, and possible
    removal are retained as uncertainty or insufficient input, rather
    than treated automatically as proof against the candidate.
    """

    if not isinstance(rule, InferenceRule):
        raise ModelValidationError("rule must be an InferenceRule")

    if not isinstance(hypothesis_id, str) or not hypothesis_id.strip():
        raise ModelValidationError(
            "hypothesis_id must be a non-empty string"
        )

    if temporal_extent is None:
        temporal_extent = TemporalExtent()

    if not isinstance(temporal_extent, TemporalExtent):
        raise ModelValidationError(
            "temporal_extent must be a TemporalExtent"
        )

    if not isinstance(candidate_attributes, Mapping):
        raise ModelValidationError(
            "candidate_attributes must be a mapping"
        )

    if not rule.required_observation_types and not rule.required_attributes:
        raise ModelValidationError(
            "Rules must specify required observation types or attributes"
        )

    if not isinstance(review_status, ReviewStatus):
        raise ModelValidationError(
            "review_status must be a ReviewStatus"
        )

    try:
        input_observations = tuple(observations)
        coverage_items = tuple(coverage_records)
        assessment_items = tuple(observation_assessments)
    except TypeError as exc:
        raise ModelValidationError(
            "Observations, coverage records, and assessments "
            "must be iterable"
        ) from exc

    if not input_observations:
        raise ModelValidationError(
            "At least one input observation is required"
        )

    if any(
        not isinstance(item, SourceObservation)
        for item in input_observations
    ):
        raise ModelValidationError(
            "Every input must be a SourceObservation"
        )

    if any(
        not isinstance(item, SourceCoverage)
        for item in coverage_items
    ):
        raise ModelValidationError(
            "Every coverage record must be a SourceCoverage"
        )

    if any(
        not isinstance(item, ObservationAssessment)
        for item in assessment_items
    ):
        raise ModelValidationError(
            "Every assessment must be an ObservationAssessment"
        )

    observation_map = {
        item.observation_id: item for item in input_observations
    }

    if len(observation_map) != len(input_observations):
        raise ModelValidationError(
            "Input observation identifiers must be unique"
        )

    input_ids = tuple(observation_map)

    contradictions = _text_tuple(
        contradicting_observation_ids,
        "contradicting_observation_ids",
    )

    unknown_contradictions = set(contradictions) - set(observation_map)
    if unknown_contradictions:
        raise ModelValidationError(
            "Contradictory observation IDs must refer to input "
            f"observations: {sorted(unknown_contradictions)!r}"
        )

    counterevidence_types = _text_tuple(
        absence_counterevidence_types,
        "absence_counterevidence_types",
    )

    undeclared_types = (
        set(counterevidence_types) - set(rule.expected_artifact_types)
    )
    if undeclared_types:
        raise ModelValidationError(
            "Absence counterevidence types must be declared as "
            f"expected artifact types: {sorted(undeclared_types)!r}"
        )

    coverage_map = {item.coverage_id: item for item in coverage_items}
    if len(coverage_map) != len(coverage_items):
        raise ModelValidationError(
            "Coverage identifiers must be unique"
        )

    assessment_map = {
        item.assessment_id: item for item in assessment_items
    }
    if len(assessment_map) != len(assessment_items):
        raise ModelValidationError(
            "Assessment identifiers must be unique"
        )

    expected_types = set(rule.expected_artifact_types)
    assessments_for_expected_types = tuple(
        item
        for item in assessment_items
        if item.expected_artifact_type in expected_types
    )

    relevant_assessments = tuple(
        item
        for item in assessments_for_expected_types
        if _scope_matches(item.scope_attributes, candidate_attributes)
    )

    for assessment in relevant_assessments:
        coverage = coverage_map.get(assessment.coverage_id)
        if coverage is None:
            raise ModelValidationError(
                f"Assessment {assessment.assessment_id!r} references "
                "a coverage record that was not supplied"
            )

        referenced_ids = (
            set(assessment.found_observation_ids)
            | set(assessment.supporting_indicator_observation_ids)
        )
        unknown_ids = referenced_ids - set(observation_map)

        if unknown_ids:
            raise ModelValidationError(
                f"Assessment {assessment.assessment_id!r} references "
                f"unknown observation IDs: {sorted(unknown_ids)!r}"
            )

        if (
            assessment.availability
            in (
                ObservationAvailability.NOT_OBSERVED_WITH_KNOWN_COVERAGE,
                ObservationAvailability
                .POSSIBLE_REMOVAL_WITH_SUPPORTING_INDICATORS,
            )
            and not coverage.covers_extent(assessment.expected_extent)
        ):
            raise ModelValidationError(
                f"Assessment {assessment.assessment_id!r} asserts a "
                "coverage-dependent state, but the supplied coverage "
                "record does not cover its expected time extent"
            )

    unresolved: list[str] = []
    input_blockers: list[str] = []

    def add_unresolved(
        message: str,
        *,
        blocks_input: bool = False,
    ) -> None:
        if message not in unresolved:
            unresolved.append(message)
        if blocks_input and message not in input_blockers:
            input_blockers.append(message)

    if rule.requires_source_coverage and not coverage_items:
        add_unresolved(
            "The inference rule requires source coverage, but no "
            "coverage records were supplied",
            blocks_input=True,
        )

    missing_candidate_attributes = [
        name
        for name in rule.required_attributes
        if name not in candidate_attributes
    ]

    for name in missing_candidate_attributes:
        add_unresolved(
            f"Required candidate attribute is missing: {name}",
            blocks_input=True,
        )

    # Identify observations that match the required source types and
    # required attributes.
    required_types = set(rule.required_observation_types)
    supporting_ids: list[str] = []

    for observation in input_observations:
        if (
            required_types
            and observation.source_type not in required_types
        ):
            continue

        if observation.parse_status in (
            ParseStatus.FAILED,
            ParseStatus.UNSUPPORTED,
        ):
            predicate_values_present = all(
                name in observation.attributes
                for name in rule.required_observation_attributes
            )
            if (
                predicate_values_present
                and not rule.matches_observation_attributes(
                    observation.attributes
                )
            ):
                continue

            add_unresolved(
                f"Observation {observation.observation_id!r} could not "
                "be parsed: " + "; ".join(observation.parse_errors),
                blocks_input=True,
            )
            continue

        if not rule.matches_observation_attributes(
            observation.attributes
        ):
            continue

        if missing_candidate_attributes:
            continue

        attributes_match = all(
            name in observation.attributes
            and _comparable(observation.attributes[name])
            == _comparable(candidate_attributes[name])
            for name in rule.required_attributes
        )

        if not attributes_match:
            continue

        supporting_ids.append(observation.observation_id)

        if observation.parse_status == ParseStatus.PARTIAL:
            add_unresolved(
                f"Observation {observation.observation_id!r} was "
                "only partially parsed"
            )

    # A required source type must be represented by matching support.
    for source_type in rule.required_observation_types:
        matching_ids = [
            identifier
            for identifier in supporting_ids
            if observation_map[identifier].source_type == source_type
        ]
        if not matching_ids:
            add_unresolved(
                f"No matching supporting observation for required "
                f"source type: {source_type}",
                blocks_input=True,
            )

    if len(supporting_ids) < rule.minimum_supporting_observations:
        add_unresolved(
            "Insufficient matching supporting observations: required "
            f"{rule.minimum_supporting_observations}, "
            f"found {len(supporting_ids)}",
            blocks_input=True,
        )

    # All expected artifact types must have an assessment. If no
    # assessment exists, the evaluator cannot treat that artifact as
    # observed or absent.
    assessed_types = {
        item.expected_artifact_type for item in relevant_assessments
    }

    for artifact_type in rule.expected_artifact_types:
        if artifact_type not in assessed_types:
            available_assessments = [
                item
                for item in assessments_for_expected_types
                if item.expected_artifact_type == artifact_type
            ]

            if available_assessments:
                add_unresolved(
                    "No assessment supplied for expected artifact type "
                    f"{artifact_type!r} within candidate scope; available "
                    "assessment scopes are empty or do not match",
                    blocks_input=True,
                )
            else:
                add_unresolved(
                    f"No assessment supplied for expected artifact type: "
                    f"{artifact_type}",
                    blocks_input=True,
                )

    contradicting_assessment_ids: list[str] = []
    used_assessment_ids: list[str] = []
    used_coverage_ids: list[str] = []

    for assessment in relevant_assessments:
        used_assessment_ids.append(assessment.assessment_id)
        if assessment.coverage_id not in used_coverage_ids:
            used_coverage_ids.append(assessment.coverage_id)

        availability = assessment.availability

        if availability == ObservationAvailability.OBSERVED:
            continue

        if (
            availability
            == ObservationAvailability
            .NOT_OBSERVED_WITH_KNOWN_COVERAGE
        ):
            if assessment.expected_artifact_type in counterevidence_types:
                contradicting_assessment_ids.append(
                    assessment.assessment_id
                )
            else:
                add_unresolved(
                    f"Artifact {assessment.expected_artifact_type!r} "
                    "was not found under known coverage, but its absence "
                    "is not declared as counterevidence by this evaluation"
                )

        elif (
            availability
            == ObservationAvailability
            .POSSIBLE_REMOVAL_WITH_SUPPORTING_INDICATORS
        ):
            add_unresolved(
                f"Possible removal indicators exist for artifact "
                f"{assessment.expected_artifact_type!r}; this does not "
                "establish ordinary negative evidence or prove intent"
            )

        elif availability == ObservationAvailability.SOURCE_UNAVAILABLE:
            add_unresolved(
                f"Source unavailable for expected artifact "
                f"{assessment.expected_artifact_type!r}",
                blocks_input=True,
            )

        else:
            add_unresolved(
                f"Insufficient coverage to interpret missing artifact "
                f"{assessment.expected_artifact_type!r}"
            )

    overlap = set(supporting_ids) & set(contradictions)
    if overlap:
        raise ModelValidationError(
            "Observations cannot both support and contradict the "
            f"same hypothesis: {sorted(overlap)!r}"
        )

    assumptions_out = list(_text_tuple(assumptions, "assumptions"))
    limitations_out = list(_text_tuple(limitations, "limitations"))

    for limitation in rule.limitations:
        if limitation not in limitations_out:
            limitations_out.append(limitation)

    if counterevidence_types:
        assumptions_out.append(
            "This evaluation treats known-coverage absence as "
            "counterevidence for: "
            + ", ".join(counterevidence_types)
            + "."
        )

    if contradictions:
        assumptions_out.append(
            "Contradictory observation IDs were provided explicitly "
            "by a rule-specific evaluator or analyst."
        )

    # Contradictions challenge the hypothesis. Otherwise, prioritize
    # missing required inputs, then unresolved conditions, before
    # allowing corroboration.
    if contradictions or contradicting_assessment_ids:
        interpretation = InterpretationState.CHALLENGED
    elif input_blockers:
        interpretation = InterpretationState.INSUFFICIENT_INPUT
    elif unresolved:
        interpretation = InterpretationState.UNDERDETERMINED
    else:
        interpretation = InterpretationState.CORROBORATED

    return EventHypothesis(
        hypothesis_id=hypothesis_id,
        event_type=rule.event_type,
        inference_rule_id=rule.rule_id,
        inference_rule_version=rule.version,
        input_observation_ids=input_ids,
        interpretation=interpretation,
        supporting_observation_ids=tuple(supporting_ids),
        contradicting_observation_ids=contradictions,
        coverage_ids=tuple(used_coverage_ids),
        correlated_observation_ids=tuple(correlated_observation_ids),
        observation_assessment_ids=tuple(used_assessment_ids),
        contradicting_assessment_ids=tuple(
            contradicting_assessment_ids
        ),
        attributes=candidate_attributes,
        temporal_extent=temporal_extent,
        assumptions=tuple(assumptions_out),
        unresolved_conditions=tuple(unresolved),
        limitations=tuple(limitations_out),
        review_status=review_status,
    )
