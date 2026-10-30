
"""
TRACEE Deterministic Reconstruction Engine.

Generates candidate event hypotheses from source observations and
versioned inference rules.

Candidate grouping is not a causal inference. Every result preserves
its input observations, inference rule, policy assumptions, and
unresolved conditions.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Iterable, Mapping

from .coverage import (
    ObservationAssessment,
    ObservationAvailability,
    SourceCoverage,
)
from .events import ParseStatus, SourceObservation, TemporalExtent
from .hypotheses import (
    EventHypothesis,
    InferenceRule,
    ReviewStatus,
)
from .inference import evaluate_candidate_hypothesis
from .models import ModelValidationError


def _plain(value: Any) -> Any:
    """Convert immutable JSON containers to plain JSON-compatible values."""
    if isinstance(value, Mapping):
        return {
            key: _plain(item)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    return value


def _canonical(value: Any) -> str:
    """Return a stable JSON representation for hashing and sorting."""
    return json.dumps(
        _plain(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


@dataclass(frozen=True)
class ReconstructionConfig:
    """Reproducible settings for candidate grouping."""

    candidate_window_seconds: int = 300

    def __post_init__(self) -> None:
        value = self.candidate_window_seconds
        if (
            not isinstance(value, int)
            or isinstance(value, bool)
            or value < 0
        ):
            raise ModelValidationError(
                "candidate_window_seconds must be a non-negative integer"
            )

    def to_dict(self) -> dict[str, int]:
        return {
            "candidate_window_seconds": self.candidate_window_seconds,
        }


@dataclass(frozen=True)
class SkippedInput:
    """An observation that could not seed a candidate for a rule."""

    rule_id: str
    rule_version: str
    observation_id: str
    reason: str

    def to_dict(self) -> dict[str, str]:
        return {
            "rule_id": self.rule_id,
            "rule_version": self.rule_version,
            "observation_id": self.observation_id,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class ReconstructionResult:
    """Deterministic output of one reconstruction run."""

    config: ReconstructionConfig
    rule_versions: tuple[tuple[str, str], ...]
    hypotheses: tuple[EventHypothesis, ...]
    skipped_inputs: tuple[SkippedInput, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "config": self.config.to_dict(),
            "rule_versions": [
                {"rule_id": rule_id, "version": version}
                for rule_id, version in self.rule_versions
            ],
            "hypotheses": [
                hypothesis.to_dict()
                for hypothesis in self.hypotheses
            ],
            "skipped_inputs": [
                item.to_dict()
                for item in self.skipped_inputs
            ],
        }


def _has_bounded_time(observation: SourceObservation) -> bool:
    extent = observation.timestamp.normalized_extent
    return (
        extent.earliest_utc is not None
        and extent.latest_utc is not None
    )


def _candidate_extent(
    observations: tuple[SourceObservation, ...],
) -> TemporalExtent:
    earliest_values = [
        item.timestamp.normalized_extent.earliest_utc
        for item in observations
        if item.timestamp.normalized_extent.earliest_utc is not None
    ]
    latest_values = [
        item.timestamp.normalized_extent.latest_utc
        for item in observations
        if item.timestamp.normalized_extent.latest_utc is not None
    ]

    return TemporalExtent(
        earliest_utc=min(earliest_values) if earliest_values else None,
        latest_utc=max(latest_values) if latest_values else None,
    )


def _within_candidate_window(
    left: TemporalExtent,
    right: TemporalExtent,
    window_seconds: int,
) -> bool:
    left_start, left_end = left.earliest_utc, left.latest_utc
    right_start, right_end = right.earliest_utc, right.latest_utc

    if None in (left_start, left_end, right_start, right_end):
        return False

    if left_end < right_start:
        distance = right_start - left_end
    elif right_end < left_start:
        distance = left_start - right_end
    else:
        return True

    return distance <= timedelta(seconds=window_seconds)


def _find_correlated_observations(
    *,
    rule: InferenceRule,
    cluster: tuple[SourceObservation, ...],
    observations: tuple[SourceObservation, ...],
    candidate_attributes: Mapping[str, Any],
    candidate_window_seconds: int,
) -> tuple[SourceObservation, ...]:
    correlation_attribute = (
        rule.correlated_observation_correlation_attribute
    )
    if not rule.correlated_observation_types or correlation_attribute is None:
        return ()

    cluster_ids = {item.observation_id for item in cluster}
    session_values = {
        _canonical(_plain(item.attributes[correlation_attribute]))
        for item in cluster
        if correlation_attribute in item.attributes
        and item.attributes[correlation_attribute] is not None
    }
    if len(session_values) != 1:
        return ()

    cluster_extent = _candidate_extent(cluster)
    matches = []

    for item in observations:
        if item.observation_id in cluster_ids:
            continue
        if item.source_type not in rule.correlated_observation_types:
            continue
        if not rule.matches_correlated_observation_attributes(item.attributes):
            continue

        identity_matches = all(
            name in item.attributes
            and _canonical(_plain(item.attributes[name]))
            == _canonical(_plain(candidate_attributes[name]))
            for name in rule.required_attributes
            if name in candidate_attributes
        )
        if not identity_matches or any(
            name not in item.attributes
            for name in rule.required_attributes
        ):
            continue

        value = item.attributes.get(correlation_attribute)
        if value is None or _canonical(_plain(value)) not in session_values:
            continue

        if not _within_candidate_window(
            cluster_extent,
            item.timestamp.normalized_extent,
            candidate_window_seconds,
        ):
            continue

        matches.append(item)

    return tuple(sorted(matches, key=lambda item: item.observation_id))


def _cluster_by_time(
    observations: Iterable[SourceObservation],
    window_seconds: int,
) -> list[tuple[SourceObservation, ...]]:
    """
    Cluster one entity's records by temporal proximity.

    This creates candidate groups only. It does not establish causal
    relationships or assert that grouped records describe one real event.
    Observations without bounded time are kept separate.
    """
    known = sorted(
        (
            item for item in observations
            if _has_bounded_time(item)
        ),
        key=lambda item: (
            item.timestamp.normalized_extent.earliest_utc,
            item.timestamp.normalized_extent.latest_utc,
            item.observation_id,
        ),
    )
    unknown = sorted(
        (
            item for item in observations
            if not _has_bounded_time(item)
        ),
        key=lambda item: item.observation_id,
    )

    clusters: list[list[SourceObservation]] = []
    current: list[SourceObservation] = []
    current_end: datetime | None = None
    gap = timedelta(seconds=window_seconds)

    for observation in known:
        extent = observation.timestamp.normalized_extent
        start = extent.earliest_utc
        end = extent.latest_utc

        if start is None or end is None:
            continue

        if not current:
            current = [observation]
            current_end = end
            continue

        if current_end is not None and start <= current_end + gap:
            current.append(observation)
            current_end = max(current_end, end)
        else:
            clusters.append(current)
            current = [observation]
            current_end = end

    if current:
        clusters.append(current)

    result = [
        tuple(sorted(cluster, key=lambda item: item.observation_id))
        for cluster in clusters
    ]
    result.extend((item,) for item in unknown)

    return sorted(
        result,
        key=lambda cluster: tuple(
            item.observation_id for item in cluster
        ),
    )


def _scope_matches(
    scope: Mapping[str, Any],
    candidate_attributes: Mapping[str, Any],
) -> bool:
    """Require a non-empty assessment scope to match candidate values."""
    if not scope:
        return False

    return all(
        key in candidate_attributes
        and _canonical(candidate_attributes[key]) == _canonical(value)
        for key, value in scope.items()
    )


def _overlaps(
    left: TemporalExtent,
    right: TemporalExtent,
) -> bool:
    """Return true only when both extents are bounded and overlap."""
    if (
        left.earliest_utc is None
        or left.latest_utc is None
        or right.earliest_utc is None
        or right.latest_utc is None
    ):
        return False

    return (
        left.earliest_utc <= right.latest_utc
        and right.earliest_utc <= left.latest_utc
    )


def _assessment_links_compatible(
    assessment: ObservationAssessment,
    cluster_ids: set[str],
    observation_map: Mapping[str, SourceObservation],
    required_types: set[str],
    candidate_attributes: Mapping[str, Any],
    correlation_attribute: str | None = None,
) -> bool:
    """Check identity compatibility and optional explicit correlation."""
    linked_ids = (
        set(assessment.found_observation_ids)
        | set(assessment.supporting_indicator_observation_ids)
    )

    if correlation_attribute is not None and assessment.found_observation_ids:
        cluster_values = {
            _canonical(observation_map[identifier].attributes[
                correlation_attribute
            ])
            for identifier in cluster_ids
            if correlation_attribute in observation_map[identifier].attributes
            and observation_map[identifier].attributes[correlation_attribute]
            is not None
        }

        for identifier in assessment.found_observation_ids:
            if identifier in cluster_ids:
                continue

            linked_value = observation_map[identifier].attributes.get(
                correlation_attribute
            )
            if (
                not cluster_values
                or linked_value is None
                or _canonical(linked_value) not in cluster_values
            ):
                return False

    for identifier in linked_ids:
        linked = observation_map[identifier]

        if identifier in cluster_ids:
            continue

        if (
            linked.source_type in required_types
            and all(
                key in linked.attributes
                and _canonical(linked.attributes[key]) == _canonical(value)
                for key, value in candidate_attributes.items()
            )
        ):
            return False

    return True


def _assessment_confirms_correlated_observed_artifact(
    assessment: ObservationAssessment,
    cluster_ids: set[str],
    observation_map: Mapping[str, SourceObservation],
    correlation_attribute: str | None,
) -> bool:
    """Require an observed artifact linked by an explicit correlation ID."""
    if (
        correlation_attribute is None
        or assessment.availability is not ObservationAvailability.OBSERVED
    ):
        return False

    cluster_values = {
        _canonical(observation_map[identifier].attributes[correlation_attribute])
        for identifier in cluster_ids
        if correlation_attribute in observation_map[identifier].attributes
        and observation_map[identifier].attributes[correlation_attribute]
        is not None
    }
    if not cluster_values:
        return False

    for identifier in assessment.found_observation_ids:
        linked_value = observation_map[identifier].attributes.get(
            correlation_attribute
        )
        if (
            linked_value is not None
            and _canonical(linked_value) in cluster_values
        ):
            return True

    return False

def _stable_hypothesis_id(
    rule: InferenceRule,
    candidate_attributes: Mapping[str, Any],
    observation_ids: Iterable[str],
    temporal_extent: TemporalExtent,
    config: ReconstructionConfig,
) -> str:
    material = {
        "rule_id": rule.rule_id,
        "rule_version": rule.version,
        "candidate_attributes": _plain(candidate_attributes),
        "observation_ids": sorted(observation_ids),
        "temporal_extent": temporal_extent.to_dict(),
        "config": config.to_dict(),
    }
    digest = hashlib.sha256(_canonical(material).encode("utf-8")).hexdigest()
    return "hyp-" + digest[:24]


def reconstruct(
    *,
    observations: Iterable[SourceObservation],
    rules: Iterable[InferenceRule],
    coverage_records: Iterable[SourceCoverage] = (),
    observation_assessments: Iterable[ObservationAssessment] = (),
    candidate_window_seconds: int = 300,
    absence_counterevidence_types_by_rule: (
        Mapping[str, Iterable[str]] | None
    ) = None,
    review_status: ReviewStatus = ReviewStatus.NOT_REVIEWED,
) -> ReconstructionResult:
    """
    Generate and evaluate candidate hypotheses deterministically.

    Candidate identity is defined by each rule's required attributes.
    Candidate time grouping uses an explicit configurable window.

    An absence policy may be keyed by "rule_id@version", or by rule_id
    when only one version is supplied. It is passed into the evaluator
    and recorded in the resulting hypothesis assumptions.

    Rules without required_attributes are rejected because this engine
    requires an explicit identity key for candidate generation.
    """
    config = ReconstructionConfig(candidate_window_seconds)

    if not isinstance(review_status, ReviewStatus):
        raise ModelValidationError(
            "review_status must be a ReviewStatus value"
        )

    observation_items = tuple(observations)
    rule_items = tuple(rules)
    coverage_items = tuple(coverage_records)
    assessment_items = tuple(observation_assessments)

    if any(
        not isinstance(item, SourceObservation)
        for item in observation_items
    ):
        raise ModelValidationError(
            "Every input observation must be a SourceObservation"
        )

    if any(not isinstance(item, InferenceRule) for item in rule_items):
        raise ModelValidationError(
            "Every rule must be an InferenceRule"
        )

    if any(not isinstance(item, SourceCoverage) for item in coverage_items):
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

    rule_items = tuple(sorted(
        rule_items,
        key=lambda item: (item.rule_id, item.version),
    ))

    rule_keys = [(item.rule_id, item.version) for item in rule_items]
    if len(set(rule_keys)) != len(rule_keys):
        raise ModelValidationError(
            "Duplicate inference rule ID and version"
        )

    for rule in rule_items:
        if not rule.required_attributes:
            raise ModelValidationError(
                f"Rule {rule.rule_id!r} requires at least one "
                "required attribute for candidate identity"
            )

    observation_items = tuple(sorted(
        observation_items,
        key=lambda item: item.observation_id,
    ))
    observation_map = {
        item.observation_id: item for item in observation_items
    }
    if len(observation_map) != len(observation_items):
        raise ModelValidationError(
            "Observation identifiers must be unique"
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

    for assessment in assessment_items:
        if assessment.coverage_id not in coverage_map:
            raise ModelValidationError(
                f"Assessment {assessment.assessment_id!r} references "
                "an unknown coverage ID"
            )

        linked_ids = (
            set(assessment.found_observation_ids)
            | set(assessment.supporting_indicator_observation_ids)
        )
        missing_ids = linked_ids - set(observation_map)
        if missing_ids:
            raise ModelValidationError(
                f"Assessment {assessment.assessment_id!r} references "
                f"unknown observation IDs: {sorted(missing_ids)!r}"
            )

    if absence_counterevidence_types_by_rule is not None:
        if not isinstance(absence_counterevidence_types_by_rule, Mapping):
            raise ModelValidationError(
                "absence_counterevidence_types_by_rule must be a mapping"
            )

    hypotheses: list[EventHypothesis] = []
    skipped: list[SkippedInput] = []

    for rule in rule_items:
        required_attributes = rule.required_attributes
        required_types = set(rule.required_observation_types)

        identity_groups: dict[str, tuple[dict[str, Any], list[SourceObservation]]] = {}

        for observation in observation_items:
            if required_types and observation.source_type not in required_types:
                continue

            if observation.parse_status in (
                ParseStatus.FAILED,
                ParseStatus.UNSUPPORTED,
            ):
                skipped.append(SkippedInput(
                    rule_id=rule.rule_id,
                    rule_version=rule.version,
                    observation_id=observation.observation_id,
                    reason=(
                        "Observation cannot seed a candidate because "
                        "parsing failed or is unsupported."
                    ),
                ))
                continue

            if not rule.matches_observation_attributes(
                observation.attributes
            ):
                skipped.append(SkippedInput(
                    rule_id=rule.rule_id,
                    rule_version=rule.version,
                    observation_id=observation.observation_id,
                    reason=(
                        "Required observation attribute conditions "
                        "did not match."
                    ),
                ))
                continue

            missing = [
                key for key in required_attributes
                if key not in observation.attributes
            ]
            if missing:
                skipped.append(SkippedInput(
                    rule_id=rule.rule_id,
                    rule_version=rule.version,
                    observation_id=observation.observation_id,
                    reason=(
                        "Missing candidate identity attributes: "
                        + ", ".join(missing)
                    ),
                ))
                continue

            candidate_attributes = {
                key: _plain(observation.attributes[key])
                for key in required_attributes
            }
            identity_key = _canonical(candidate_attributes)

            if identity_key not in identity_groups:
                identity_groups[identity_key] = (
                    candidate_attributes,
                    [],
                )

            identity_groups[identity_key][1].append(observation)

        for identity_key in sorted(identity_groups):
            candidate_attributes, identity_observations = (
                identity_groups[identity_key]
            )

            partition_groups: dict[
                str, list[SourceObservation]
            ] = {}

            for item in identity_observations:
                if not rule.candidate_partition_attributes:
                    partition_key = "default"
                elif all(
                    name in item.attributes
                    and item.attributes[name] is not None
                    for name in rule.candidate_partition_attributes
                ):
                    partition_values = {
                        name: _plain(item.attributes[name])
                        for name in rule.candidate_partition_attributes
                    }
                    partition_key = (
                        "explicit:" + _canonical(partition_values)
                    )
                else:
                    # Missing correlation IDs must not silently merge
                    # an observation into another explicit session.
                    partition_key = (
                        "unpartitioned:" + item.observation_id
                    )

                partition_groups.setdefault(
                    partition_key, []
                ).append(item)

            clusters = tuple(
                cluster
                for partition_key in sorted(partition_groups)
                for cluster in _cluster_by_time(
                    partition_groups[partition_key],
                    config.candidate_window_seconds,
                )
            )

            for cluster in clusters:
                cluster_types = {item.source_type for item in cluster}

                if required_types and not (cluster_types & required_types):
                    continue

                extent = _candidate_extent(cluster)
                cluster_ids = {item.observation_id for item in cluster}

                matched_assessments: list[ObservationAssessment] = []

                for assessment in assessment_items:
                    if (
                        assessment.expected_artifact_type
                        not in rule.expected_artifact_types
                    ):
                        continue

                    if not _scope_matches(
                        assessment.scope_attributes,
                        candidate_attributes,
                    ):
                        continue

                    if not _overlaps(assessment.expected_extent, extent):
                        continue

                    if not _assessment_links_compatible(
                        assessment,
                        cluster_ids,
                        observation_map,
                        required_types,
                        candidate_attributes,
                        rule.expected_artifact_correlation_attribute,
                    ):
                        continue

                    matched_assessments.append(assessment)

                if rule.suppress_if_expected_artifact_observed and any(
                    _assessment_confirms_correlated_observed_artifact(
                        assessment,
                        cluster_ids,
                        observation_map,
                        rule.expected_artifact_correlation_attribute,
                    )
                    for assessment in matched_assessments
                ):
                    skipped.append(SkippedInput(
                        rule_id=rule.rule_id,
                        rule_version=rule.version,
                        observation_id=cluster[0].observation_id,
                        reason=(
                            "Fallback candidate suppressed because an "
                            "observed expected artifact shares its explicit "
                            "correlation identifier."
                        ),
                    ))
                    continue

                correlated_observations = _find_correlated_observations(
                    rule=rule,
                    cluster=cluster,
                    observations=observation_items,
                    candidate_attributes=candidate_attributes,
                    candidate_window_seconds=config.candidate_window_seconds,
                )
                correlated_ids = tuple(
                    item.observation_id for item in correlated_observations
                )

                input_ids = set(cluster_ids)
                input_ids.update(correlated_ids)

                for assessment in matched_assessments:
                    input_ids.update(assessment.found_observation_ids)
                    input_ids.update(
                        assessment.supporting_indicator_observation_ids
                    )

                hypothesis_observations = tuple(
                    observation_map[identifier]
                    for identifier in sorted(input_ids)
                )

                assessment_coverage_ids = {
                    item.coverage_id for item in matched_assessments
                }
                evidence_source_pairs = {
                    (item.evidence_id, item.source_type)
                    for item in hypothesis_observations
                }

                relevant_coverage = tuple(
                    item for item in coverage_items
                    if (
                        item.coverage_id in assessment_coverage_ids
                        or (item.evidence_id, item.source_type)
                        in evidence_source_pairs
                    )
                )

                policy_key = f"{rule.rule_id}@{rule.version}"
                absence_types: Iterable[str] = ()

                if absence_counterevidence_types_by_rule is not None:
                    absence_types = absence_counterevidence_types_by_rule.get(
                        policy_key,
                        absence_counterevidence_types_by_rule.get(
                            rule.rule_id, ()
                        ),
                    )

                hypothesis_id = _stable_hypothesis_id(
                    rule,
                    candidate_attributes,
                    cluster_ids,
                    extent,
                    config,
                )

                assumptions = (
                    "Candidate grouping window: "
                    f"{config.candidate_window_seconds} seconds. "
                    "This window groups observations for candidate "
                    "generation only and does not establish causality.",
                )

                hypothesis = evaluate_candidate_hypothesis(
                    hypothesis_id=hypothesis_id,
                    rule=rule,
                    observations=hypothesis_observations,
                    candidate_attributes=candidate_attributes,
                    temporal_extent=extent,
                    coverage_records=relevant_coverage,
                    observation_assessments=matched_assessments,
                    absence_counterevidence_types=absence_types,
                    assumptions=assumptions,
                    review_status=review_status,
                    correlated_observation_ids=correlated_ids,
                )
                hypotheses.append(hypothesis)

    hypotheses.sort(key=lambda item: item.hypothesis_id)
    skipped.sort(key=lambda item: (
        item.rule_id,
        item.rule_version,
        item.observation_id,
        item.reason,
    ))

    return ReconstructionResult(
        config=config,
        rule_versions=tuple(
            (rule.rule_id, rule.version) for rule in rule_items
        ),
        hypotheses=tuple(hypotheses),
        skipped_inputs=tuple(skipped),
    )
