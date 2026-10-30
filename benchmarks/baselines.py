"""Reference methods for the synthetic reconstruction benchmark."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone

from benchmarks.evaluate import BenchmarkPrediction
from benchmarks.models import BenchmarkInput
from tracee.events import SourceObservation, TemporalExtent
from tracee.models import ModelValidationError


_UNKNOWN_TIME = datetime.max.replace(tzinfo=timezone.utc)


def _validate_input(method_input: BenchmarkInput) -> None:
    if not isinstance(method_input, BenchmarkInput):
        raise ModelValidationError("method_input must be a BenchmarkInput")


def _action(observation: SourceObservation) -> str:
    value = observation.attributes.get("action")
    if isinstance(value, str) and value.strip():
        return value.strip()
    return "unclassified_observation"


def _identity(observation: SourceObservation) -> tuple[str, str] | None:
    user = observation.attributes.get("user")
    host = observation.attributes.get("host")

    if not isinstance(user, str) or not user.strip():
        return None
    if not isinstance(host, str) or not host.strip():
        return None

    return user, host


def _entity_attributes(observation: SourceObservation) -> dict[str, object]:
    return {
        key: observation.attributes[key]
        for key in ("user", "host")
        if key in observation.attributes
    }


def _extent_key(
    extent: TemporalExtent,
    identifier: str,
) -> tuple[bool, datetime, str]:
    earliest = extent.earliest_utc
    return (earliest is None, earliest or _UNKNOWN_TIME, identifier)


def _observation_key(
    observation: SourceObservation,
) -> tuple[bool, datetime, str]:
    return _extent_key(
        observation.timestamp.normalized_extent,
        observation.observation_id,
    )


def _prediction_key(
    prediction: BenchmarkPrediction,
) -> tuple[bool, datetime, str]:
    return _extent_key(prediction.temporal_extent, prediction.prediction_id)


def _merge_extents(
    observations: tuple[SourceObservation, ...],
) -> TemporalExtent:
    extents = tuple(item.timestamp.normalized_extent for item in observations)

    earliest_values = tuple(item.earliest_utc for item in extents)
    latest_values = tuple(item.latest_utc for item in extents)

    earliest = (
        None
        if any(value is None for value in earliest_values)
        else min(earliest_values)
    )
    latest = (
        None
        if any(value is None for value in latest_values)
        else max(latest_values)
    )

    return TemporalExtent(earliest, latest)


def _time_distance_seconds(
    left: TemporalExtent,
    right: TemporalExtent,
) -> float | None:
    bounds = (
        left.earliest_utc,
        left.latest_utc,
        right.earliest_utc,
        right.latest_utc,
    )
    if any(value is None for value in bounds):
        return None

    left_start, left_end, right_start, right_end = bounds

    if left_end < right_start:
        return (right_start - left_end).total_seconds()
    if right_end < left_start:
        return (left_start - right_end).total_seconds()
    return 0.0


def chronology_only_predictions(
    method_input: BenchmarkInput,
) -> tuple[BenchmarkPrediction, ...]:
    """Emit target-event predictions from explicit authentication records."""

    _validate_input(method_input)
    observations = sorted(
        (
            item for item in method_input.observations
            if _action(item) == "authentication_success"
        ),
        key=_observation_key,
    )

    return tuple(
        BenchmarkPrediction(
            prediction_id=f"chronology-{item.observation_id}",
            event_type="authentication_success",
            entity_attributes=_entity_attributes(item),
            temporal_extent=item.timestamp.normalized_extent,
            source_observation_ids=(item.observation_id,),
            interpretation_state="observed",
        )
        for item in observations
    )


def rule_correlation_predictions(
    method_input: BenchmarkInput,
    correlation_window_seconds: int = 300,
) -> tuple[BenchmarkPrediction, ...]:
    """Correlate nearby login and session records for target-event prediction."""

    _validate_input(method_input)

    if (
        not isinstance(correlation_window_seconds, int)
        or isinstance(correlation_window_seconds, bool)
        or correlation_window_seconds < 0
    ):
        raise ModelValidationError(
            "correlation_window_seconds must be a non-negative integer"
        )

    observations = tuple(
        sorted(method_input.observations, key=_observation_key)
    )
    authentications = tuple(
        item for item in observations
        if _action(item) == "authentication_success"
    )
    sessions = tuple(
        item for item in observations
        if _action(item) == "session_created"
    )

    paired_sessions: dict[str, SourceObservation] = {}
    used_authentication_ids: set[str] = set()

    for session in sessions:
        session_identity = _identity(session)
        if session_identity is None:
            continue

        candidates = []
        for authentication in authentications:
            if authentication.observation_id in used_authentication_ids:
                continue
            if _identity(authentication) != session_identity:
                continue

            distance = _time_distance_seconds(
                authentication.timestamp.normalized_extent,
                session.timestamp.normalized_extent,
            )
            if (
                distance is not None
                and distance <= correlation_window_seconds
            ):
                candidates.append(
                    (distance, authentication.observation_id, authentication)
                )

        if candidates:
            _, authentication_id, authentication = min(
                candidates, key=lambda item: (item[0], item[1])
            )
            paired_sessions[authentication_id] = session
            used_authentication_ids.add(authentication_id)

    predictions = []

    for authentication in authentications:
        session = paired_sessions.get(authentication.observation_id)

        if session is None:
            source_ids = (authentication.observation_id,)
            extent = authentication.timestamp.normalized_extent
            state = "observed"
        else:
            related = (authentication, session)
            source_ids = tuple(sorted(
                item.observation_id for item in related
            ))
            extent = _merge_extents(related)
            state = "rule_correlated"

        digest = hashlib.sha256(
            "\\0".join(source_ids).encode("utf-8")
        ).hexdigest()[:20]

        predictions.append(
            BenchmarkPrediction(
                prediction_id=f"rule-correlation-{digest}",
                event_type="authentication_success",
                entity_attributes=_entity_attributes(authentication),
                temporal_extent=extent,
                source_observation_ids=source_ids,
                interpretation_state=state,
                inference_rule_id=(
                    "basic-auth-session-correlation" if session else None
                ),
                inference_rule_version="1.0" if session else None,
            )
        )

    return tuple(sorted(predictions, key=_prediction_key))
