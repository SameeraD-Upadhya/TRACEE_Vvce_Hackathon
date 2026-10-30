"""Adapter between TRACEE reconstruction and benchmark evaluation."""

from __future__ import annotations

from benchmarks.evaluate import BenchmarkPrediction
from benchmarks.models import BenchmarkInput
from tracee.hypotheses import InferenceRule
from tracee.models import ModelValidationError
from tracee.reconstruction import ReconstructionResult, reconstruct


SESSION_ACTIVITY_RULE_ID = "auth-candidate-from-session-activity"
SESSION_CREATION_RULE_ID = "auth-candidate-from-session-creation"


def benchmark_inference_rules() -> tuple[InferenceRule, ...]:
    """Return the versioned rules used by the synthetic benchmark."""

    explicit_authentication = InferenceRule(
        rule_id="explicit-authentication-success",
        version="1.0",
        event_type="authentication_success",
        description=(
            "Identify explicit authentication success in a supported "
            "benchmark observation."
        ),
        required_attributes=("user", "host"),
        required_observation_attributes={
            "action": "authentication_success",
        },
        candidate_partition_attributes=("session_id",),
        correlated_observation_types=("endpoint_audit",),
        correlated_observation_attributes={
            "action": "session_created",
        },
        correlated_observation_correlation_attribute="session_id",
        limitations=(
            "Endpoint session creation is recorded as explicitly correlated "
            "context, not direct proof of authentication success.",
            "Evaluated only against the source types and action values "
            "represented by this synthetic benchmark.",
        ),
    )

    session_activity = InferenceRule(
        rule_id=SESSION_ACTIVITY_RULE_ID,
        version="1.0",
        event_type="authentication_success",
        description=(
            "Evaluate whether session activity is consistent with an "
            "authentication event when an authentication record is missing."
        ),
        required_attributes=("user", "host"),
        required_observation_attributes={
            "action": "session_activity",
        },
        expected_artifact_types=("authentication_record",),
        candidate_partition_attributes=("session_id",),
        limitations=(
            "Session activity does not establish successful authentication.",
            "The interpretation depends on the availability and coverage "
            "of the expected authentication record.",
        ),
    )

    session_creation = InferenceRule(
        rule_id=SESSION_CREATION_RULE_ID,
        version="1.1",
        event_type="authentication_success",
        description=(
            "Create an unresolved authentication candidate from endpoint "
            "session creation when its authentication record is absent."
        ),
        required_attributes=("user", "host"),
        required_observation_attributes={
            "action": "session_created",
        },
        expected_artifact_types=("authentication_record",),
        candidate_partition_attributes=("session_id",),
        suppress_if_expected_artifact_observed=True,
        expected_artifact_correlation_attribute="session_id",
        limitations=(
            "Session creation is indirect evidence and does not by itself "
            "establish successful authentication.",
            "The interpretation depends on authentication-log coverage and "
            "availability of the expected record.",
        ),
    )

    return explicit_authentication, session_activity, session_creation


def run_tracee_reconstruction(
    method_input: BenchmarkInput,
    candidate_window_seconds: int = 300,
) -> ReconstructionResult:
    """Run the actual reconstruction engine using benchmark rules."""

    if not isinstance(method_input, BenchmarkInput):
        raise ModelValidationError(
            "method_input must be a BenchmarkInput"
        )

    return reconstruct(
        observations=method_input.observations,
        rules=benchmark_inference_rules(),
        coverage_records=method_input.coverage_records,
        observation_assessments=method_input.observation_assessments,
        candidate_window_seconds=candidate_window_seconds,
        absence_counterevidence_types_by_rule={
            f"{SESSION_ACTIVITY_RULE_ID}@1.0": (
                "authentication_record",
            ),
            f"{SESSION_CREATION_RULE_ID}@1.1": (
                "authentication_record",
            ),
        },
    )


def hypotheses_to_predictions(
    result: ReconstructionResult,
) -> tuple[BenchmarkPrediction, ...]:
    """Convert reconstruction hypotheses without changing their status."""

    if not isinstance(result, ReconstructionResult):
        raise ModelValidationError(
            "result must be a ReconstructionResult"
        )

    predictions = []

    for hypothesis in result.hypotheses:
        predictions.append(
            BenchmarkPrediction(
                prediction_id=f"tracee-{hypothesis.hypothesis_id}",
                event_type=hypothesis.event_type,
                entity_attributes=hypothesis.attributes,
                temporal_extent=hypothesis.temporal_extent,
                source_observation_ids=tuple(
                    sorted(hypothesis.supporting_observation_ids)
                ),
                correlated_observation_ids=tuple(
                    sorted(hypothesis.correlated_observation_ids)
                ),
                interpretation_state=hypothesis.interpretation.value,
                inference_rule_id=hypothesis.inference_rule_id,
                inference_rule_version=hypothesis.inference_rule_version,
            )
        )

    return tuple(sorted(predictions, key=lambda item: item.prediction_id))


def tracee_predictions(
    method_input: BenchmarkInput,
    candidate_window_seconds: int = 300,
) -> tuple[BenchmarkPrediction, ...]:
    """Return benchmark predictions from TRACEE's reconstruction engine."""

    result = run_tracee_reconstruction(
        method_input,
        candidate_window_seconds=candidate_window_seconds,
    )
    return hypotheses_to_predictions(result)
