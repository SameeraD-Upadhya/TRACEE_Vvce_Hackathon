"""Tests for TRACEE's deterministic hypothesis evaluator."""

from datetime import datetime, timezone

import pytest

from tracee.coverage import (
    CoverageInterval,
    CoverageStatus,
    ObservationAssessment,
    ObservationAvailability,
    SourceCoverage,
)
from tracee.events import ParseStatus, SourceObservation, TemporalExtent
from tracee.hypotheses import (
    InferenceRule,
    InterpretationState,
)
from tracee.inference import evaluate_candidate_hypothesis
from tracee.models import ModelValidationError


EVIDENCE_ID = "TRACE-EV-000001"
UTC = timezone.utc


def time_at(hour):
    return datetime(2026, 10, 2, hour, tzinfo=UTC)


def make_extent():
    return TemporalExtent(time_at(1), time_at(2))


def make_observation(
    observation_id="obs-001",
    source_type="linux_auth",
    attributes=None,
    parse_status=ParseStatus.PARSED,
    parse_errors=(),
):
    return SourceObservation(
        observation_id=observation_id,
        evidence_id=EVIDENCE_ID,
        source_type=source_type,
        source_locator=f"test-source:{observation_id}",
        parser_name="test_parser",
        parser_version="1.0",
        attributes=attributes or {"user": "alice"},
        parse_status=parse_status,
        parse_errors=parse_errors,
    )


def make_rule(**overrides):
    values = {
        "rule_id": "authentication-rule",
        "version": "1.0",
        "event_type": "authentication_success",
        "description": "Evaluate an authentication hypothesis.",
        "required_observation_types": ("linux_auth",),
        "required_attributes": ("user",),
        "expected_artifact_types": ("authentication_record",),
        "minimum_supporting_observations": 1,
        "requires_source_coverage": True,
    }
    values.update(overrides)
    return InferenceRule(**values)


def make_coverage(status=CoverageStatus.KNOWN_COVERAGE):
    intervals = (
        (CoverageInterval(time_at(0), time_at(4)),)
        if status in (
            CoverageStatus.KNOWN_COVERAGE,
            CoverageStatus.PARTIAL_COVERAGE,
        )
        else ()
    )

    return SourceCoverage(
        coverage_id="coverage-001",
        evidence_id=EVIDENCE_ID,
        source_type="linux_auth",
        source_locator="/var/log/auth.log",
        status=status,
        intervals=intervals,
        basis="Controlled test fixture",
    )


def make_assessment(
    availability=ObservationAvailability.OBSERVED,
    found_ids=("obs-001",),
    indicator_ids=(),
    scope_attributes=None,
):
    if scope_attributes is None:
        scope_attributes = {"user": "alice"}

    return ObservationAssessment(
        assessment_id="assessment-001",
        expected_artifact_type="authentication_record",
        coverage_id="coverage-001",
        expected_extent=make_extent(),
        availability=availability,
        scope_attributes=scope_attributes,
        found_observation_ids=found_ids,
        supporting_indicator_observation_ids=indicator_ids,
        explanation="Controlled test fixture",
    )


def evaluate(
    *,
    observations=None,
    rule=None,
    coverage=None,
    assessments=None,
    attributes=None,
    contradictions=(),
    absence_counterevidence=(),
):
    observations = observations or (make_observation(),)
    rule = rule or make_rule()
    coverage = coverage or make_coverage()
    assessments = (
        assessments
        if assessments is not None
        else (make_assessment(),)
    )

    return evaluate_candidate_hypothesis(
        hypothesis_id="hyp-001",
        rule=rule,
        observations=observations,
        candidate_attributes=(attributes if attributes is not None else {"user": "alice"}),
        temporal_extent=make_extent(),
        coverage_records=(coverage,),
        observation_assessments=assessments,
        contradicting_observation_ids=contradictions,
        absence_counterevidence_types=absence_counterevidence,
    )


def test_matching_evidence_corroborates_candidate():
    result = evaluate()

    assert result.interpretation is InterpretationState.CORROBORATED
    assert result.supporting_observation_ids == ("obs-001",)
    assert result.inference_rule_version == "1.0"


def test_wrong_candidate_attribute_is_not_supported():
    result = evaluate(attributes={"user": "mallory"})

    assert result.interpretation is InterpretationState.INSUFFICIENT_INPUT
    assert not result.supporting_observation_ids


def test_missing_required_candidate_attribute_is_insufficient():
    result = evaluate(attributes={})

    assert result.interpretation is InterpretationState.INSUFFICIENT_INPUT
    assert result.unresolved_conditions


def test_explicit_contradictory_observation_challenges_candidate():
    observations = (
        make_observation(),
        make_observation(
            observation_id="obs-002",
            source_type="other_source",
            attributes={"user": "mallory"},
        ),
    )

    result = evaluate(
        observations=observations,
        contradictions=("obs-002",),
    )

    assert result.interpretation is InterpretationState.CHALLENGED
    assert result.supporting_observation_ids == ("obs-001",)
    assert result.contradicting_observation_ids == ("obs-002",)


def test_unknown_coverage_does_not_create_contradiction():
    coverage = make_coverage(CoverageStatus.COVERAGE_UNKNOWN)
    assessment = make_assessment(
        ObservationAvailability.NOT_OBSERVED_WITH_UNKNOWN_COVERAGE,
        found_ids=(),
    )

    result = evaluate(coverage=coverage, assessments=(assessment,))

    assert result.interpretation is InterpretationState.UNDERDETERMINED
    assert not result.contradicting_assessment_ids
    assert result.unresolved_conditions


def test_missing_artifact_is_not_counterevidence_by_default():
    assessment = make_assessment(
        ObservationAvailability.NOT_OBSERVED_WITH_KNOWN_COVERAGE,
        found_ids=(),
    )

    result = evaluate(assessments=(assessment,))

    assert result.interpretation is InterpretationState.UNDERDETERMINED
    assert not result.contradicting_assessment_ids


def test_explicitly_configured_absence_can_challenge_candidate():
    assessment = make_assessment(
        ObservationAvailability.NOT_OBSERVED_WITH_KNOWN_COVERAGE,
        found_ids=(),
    )

    result = evaluate(
        assessments=(assessment,),
        absence_counterevidence=("authentication_record",),
    )

    assert result.interpretation is InterpretationState.CHALLENGED
    assert result.contradicting_assessment_ids == ("assessment-001",)


def test_possible_removal_remains_unresolved():
    observations = (
        make_observation(),
        make_observation(
            observation_id="obs-002",
            source_type="integrity_event",
            attributes={"indicator": "log_truncation"},
        ),
    )

    assessment = make_assessment(
        ObservationAvailability.POSSIBLE_REMOVAL_WITH_SUPPORTING_INDICATORS,
        found_ids=(),
        indicator_ids=("obs-002",),
    )

    result = evaluate(
        observations=observations,
        assessments=(assessment,),
        absence_counterevidence=("authentication_record",),
    )

    assert result.interpretation is InterpretationState.UNDERDETERMINED
    assert not result.contradicting_assessment_ids
    assert result.unresolved_conditions


def test_unavailable_source_prevents_definitive_corroboration():
    coverage = make_coverage(CoverageStatus.SOURCE_UNAVAILABLE)
    assessment = make_assessment(
        ObservationAvailability.SOURCE_UNAVAILABLE,
        found_ids=(),
    )

    result = evaluate(coverage=coverage, assessments=(assessment,))

    assert result.interpretation is InterpretationState.INSUFFICIENT_INPUT


def test_missing_assessment_leaves_expected_artifact_unresolved():
    result = evaluate(assessments=())

    assert result.interpretation is InterpretationState.INSUFFICIENT_INPUT
    assert any(
        "No assessment supplied" in item
        for item in result.unresolved_conditions
    )


def test_partial_parse_prevents_full_corroboration():
    observation = make_observation(
        parse_status=ParseStatus.PARTIAL,
    )

    result = evaluate(observations=(observation,))

    assert result.interpretation is InterpretationState.UNDERDETERMINED


def test_failed_parse_cannot_support_candidate():
    observation = make_observation(
        parse_status=ParseStatus.FAILED,
        parse_errors=("Malformed source record",),
    )

    result = evaluate(observations=(observation,))

    assert result.interpretation is InterpretationState.INSUFFICIENT_INPUT
    assert not result.supporting_observation_ids


def test_unknown_contradiction_reference_is_rejected():
    with pytest.raises(ModelValidationError):
        evaluate(contradictions=("obs-not-supplied",))


def test_duplicate_observation_ids_are_rejected():
    with pytest.raises(ModelValidationError):
        evaluate(
            observations=(
                make_observation(),
                make_observation(),
            )
        )


def test_undeclared_absence_counterevidence_type_is_rejected():
    with pytest.raises(ModelValidationError):
        evaluate(absence_counterevidence=("unknown_artifact",))


def test_serialized_hypothesis_preserves_rule_and_derivation():
    result = evaluate().to_dict()

    assert result["inference_rule_id"] == "authentication-rule"
    assert result["inference_rule_version"] == "1.0"
    assert result["input_observation_ids"] == ["obs-001"]
    assert result["supporting_observation_ids"] == ["obs-001"]
    assert result["observation_assessment_ids"] == ["assessment-001"]



def test_mismatched_scope_cannot_challenge_another_entity():
    assessment = make_assessment(
        ObservationAvailability.NOT_OBSERVED_WITH_KNOWN_COVERAGE,
        found_ids=(),
        scope_attributes={"user": "bob"},
    )

    result = evaluate(
        assessments=(assessment,),
        absence_counterevidence=("authentication_record",),
    )

    assert result.interpretation is InterpretationState.INSUFFICIENT_INPUT
    assert result.contradicting_assessment_ids == ()
    assert any(
        "candidate scope" in condition
        for condition in result.unresolved_conditions
    )


def test_empty_scope_cannot_be_used_as_candidate_counterevidence():
    assessment = make_assessment(
        ObservationAvailability.NOT_OBSERVED_WITH_KNOWN_COVERAGE,
        found_ids=(),
        scope_attributes={},
    )

    result = evaluate(
        assessments=(assessment,),
        absence_counterevidence=("authentication_record",),
    )

    assert result.interpretation is InterpretationState.INSUFFICIENT_INPUT
    assert result.contradicting_assessment_ids == ()


def test_nested_scope_attributes_match_exactly():
    attributes = {
        "user": "alice",
        "process": {"pid": 1234},
    }
    observation = make_observation(attributes=attributes)
    assessment = make_assessment(
        scope_attributes={"process": {"pid": 1234}},
    )

    result = evaluate(
        observations=(observation,),
        attributes=attributes,
        assessments=(assessment,),
    )

    assert result.interpretation is InterpretationState.CORROBORATED
    assert result.observation_assessment_ids == ("assessment-001",)
