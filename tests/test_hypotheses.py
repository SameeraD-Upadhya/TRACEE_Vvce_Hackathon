"""Tests for TRACEE evidence-backed hypothesis models."""

import pytest

from tracee.events import TemporalExtent
from tracee.hypotheses import (
    EventHypothesis,
    InferenceRule,
    InterpretationState,
    ReviewStatus,
)
from tracee.models import ModelValidationError


def make_rule(**overrides):
    values = {
        "rule_id": "auth-success",
        "version": "1.0",
        "event_type": "authentication_success",
        "description": "Identify a successful authentication event.",
        "required_observation_types": ["linux_auth"],
        "required_attributes": ["user"],
        "expected_artifact_types": ["authentication_record"],
        "minimum_supporting_observations": 1,
        "requires_source_coverage": True,
        "limitations": ["Requires a supported authentication log."],
    }
    values.update(overrides)
    return InferenceRule(**values)


def make_hypothesis(**overrides):
    values = {
        "hypothesis_id": "hyp-001",
        "event_type": "authentication_success",
        "inference_rule_id": "auth-success",
        "inference_rule_version": "1.0",
        "input_observation_ids": ("obs-001", "obs-002"),
        "interpretation": InterpretationState.CORROBORATED,
        "supporting_observation_ids": ("obs-001",),
        "contradicting_observation_ids": (),
        "coverage_ids": ("coverage-001",),
        "observation_assessment_ids": ("assessment-001",),
        "attributes": {"user": "alice"},
        "temporal_extent": TemporalExtent(),
        "assumptions": (),
        "unresolved_conditions": (),
        "limitations": (),
        "review_status": ReviewStatus.NOT_REVIEWED,
    }
    values.update(overrides)
    return EventHypothesis(**values)


def test_valid_inference_rule_is_created():
    rule = make_rule()

    assert rule.rule_id == "auth-success"
    assert rule.version == "1.0"
    assert rule.requires_source_coverage is True


def test_rule_serialization_preserves_version_and_requirements():
    result = make_rule().to_dict()
    assert result["schema_version"] == "1.2"
    assert result["candidate_partition_attributes"] == []

    assert result["rule_id"] == "auth-success"
    assert result["version"] == "1.0"
    assert result["required_attributes"] == ["user"]
    assert result["required_observation_attributes"] == {}
    assert result["minimum_supporting_observations"] == 1


def test_rule_observation_attribute_conditions_match_exact_values():
    rule = make_rule(
        required_observation_attributes={
            "action": "authentication_success",
        }
    )

    assert rule.matches_observation_attributes(
        {"action": "authentication_success"}
    )
    assert not rule.matches_observation_attributes(
        {"action": "session_activity"}
    )
    assert not rule.matches_observation_attributes({})
    assert rule.to_dict()["required_observation_attributes"] == {
        "action": "authentication_success"
    }


def test_rule_observation_attribute_conditions_are_immutable():
    rule = make_rule(
        required_observation_attributes={"action": "authentication_success"}
    )
    with pytest.raises(TypeError):
        rule.required_observation_attributes["action"] = "session_activity"


def test_rule_rejects_non_mapping_observation_attribute_conditions():
    with pytest.raises(ModelValidationError):
        make_rule(required_observation_attributes=["action"])


@pytest.mark.parametrize(
    "field,value",
    [
        ("rule_id", ""),
        ("version", " "),
        ("event_type", ""),
        ("description", ""),
    ],
)
def test_rule_rejects_empty_required_fields(field, value):
    with pytest.raises(ModelValidationError):
        make_rule(**{field: value})


@pytest.mark.parametrize("value", [0, -1, True])
def test_rule_requires_positive_integer_support_count(value):
    with pytest.raises(ModelValidationError):
        make_rule(minimum_supporting_observations=value)


def test_rule_rejects_non_boolean_coverage_requirement():
    with pytest.raises(ModelValidationError):
        make_rule(requires_source_coverage="yes")


def test_rule_sequences_are_immutable():
    rule = make_rule()

    assert rule.required_observation_types == ("linux_auth",)

    with pytest.raises(AttributeError):
        rule.required_observation_types.append("windows_event")


def test_valid_hypothesis_is_created():
    hypothesis = make_hypothesis()

    assert hypothesis.hypothesis_id == "hyp-001"
    assert hypothesis.interpretation is InterpretationState.CORROBORATED
    assert hypothesis.review_status is ReviewStatus.NOT_REVIEWED


def test_hypothesis_requires_at_least_one_input_observation():
    with pytest.raises(ModelValidationError):
        make_hypothesis(input_observation_ids=())


def test_supporting_observation_must_be_an_input():
    with pytest.raises(ModelValidationError):
        make_hypothesis(
            supporting_observation_ids=("obs-not-in-inputs",)
        )


def test_contradictory_observation_must_be_an_input():
    with pytest.raises(ModelValidationError):
        make_hypothesis(
            contradicting_observation_ids=("obs-not-in-inputs",)
        )


def test_observation_cannot_support_and_contradict_same_hypothesis():
    with pytest.raises(ModelValidationError):
        make_hypothesis(
            supporting_observation_ids=("obs-001",),
            contradicting_observation_ids=("obs-001",),
        )


def test_corroborated_hypothesis_requires_support():
    with pytest.raises(ModelValidationError):
        make_hypothesis(supporting_observation_ids=())


def test_challenged_hypothesis_requires_contradictory_evidence():
    with pytest.raises(ModelValidationError):
        make_hypothesis(
            interpretation=InterpretationState.CHALLENGED,
            supporting_observation_ids=(),
            contradicting_observation_ids=(),
        )


def test_challenged_hypothesis_preserves_contradictory_evidence():
    hypothesis = make_hypothesis(
        interpretation=InterpretationState.CHALLENGED,
        supporting_observation_ids=(),
        contradicting_observation_ids=("obs-002",),
    )

    assert hypothesis.contradicting_observation_ids == ("obs-002",)


def test_support_and_contradiction_can_both_be_preserved():
    hypothesis = make_hypothesis(
        supporting_observation_ids=("obs-001",),
        contradicting_observation_ids=("obs-002",),
    )

    assert hypothesis.supporting_observation_ids == ("obs-001",)
    assert hypothesis.contradicting_observation_ids == ("obs-002",)


@pytest.mark.parametrize(
    "state",
    [
        InterpretationState.UNDERDETERMINED,
        InterpretationState.INSUFFICIENT_INPUT,
    ],
)
def test_unresolved_states_require_explanation(state):
    with pytest.raises(ModelValidationError):
        make_hypothesis(
            interpretation=state,
            unresolved_conditions=(),
        )


def test_underdetermined_hypothesis_records_unknown_conditions():
    hypothesis = make_hypothesis(
        interpretation=InterpretationState.UNDERDETERMINED,
        unresolved_conditions=("Source coverage is unknown.",),
    )

    assert hypothesis.unresolved_conditions == (
        "Source coverage is unknown.",
    )


def test_attributes_are_deeply_immutable():
    hypothesis = make_hypothesis(
        attributes={"process": {"pid": 1234}, "tags": ["ssh"]}
    )

    with pytest.raises(TypeError):
        hypothesis.attributes["process"]["pid"] = 9999

    with pytest.raises(AttributeError):
        hypothesis.attributes["tags"].append("modified")


def test_non_json_attribute_values_are_rejected():
    with pytest.raises(ModelValidationError):
        make_hypothesis(attributes={"value": float("nan")})

    with pytest.raises(ModelValidationError):
        make_hypothesis(attributes={"value": {1, 2, 3}})


def test_hypothesis_serialization_preserves_derivation():
    result = make_hypothesis().to_dict()

    assert result["inference_rule_id"] == "auth-success"
    assert result["inference_rule_version"] == "1.0"
    assert result["input_observation_ids"] == [
        "obs-001",
        "obs-002",
    ]
    assert result["supporting_observation_ids"] == ["obs-001"]
    assert result["coverage_ids"] == ["coverage-001"]
    assert result["observation_assessment_ids"] == ["assessment-001"]
    assert result["review_status"] == "not_reviewed"


def test_serialized_attributes_do_not_mutate_hypothesis():
    hypothesis = make_hypothesis()
    result = hypothesis.to_dict()

    result["attributes"]["user"] = "mallory"

    assert hypothesis.attributes["user"] == "alice"

def test_correlated_observation_ids_are_serialized_separately():
    hypothesis = make_hypothesis(
        correlated_observation_ids=("obs-002",)
    )
    assert hypothesis.supporting_observation_ids == ("obs-001",)
    assert hypothesis.correlated_observation_ids == ("obs-002",)
    assert hypothesis.to_dict()["correlated_observation_ids"] == ["obs-002"]

def test_correlated_observation_ids_must_belong_to_hypothesis_inputs():
    with pytest.raises(ModelValidationError):
        make_hypothesis(
            correlated_observation_ids=("obs-not-in-inputs",)
        )

def test_correlated_observations_cannot_also_be_direct_support():
    with pytest.raises(ModelValidationError):
        make_hypothesis(correlated_observation_ids=("obs-001",))
