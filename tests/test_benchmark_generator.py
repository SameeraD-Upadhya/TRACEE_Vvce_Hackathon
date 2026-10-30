
"""Tests for TRACEE's reproducible synthetic benchmark."""

import pytest

from benchmarks.models import (
    BenchmarkInput,
    GeneratedScenario,
    ScenarioFamily,
)
from benchmarks.scenario_generator import (
    generate_dataset,
    generate_scenario,
)
from tracee.coverage import (
    CoverageStatus,
    ObservationAvailability,
)
from tracee.models import ModelValidationError


@pytest.mark.parametrize("family", list(ScenarioFamily))
def test_every_scenario_family_generates(family):
    scenario = generate_scenario(42, family)

    assert isinstance(scenario, GeneratedScenario)
    assert scenario.ground_truth.family is family
    assert scenario.method_input.scenario_id == scenario.ground_truth.scenario_id
    assert scenario.ground_truth.seed == 42
    assert not hasattr(scenario.method_input, "seed")
    assert family.value not in scenario.method_input.scenario_id
    assert scenario.method_input.observations


@pytest.mark.parametrize("family", list(ScenarioFamily))
def test_same_seed_and_family_produce_equal_scenarios(family):
    first = generate_scenario(42, family)
    second = generate_scenario(42, family)

    assert first == second


def test_scenario_ids_do_not_expose_family_names():
    for family in ScenarioFamily:
        scenario = generate_scenario(42, family)
        assert family.value not in scenario.method_input.scenario_id


def test_different_seeds_have_distinct_scenario_ids():
    first = generate_scenario(42, ScenarioFamily.COMPLETE_RECORDS)
    second = generate_scenario(43, ScenarioFamily.COMPLETE_RECORDS)

    assert first.method_input.scenario_id != second.method_input.scenario_id
    assert first.ground_truth.seed != second.ground_truth.seed


def test_dataset_generation_is_reproducible():
    first = generate_dataset(seed=100, scenarios_per_family=2)
    second = generate_dataset(seed=100, scenarios_per_family=2)

    assert first == second
    assert len(first) == len(ScenarioFamily) * 2


def test_dataset_contains_every_scenario_family():
    scenarios = generate_dataset(seed=100)

    families = tuple(
        scenario.ground_truth.family for scenario in scenarios
    )

    assert families == tuple(ScenarioFamily)


def test_method_input_does_not_expose_ground_truth_labels():
    scenario = generate_scenario(42, ScenarioFamily.MISSING_RECORD)
    method_input = scenario.method_input

    assert isinstance(method_input, BenchmarkInput)
    assert not hasattr(method_input, "ground_truth")
    assert not hasattr(method_input, "family")
    assert not hasattr(method_input, "omitted_record_ids")
    assert not hasattr(method_input, "ambiguous")


@pytest.mark.parametrize("family", list(ScenarioFamily))
def test_all_assessments_reference_supplied_records_and_coverage(family):
    scenario = generate_scenario(42, family)
    method_input = scenario.method_input

    observation_ids = {
        observation.observation_id
        for observation in method_input.observations
    }
    coverage_ids = {
        coverage.coverage_id
        for coverage in method_input.coverage_records
    }

    for assessment in method_input.observation_assessments:
        assert assessment.coverage_id in coverage_ids

        linked_ids = (
            set(assessment.found_observation_ids)
            | set(assessment.supporting_indicator_observation_ids)
        )
        assert linked_ids <= observation_ids


def test_all_observation_ids_are_unique_within_scenario():
    for family in ScenarioFamily:
        scenario = generate_scenario(42, family)
        ids = [
            item.observation_id
            for item in scenario.method_input.observations
        ]
        assert len(ids) == len(set(ids))


@pytest.mark.parametrize(
    ("family", "expected_state"),
    [
        (ScenarioFamily.COMPLETE_RECORDS, "corroborated"),
        (ScenarioFamily.MISSING_RECORD, "challenged"),
        (ScenarioFamily.LOGGING_DISABLED, "underdetermined"),
        (ScenarioFamily.MULTIPLE_ENTITIES, "corroborated"),
        (ScenarioFamily.AMBIGUOUS_EVIDENCE, "underdetermined"),
        (ScenarioFamily.CONFLICTING_TIMESTAMPS, None),
    ],
)
def test_generated_scenarios_declare_expected_interpretation(
    family, expected_state
):
    scenario = generate_scenario(42, family)

    assert scenario.ground_truth.events
    assert all(
        event.expected_interpretation_state == expected_state
        for event in scenario.ground_truth.events
    )


def test_missing_record_scenario_separates_omission_from_observations():
    scenario = generate_scenario(42, ScenarioFamily.MISSING_RECORD)

    assert any(
        item.attributes.get("action") == "session_created"
        for item in scenario.method_input.observations
    )
    observed_ids = {
        item.observation_id
        for item in scenario.method_input.observations
    }
    omitted_ids = set(scenario.ground_truth.omitted_record_ids)

    assert omitted_ids
    assert not (omitted_ids & observed_ids)

    assessment = scenario.method_input.observation_assessments[0]
    assert (
        assessment.availability
        == ObservationAvailability.NOT_OBSERVED_WITH_KNOWN_COVERAGE
    )


def test_logging_disabled_scenario_does_not_claim_full_coverage():
    scenario = generate_scenario(42, ScenarioFamily.LOGGING_DISABLED)

    assert scenario.ground_truth.omitted_record_ids
    assert any(
        "disabled" in condition.lower()
        for condition in scenario.ground_truth.conditions
    )
    assert scenario.method_input.coverage_records[0].status is (
        CoverageStatus.PARTIAL_COVERAGE
    )
    assert scenario.method_input.observation_assessments[0].availability is (
        ObservationAvailability.NOT_OBSERVED_WITH_UNKNOWN_COVERAGE
    )


def test_ambiguous_scenario_is_marked_only_in_ground_truth():
    scenario = generate_scenario(42, ScenarioFamily.AMBIGUOUS_EVIDENCE)

    assert scenario.ground_truth.ambiguous is True
    assert not hasattr(scenario.method_input, "ambiguous")
    assert scenario.method_input.coverage_records[0].status is (
        CoverageStatus.COVERAGE_UNKNOWN
    )
    assert scenario.method_input.observation_assessments[0].availability is (
        ObservationAvailability.NOT_OBSERVED_WITH_UNKNOWN_COVERAGE
    )


def test_negative_control_has_failure_record_and_known_coverage():
    scenario = generate_scenario(42, ScenarioFamily.NEGATIVE_CONTROL)
    method_input = scenario.method_input

    assert scenario.ground_truth.events == ()
    assert scenario.ground_truth.omitted_record_ids == ()

    failures = [
        item for item in method_input.observations
        if item.attributes.get("action") == "authentication_failure"
    ]
    assert len(failures) == 1
    assert failures[0].source_type == "linux_auth"
    assert all(
        item.attributes.get("action") != "authentication_success"
        for item in method_input.observations
    )

    assert method_input.coverage_records[0].status is (
        CoverageStatus.KNOWN_COVERAGE
    )
    assessment = method_input.observation_assessments[0]
    assert assessment.expected_artifact_type == "authentication_success_record"
    assert assessment.supporting_indicator_observation_ids == (
        failures[0].observation_id,
    )
    assert assessment.availability is (
        ObservationAvailability.NOT_OBSERVED_WITH_KNOWN_COVERAGE
    )

def test_multiple_entity_scenario_has_distinct_truth_entities():
    scenario = generate_scenario(42, ScenarioFamily.MULTIPLE_ENTITIES)

    assert len(scenario.ground_truth.events) == 2
    identities = {
        (
            event.entity_attributes["user"],
            event.entity_attributes["host"],
        )
        for event in scenario.ground_truth.events
    }
    assert len(identities) == 2


def test_conflicting_timestamp_scenario_documents_hidden_offset():
    scenario = generate_scenario(
        42, ScenarioFamily.CONFLICTING_TIMESTAMPS
    )

    assert scenario.ground_truth.ambiguous is True
    assert scenario.ground_truth.event_matching_eligible is False
    observations = scenario.method_input.observations
    assert len(observations) == 2
    assert {
        item.attributes["action"] for item in observations
    } == {"authentication_success"}
    timestamps = [
        item.timestamp.normalized_extent.earliest_utc
        for item in observations
    ]
    assert abs((timestamps[1] - timestamps[0]).total_seconds()) == 2700
    assert any(
        "45 minutes" in condition
        for condition in scenario.ground_truth.conditions
    )
    assert all(
        "45 minutes" not in str(observation.to_dict())
        for observation in scenario.method_input.observations
    )


@pytest.mark.parametrize("seed", [-1, True, 1.5, "42"])
def test_invalid_seed_is_rejected(seed):
    with pytest.raises(ModelValidationError):
        generate_scenario(seed, ScenarioFamily.COMPLETE_RECORDS)


def test_invalid_family_is_rejected():
    with pytest.raises(ModelValidationError):
        generate_scenario(42, "missing_record")


@pytest.mark.parametrize("count", [0, -1, True, 1.5])
def test_invalid_scenarios_per_family_is_rejected(count):
    with pytest.raises(ModelValidationError):
        generate_dataset(seed=42, scenarios_per_family=count)


def test_ground_truth_records_refer_to_known_or_omitted_ids():
    for family in ScenarioFamily:
        scenario = generate_scenario(42, family)

        declared = {
            record_id
            for event in scenario.ground_truth.events
            for record_id in event.expected_record_ids
        }
        omitted = set(scenario.ground_truth.omitted_record_ids)

        assert omitted <= declared


def test_complete_and_missing_scenarios_use_session_correlation_ids():
    complete = generate_scenario(42, ScenarioFamily.COMPLETE_RECORDS)
    complete_by_action = {
        item.attributes.get("action"): item
        for item in complete.method_input.observations
    }

    authentication = complete_by_action["authentication_success"]
    session = complete_by_action["session_created"]
    assert authentication.attributes.get("session_id")
    assert (
        authentication.attributes["session_id"]
        == session.attributes.get("session_id")
    )

    missing = generate_scenario(42, ScenarioFamily.MISSING_RECORD)
    missing_sessions = [
        item
        for item in missing.method_input.observations
        if item.attributes.get("action") == "session_created"
    ]
    assert len(missing_sessions) == 1
    assert missing_sessions[0].attributes.get("session_id")
    assert (
        missing.method_input.observation_assessments[0].availability
        == ObservationAvailability.NOT_OBSERVED_WITH_KNOWN_COVERAGE
    )


def test_dev_comp_02_has_interleaved_sessions_and_isolated_profile_metadata():
    scenario = generate_scenario(
        42,
        ScenarioFamily.COMPLETE_RECORDS,
        profile_id="DEV-COMP-02",
    )

    assert scenario.ground_truth.profile_id == "DEV-COMP-02"
    assert len(scenario.ground_truth.events) == 2
    assert scenario.ground_truth.event_matching_eligible is True

    method_input = scenario.method_input
    assert not hasattr(method_input, "profile_id")
    assert not hasattr(method_input, "family")
    assert not hasattr(method_input, "ground_truth")
    assert "DEV-COMP-02" not in method_input.scenario_id

    observations = method_input.observations
    actions = [item.attributes.get("action") for item in observations]
    assert actions == [
        "authentication_success",
        "authentication_success",
        "process_execution",
        "session_created",
        "session_created",
    ]

    by_id = {item.observation_id: item for item in observations}
    assert len(by_id) == 5

    event_sessions = set()
    for event in scenario.ground_truth.events:
        records = [by_id[item] for item in event.expected_record_ids]
        authentication = next(
            item for item in records
            if item.attributes.get("action") == "authentication_success"
        )
        endpoint = next(
            item for item in records
            if item.attributes.get("action") == "session_created"
        )

        assert authentication.attributes["session_id"] == (
            endpoint.attributes["session_id"]
        )
        event_sessions.add(authentication.attributes["session_id"])
        assert event.expected_interpretation_state == "corroborated"

    assert len(event_sessions) == 2

    # Existing default generation remains available and gets no development ID.
    legacy = generate_scenario(42, ScenarioFamily.COMPLETE_RECORDS)
    assert legacy.ground_truth.profile_id is None
    assert legacy.method_input.scenario_id != method_input.scenario_id


def test_unknown_or_wrong_family_profile_is_rejected():
    with pytest.raises(ModelValidationError):
        generate_scenario(
            42,
            ScenarioFamily.COMPLETE_RECORDS,
            profile_id="HOLD-COMP-01",
        )

    with pytest.raises(ModelValidationError):
        generate_scenario(
            42,
            ScenarioFamily.MISSING_RECORD,
            profile_id="DEV-COMP-02",
        )


def test_dev_comp_02_is_reproducible():
    first = generate_scenario(
        42, ScenarioFamily.COMPLETE_RECORDS, profile_id="DEV-COMP-02"
    )
    second = generate_scenario(
        42, ScenarioFamily.COMPLETE_RECORDS, profile_id="DEV-COMP-02"
    )
    assert first == second
