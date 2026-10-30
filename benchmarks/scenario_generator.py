
"""Deterministic synthetic scenario generation for TRACEE research."""

from __future__ import annotations

import hashlib
import random
from datetime import datetime, timedelta, timezone

from tracee.coverage import (
    CoverageInterval,
    CoverageStatus,
    ObservationAssessment,
    ObservationAvailability,
    SourceCoverage,
)
from tracee.events import (
    ParseStatus,
    SourceObservation,
    TemporalExtent,
    TimestampInfo,
    TimestampPrecision,
    TimezoneStatus,
)
from tracee.models import ModelValidationError

from .models import (
    BenchmarkInput,
    GeneratedScenario,
    GroundTruthEvent,
    ScenarioFamily,
    ScenarioGroundTruth,
)


UTC = timezone.utc
EVIDENCE_ID = "TRACE-EV-000001"
FAMILIES = tuple(ScenarioFamily)


def _instant(hour: int, minute: int = 0) -> datetime:
    return datetime(2026, 10, 2, hour, minute, tzinfo=UTC)


NEGATIVE_CONTROL_PROFILE_IDS = (
    "NEG-CTRL-01",
    "NEG-CTRL-02",
    "NEG-CTRL-03",
)


def _extent(start: datetime, end: datetime | None = None) -> TemporalExtent:
    return TemporalExtent(start, end if end is not None else start)


def _observation(
    scenario_id: str,
    suffix: str,
    *,
    user: str,
    host: str,
    when: datetime,
    source_type: str = "linux_auth",
    extra_attributes: dict | None = None,
) -> SourceObservation:
    attributes = {
        "user": user,
        "host": host,
    }
    if extra_attributes:
        attributes.update(extra_attributes)

    return SourceObservation(
        observation_id=f"{scenario_id}-obs-{suffix}",
        evidence_id=EVIDENCE_ID,
        source_type=source_type,
        source_locator=f"synthetic://{scenario_id}/{suffix}",
        parser_name="synthetic_benchmark_parser",
        parser_version="1.0",
        timestamp=TimestampInfo(
            raw_value=when.isoformat().replace("+00:00", "Z"),
            raw_format="ISO-8601",
            timezone_status=TimezoneStatus.KNOWN,
            precision=TimestampPrecision.MINUTE,
            normalized_extent=_extent(when),
        ),
        attributes=attributes,
        parse_status=ParseStatus.PARSED,
    )


def _coverage(
    scenario_id: str,
    status: CoverageStatus,
    expected_time: datetime,
) -> SourceCoverage:
    if status == CoverageStatus.KNOWN_COVERAGE:
        intervals = (
            CoverageInterval(_instant(0), _instant(23, 59)),
        )
        basis = "Synthetic source available for the complete test period"
    elif status == CoverageStatus.PARTIAL_COVERAGE:
        # Coverage ends before the target event.
        intervals = (
            CoverageInterval(
                _instant(0),
                expected_time - timedelta(minutes=1),
            ),
        )
        basis = "Synthetic source has a documented coverage gap"
    else:
        intervals = ()
        basis = (
            "Synthetic source coverage is unknown"
            if status == CoverageStatus.COVERAGE_UNKNOWN
            else "Synthetic source is unavailable"
        )

    return SourceCoverage(
        coverage_id=f"{scenario_id}-coverage-auth",
        evidence_id=EVIDENCE_ID,
        source_type="linux_auth",
        source_locator="/synthetic/auth.log",
        status=status,
        intervals=intervals,
        basis=basis,
        limitations=("Synthetic benchmark data; not real forensic evidence.",),
    )


def _assessment(
    scenario_id: str,
    coverage: SourceCoverage,
    expected_time: datetime,
    *,
    availability: ObservationAvailability,
    user: str,
    host: str,
    found_ids: tuple[str, ...] = (),
    expected_artifact_type: str = "authentication_record",
    supporting_indicator_ids: tuple[str, ...] = (),
    expected_end: datetime | None = None,
) -> ObservationAssessment:
    return ObservationAssessment(
        assessment_id=f"{scenario_id}-assessment-auth",
        expected_artifact_type=expected_artifact_type,
        coverage_id=coverage.coverage_id,
        expected_extent=_extent(expected_time, expected_end),
        availability=availability,
        scope_attributes={"user": user, "host": host},
        found_observation_ids=found_ids,
        supporting_indicator_observation_ids=supporting_indicator_ids,
        explanation="Generated from a deterministic synthetic scenario.",
    )


def _truth_event(
    scenario_id: str,
    suffix: str,
    *,
    user: str,
    host: str,
    when: datetime,
    expected_record_ids: tuple[str, ...],
    expected_interpretation_state: str | None,
) -> GroundTruthEvent:
    return GroundTruthEvent(
        event_id=f"{scenario_id}-truth-{suffix}",
        event_type="authentication_success",
        entity_attributes={"user": user, "host": host},
        temporal_extent=_extent(when),
        expected_record_ids=expected_record_ids,
        expected_interpretation_state=expected_interpretation_state,
    )


def _assemble(
    *,
    scenario_id: str,
    seed: int,
    family: ScenarioFamily,
    observations: tuple[SourceObservation, ...],
    coverage_records: tuple[SourceCoverage, ...],
    assessments: tuple[ObservationAssessment, ...],
    events: tuple[GroundTruthEvent, ...],
    omitted_record_ids: tuple[str, ...] = (),
    ambiguous: bool = False,
    event_matching_eligible: bool = True,
    conditions: tuple[str, ...] = (),
    profile_id: str | None = None,
) -> GeneratedScenario:
    method_input = BenchmarkInput(
        scenario_id=scenario_id,
        observations=observations,
        coverage_records=coverage_records,
        observation_assessments=assessments,
    )

    ground_truth = ScenarioGroundTruth(
        scenario_id=scenario_id,
        seed=seed,
        family=family,
        events=events,
        omitted_record_ids=omitted_record_ids,
        ambiguous=ambiguous,
        event_matching_eligible=event_matching_eligible,
        conditions=conditions,
        profile_id=profile_id,
    )

    return GeneratedScenario(
        method_input=method_input,
        ground_truth=ground_truth,
    )


def generate_scenario(
    seed: int,
    family: ScenarioFamily,
    *,
    profile_id: str | None = None,
) -> GeneratedScenario:
    """Generate one scenario with separate observable and hidden data."""

    if not isinstance(seed, int) or isinstance(seed, bool) or seed < 0:
        raise ModelValidationError(
            "seed must be a non-negative integer"
        )
    if not isinstance(family, ScenarioFamily):
        raise ModelValidationError(
            "family must be a ScenarioFamily value"
        )
    if profile_id is not None and (
        not isinstance(profile_id, str) or not profile_id.strip()
    ):
        raise ModelValidationError(
            "profile_id must be a non-empty string or None"
        )
    if profile_id not in (None, "DEV-COMP-02") + NEGATIVE_CONTROL_PROFILE_IDS:
        raise ModelValidationError(
            f"Unsupported development profile: {profile_id!r}"
        )
    if profile_id == "DEV-COMP-02" and (
        family is not ScenarioFamily.COMPLETE_RECORDS
    ):
        raise ModelValidationError(
            "DEV-COMP-02 requires the complete_records family"
        )

    if (
        profile_id in NEGATIVE_CONTROL_PROFILE_IDS
        and family is not ScenarioFamily.NEGATIVE_CONTROL
    ):
        raise ModelValidationError(
            f"{profile_id} requires the negative_control family"
        )

    rng = random.Random(seed)
    scenario_key = f"tracee-benchmark-v1:{seed}:{family.value}"
    if profile_id is not None:
        scenario_key += f":profile:{profile_id}"
    scenario_id = "scenario-" + hashlib.sha256(
        scenario_key.encode("utf-8")
    ).hexdigest()
    user = rng.choice(("alice", "bob", "carol"))
    host = f"host-{rng.randint(1, 4):02d}"
    when = _instant(rng.randint(1, 3), rng.choice((0, 5, 10)))
    expected_id = f"{scenario_id}-expected-auth-record"

    if profile_id == "DEV-COMP-02":
        session_a = f"{scenario_id}-session-a"
        session_b = f"{scenario_id}-session-b"
        t_auth_a = when
        t_auth_b = when + timedelta(minutes=2)
        t_process = when + timedelta(minutes=3)
        t_session_b = when + timedelta(minutes=4)
        t_session_a = when + timedelta(minutes=5)

        auth_a = _observation(
            scenario_id, "001",
            user=user, host=host, when=t_auth_a,
            extra_attributes={
                "action": "authentication_success",
                "session_id": session_a,
            },
        )
        auth_b = _observation(
            scenario_id, "002",
            user=user, host=host, when=t_auth_b,
            extra_attributes={
                "action": "authentication_success",
                "session_id": session_b,
            },
        )
        unrelated = _observation(
            scenario_id, "003",
            user=user, host=host, when=t_process,
            source_type="process_audit",
            extra_attributes={
                "action": "process_execution",
                "process_name": "system-indexer",
            },
        )
        endpoint_b = _observation(
            scenario_id, "004",
            user=user, host=host, when=t_session_b,
            source_type="endpoint_audit",
            extra_attributes={
                "action": "session_created",
                "session_id": session_b,
            },
        )
        endpoint_a = _observation(
            scenario_id, "005",
            user=user, host=host, when=t_session_a,
            source_type="endpoint_audit",
            extra_attributes={
                "action": "session_created",
                "session_id": session_a,
            },
        )

        coverage = _coverage(
            scenario_id, CoverageStatus.KNOWN_COVERAGE, when
        )
        assessment_a = _assessment(
            scenario_id + "-session-a",
            coverage, t_auth_a,
            availability=ObservationAvailability.OBSERVED,
            user=user, host=host,
            found_ids=(auth_a.observation_id,),
            expected_end=t_session_a,
        )
        assessment_b = _assessment(
            scenario_id + "-session-b",
            coverage, t_auth_b,
            availability=ObservationAvailability.OBSERVED,
            user=user, host=host,
            found_ids=(auth_b.observation_id,),
            expected_end=t_session_b,
        )

        truth_a = _truth_event(
            scenario_id, "session-a",
            user=user, host=host, when=t_auth_a,
            expected_record_ids=(
                auth_a.observation_id,
                endpoint_a.observation_id,
            ),
            expected_interpretation_state="corroborated",
        )
        truth_b = _truth_event(
            scenario_id, "session-b",
            user=user, host=host, when=t_auth_b,
            expected_record_ids=(
                auth_b.observation_id,
                endpoint_b.observation_id,
            ),
            expected_interpretation_state="corroborated",
        )

        # Deliberately interleaved order. Both authentication records share
        # user/host and fall inside the engine's default candidate window.
        return _assemble(
            scenario_id=scenario_id,
            seed=seed,
            family=family,
            observations=(
                auth_a, auth_b, unrelated, endpoint_b, endpoint_a,
            ),
            coverage_records=(coverage,),
            assessments=(assessment_a, assessment_b),
            events=(truth_a, truth_b),
            conditions=(
                "Development profile DEV-COMP-02.",
                "Two identifiable authentication-success events share "
                "user and host but have distinct session identifiers.",
                "An unrelated process observation is interleaved.",
                "Session creation records arrive in the opposite order "
                "to their authentication records.",
                "Authentication timestamps are separated beyond "
                "the event-matching tolerance but remain inside the "
                "candidate grouping window.",
            ),
            profile_id=profile_id,
        )

    if family == ScenarioFamily.COMPLETE_RECORDS:
        session_id = f"session-{scenario_id}"
        obs1 = _observation(
            scenario_id, "001",
            user=user, host=host, when=when,
            extra_attributes={
                "action": "authentication_success",
                "session_id": session_id,
            },
        )
        obs2 = _observation(
            scenario_id, "002",
            user=user, host=host,
            when=when + timedelta(minutes=1),
            source_type="endpoint_audit",
            extra_attributes={
                "action": "session_created",
                "session_id": session_id,
            },
        )
        cov = _coverage(
            scenario_id, CoverageStatus.KNOWN_COVERAGE, when
        )
        assessment = _assessment(
            scenario_id, cov, when,
            availability=ObservationAvailability.OBSERVED,
            user=user, host=host,
            found_ids=(obs1.observation_id,),
            expected_end=when + timedelta(minutes=1),
        )
        truth = _truth_event(
            scenario_id, "001",
            user=user, host=host, when=when,
            expected_record_ids=(
                obs1.observation_id, obs2.observation_id,
            ),
            expected_interpretation_state="corroborated",
        )
        return _assemble(
            scenario_id=scenario_id, seed=seed, family=family,
            observations=(obs1, obs2),
            coverage_records=(cov,), assessments=(assessment,),
            events=(truth,),
        )

    if family == ScenarioFamily.MISSING_RECORD:
        session_id = f"session-{scenario_id}"
        obs = _observation(
            scenario_id, "001",
            user=user, host=host,
            when=when + timedelta(minutes=1),
            source_type="endpoint_audit",
            extra_attributes={
                "action": "session_created",
                "session_id": session_id,
            },
        )
        cov = _coverage(
            scenario_id, CoverageStatus.KNOWN_COVERAGE, when
        )
        assessment = _assessment(
            scenario_id, cov, when,
            availability=(
                ObservationAvailability.NOT_OBSERVED_WITH_KNOWN_COVERAGE
            ),
            user=user, host=host,
            expected_end=when + timedelta(minutes=1),
        )
        truth = _truth_event(
            scenario_id, "001",
            user=user, host=host, when=when,
            expected_record_ids=(expected_id, obs.observation_id),
            expected_interpretation_state="challenged",
        )
        return _assemble(
            scenario_id=scenario_id, seed=seed, family=family,
            observations=(obs,),
            coverage_records=(cov,), assessments=(assessment,),
            events=(truth,),
            omitted_record_ids=(expected_id,),
            conditions=("One expected authentication record was omitted.",),
        )

    if family == ScenarioFamily.LOGGING_DISABLED:
        obs = _observation(
            scenario_id, "001",
            user=user, host=host, when=when,
            source_type="endpoint_audit",
            extra_attributes={"action": "session_activity"},
        )
        cov = _coverage(
            scenario_id, CoverageStatus.PARTIAL_COVERAGE, when
        )
        assessment = _assessment(
            scenario_id, cov, when,
            availability=(
                ObservationAvailability.NOT_OBSERVED_WITH_UNKNOWN_COVERAGE
            ),
            user=user, host=host,
        )
        truth = _truth_event(
            scenario_id, "001",
            user=user, host=host, when=when,
            expected_record_ids=(expected_id, obs.observation_id),
            expected_interpretation_state="underdetermined",
        )
        return _assemble(
            scenario_id=scenario_id, seed=seed, family=family,
            observations=(obs,),
            coverage_records=(cov,), assessments=(assessment,),
            events=(truth,),
            omitted_record_ids=(expected_id,),
            conditions=(
                "Authentication logging was disabled during the event.",
                "A separate endpoint record remains available.",
            ),
        )

    if family == ScenarioFamily.CONFLICTING_TIMESTAMPS:
        auth = _observation(
            scenario_id, "001",
            user=user, host=host, when=when,
            extra_attributes={"action": "authentication_success"},
        )
        offset_record = _observation(
            scenario_id, "002",
            user=user, host=host,
            when=when + timedelta(minutes=45),
            source_type="endpoint_audit",
            extra_attributes={"action": "authentication_success"},
        )
        cov = _coverage(
            scenario_id, CoverageStatus.KNOWN_COVERAGE, when
        )
        assessment = _assessment(
            scenario_id, cov, when,
            availability=ObservationAvailability.OBSERVED,
            user=user, host=host,
            found_ids=(auth.observation_id,),
        )
        truth = _truth_event(
            scenario_id, "001",
            user=user, host=host, when=when,
            expected_record_ids=(
                auth.observation_id, offset_record.observation_id,
            ),
            expected_interpretation_state=None,
        )
        return _assemble(
            scenario_id=scenario_id, seed=seed, family=family,
            observations=(auth, offset_record),
            coverage_records=(cov,), assessments=(assessment,),
            events=(truth,),
            ambiguous=True,
            event_matching_eligible=False,
            conditions=(
                "The endpoint record timestamp is offset by 45 minutes.",
                "The reconstruction input does not include the hidden offset.",
            ),
        )

    if family == ScenarioFamily.MULTIPLE_ENTITIES:
        users = rng.sample(("alice", "bob", "carol"), 2)
        observations: list[SourceObservation] = []
        events: list[GroundTruthEvent] = []
        assessments: list[ObservationAssessment] = []
        cov = _coverage(
            scenario_id, CoverageStatus.KNOWN_COVERAGE, when
        )

        for index, entity_user in enumerate(users, start=1):
            suffix = f"{index:03d}"
            event_time = when + timedelta(minutes=index - 1)
            entity_host = f"host-{index:02d}"
            obs = _observation(
                scenario_id, suffix,
                user=entity_user, host=entity_host, when=event_time,
                extra_attributes={"action": "authentication_success"},
            )
            observations.append(obs)
            events.append(
                _truth_event(
                    scenario_id, suffix,
                    user=entity_user, host=entity_host,
                    when=event_time,
                    expected_record_ids=(obs.observation_id,),
                    expected_interpretation_state="corroborated",
                )
            )
            assessments.append(
                _assessment(
                    scenario_id + f"-{index}",
                    cov, event_time,
                    availability=ObservationAvailability.OBSERVED,
                    user=entity_user, host=entity_host,
                    found_ids=(obs.observation_id,),
                )
            )

        return _assemble(
            scenario_id=scenario_id, seed=seed, family=family,
            observations=tuple(observations),
            coverage_records=(cov,),
            assessments=tuple(assessments),
            events=tuple(events),
        )

    if family == ScenarioFamily.AMBIGUOUS_EVIDENCE:
        obs = _observation(
            scenario_id, "001",
            user=user, host=host, when=when,
            source_type="process_audit",
            extra_attributes={"action": "session_activity"},
        )
        cov = _coverage(
            scenario_id, CoverageStatus.COVERAGE_UNKNOWN, when
        )
        assessment = _assessment(
            scenario_id, cov, when,
            availability=(
                ObservationAvailability.NOT_OBSERVED_WITH_UNKNOWN_COVERAGE
            ),
            user=user, host=host,
        )
        truth = _truth_event(
            scenario_id, "001",
            user=user, host=host, when=when,
            expected_record_ids=(expected_id,),
            expected_interpretation_state="underdetermined",
        )
        return _assemble(
            scenario_id=scenario_id, seed=seed, family=family,
            observations=(obs,),
            coverage_records=(cov,), assessments=(assessment,),
            events=(truth,),
            omitted_record_ids=(expected_id,),
            ambiguous=True,
            conditions=(
                "The available record is compatible with multiple explanations.",
                "The missing authentication record cannot resolve the alternatives.",
            ),
        )

    if family == ScenarioFamily.NEGATIVE_CONTROL:
        failure_attributes = {"action": "authentication_failure"}
        conditions = (
            "No authentication-success event occurred.",
            "An explicit authentication-failure record is present.",
            "Authentication-log coverage is documented for the period.",
        )

        if profile_id is None:
            # Preserve the original baseline scenario.
            obs = _observation(
                scenario_id, "001",
                user=user, host=host, when=when,
                source_type="linux_auth",
                extra_attributes=failure_attributes,
            )
            observations = (obs,)
        else:
            failed_session_id = f"{scenario_id}-failed-auth-session"
            failure_attributes["session_id"] = failed_session_id

            endpoint_user = user
            endpoint_when = when + timedelta(minutes=1)
            endpoint_session_id = f"{scenario_id}-endpoint-session"

            if profile_id == "NEG-CTRL-01":
                # Same user and host, but a distinct endpoint session.
                profile_conditions = (
                    "A failed login and a separate endpoint session "
                    "occur close together.",
                    "The endpoint session has a distinct session identifier.",
                )

            elif profile_id == "NEG-CTRL-02":
                # Similar timing and host, but a different user.
                endpoint_user = next(
                    candidate
                    for candidate in ("alice", "bob", "carol")
                    if candidate != user
                )
                profile_conditions = (
                    "The failed authentication and endpoint activity "
                    "refer to different users.",
                    "The endpoint activity occurs close to the failed "
                    "authentication in time.",
                )

            else:
                # Shared identifier, but deliberately beyond five minutes.
                endpoint_session_id = failed_session_id
                endpoint_when = when + timedelta(minutes=10)
                profile_conditions = (
                    "The failed authentication and endpoint activity "
                    "share a session identifier.",
                    "The endpoint activity occurs outside a 300-second "
                    "correlation window.",
                )

            obs = _observation(
                scenario_id, "001",
                user=user, host=host, when=when,
                source_type="linux_auth",
                extra_attributes=failure_attributes,
            )
            endpoint = _observation(
                scenario_id, "002",
                user=endpoint_user,
                host=host,
                when=endpoint_when,
                source_type="endpoint_audit",
                extra_attributes={
                    "action": "session_created",
                    "session_id": endpoint_session_id,
                },
            )
            observations = (obs, endpoint)
            conditions = conditions + profile_conditions

        cov = _coverage(
            scenario_id, CoverageStatus.KNOWN_COVERAGE, when
        )
        assessment = _assessment(
            scenario_id, cov, when,
            availability=(
                ObservationAvailability.NOT_OBSERVED_WITH_KNOWN_COVERAGE
            ),
            user=user, host=host,
            expected_artifact_type="authentication_success_record",
            supporting_indicator_ids=(obs.observation_id,),
        )
        return _assemble(
            scenario_id=scenario_id, seed=seed, family=family,
            observations=observations,
            coverage_records=(cov,),
            assessments=(assessment,),
            events=(),
            conditions=conditions,
            profile_id=profile_id,
        )
    raise ModelValidationError(f"Unsupported scenario family: {family!r}")


def generate_dataset(
    seed: int,
    scenarios_per_family: int = 1,
    *,
    include_negative_control_profiles: bool = False,
) -> tuple[GeneratedScenario, ...]:
    """Generate a deterministic dataset, optionally adding exploratory profiles."""

    if not isinstance(seed, int) or isinstance(seed, bool) or seed < 0:
        raise ModelValidationError(
            "seed must be a non-negative integer"
        )
    if (
        not isinstance(scenarios_per_family, int)
        or isinstance(scenarios_per_family, bool)
        or scenarios_per_family < 1
    ):
        raise ModelValidationError(
            "scenarios_per_family must be a positive integer"
        )
    if not isinstance(include_negative_control_profiles, bool):
        raise ModelValidationError(
            "include_negative_control_profiles must be a boolean"
        )

    scenarios = []
    negative_control_seeds = []
    index = 0

    # Preserve the original baseline generation order and seed assignment.
    for family in FAMILIES:
        for _ in range(scenarios_per_family):
            scenario_seed = seed + index * 1009
            scenarios.append(generate_scenario(scenario_seed, family))
            if family is ScenarioFamily.NEGATIVE_CONTROL:
                negative_control_seeds.append(scenario_seed)
            index += 1

    # Exploratory profiles are appended after all baseline scenarios so
    # enabling them cannot change baseline scenario IDs, seeds, or ordering.
    if include_negative_control_profiles:
        for scenario_seed in negative_control_seeds:
            for profile_id in NEGATIVE_CONTROL_PROFILE_IDS:
                scenarios.append(
                    generate_scenario(
                        scenario_seed,
                        ScenarioFamily.NEGATIVE_CONTROL,
                        profile_id=profile_id,
                    )
                )

    return tuple(scenarios)
