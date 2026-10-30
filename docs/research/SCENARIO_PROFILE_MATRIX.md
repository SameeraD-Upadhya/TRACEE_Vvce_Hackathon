# TRACEE Scenario Profile Matrix

**Status:** Partially implemented draft; not frozen. DEV-COMP-02 and the opt-in NEG-CTRL-01, NEG-CTRL-02, and NEG-CTRL-03 profiles are implemented. All other matrix profiles remain design-only.

This document proposes structurally different profiles for development
and held-out evaluation. Profile names are evaluator-side metadata and
must not be exposed to reconstruction methods.

## 1. Separation of evaluation tasks

The benchmark must distinguish two questions:

1. **Event reconstruction:** Does the supplied evidence identify an event
   that can validly be matched against an independently specified
   historical event?
2. **Evidence interpretation:** Given an evidence case, does the method
   correctly characterize the support, counterevidence, and uncertainty?

An event that occurred in the simulator is not automatically identifiable
from the observations. A hidden historical event must not be used as an
event-matching target merely because the generator knows it occurred.

The existing event evaluator matches predictions to hidden ground truth
by event type, identity, and time. It is not yet a separate evaluator for
evidence-interpretation cases. Do not claim interpretation-state accuracy
for unidentifiable events until that evaluation task is implemented and
validated independently.

## 2. Development profiles

These profiles may be used to implement and debug the generator and rules.

| Profile ID | Family | Observable structure | Intended label or truth | Primary event matching |
|---|---|---|---|---|
| DEV-COMP-01 | Complete records | One explicit authentication-success record and one endpoint session record with the same explicit session identifier | Corroborated event | Eligible |
| DEV-COMP-02 | Complete records | Two sessions for the same user and host, interleaved with unrelated activity; each target event has its own direct success record and session identifier | Corroborated per directly observed event | Eligible |
| DEV-MISS-01 | Missing record | Endpoint session creation, no authentication record, documented coverage over the complete expected extent | Challenged evidence hypothesis; historical success is not established by the endpoint record alone | Diagnostic-only |
| DEV-OUTAGE-01 | Logging disabled | Endpoint session activity overlaps a documented authentication-source outage | Underdetermined unless other observations identify the event | Diagnostic-only |
| DEV-TIME-01 | Conflicting timestamps | Records disagree in time, with no observable offset calibration | No required single reconstructed history | Diagnostic-only |
| DEV-TIME-02 | Conflicting timestamps | Records disagree in time, with an explicit observable calibration record and bounded offset | Label according to whether the declared bounds uniquely support reconciliation | Eligible only if independently identifiable |
| DEV-ENTITY-01 | Multiple entities | Three or more entities with direct authentication records, shared hosts, overlapping times, and interleaved observations | Corroborated per directly observed event | Eligible |
| DEV-AMB-01 | Ambiguous evidence | Process or session activity is consistent with multiple possible explanations, including histories with and without authentication success | Underdetermined | Diagnostic-only |
| DEV-NEG-01 | Negative control | Authentication failure plus unrelated endpoint activity, with documented coverage and no target success | No target authentication-success event | Eligible |
| NEG-CTRL-01 | Negative control | Failed authentication plus endpoint session creation for the same user and host one minute later, with distinct session identifiers | No target authentication-success event; endpoint activity may yield an unconfirmed candidate | Eligible for target-event false-positive scoring |
| NEG-CTRL-02 | Negative control | Failed authentication for one user plus endpoint session creation for another user on the same host one minute later; identifiers differ | No target authentication-success event for the failed user's identity | Eligible for target-event false-positive scoring |
| NEG-CTRL-03 | Negative control | Failed authentication and endpoint session creation share user, host, and session ID but are ten minutes apart | No target authentication-success event; the endpoint-derived candidate remains unconfirmed | Eligible for target-event false-positive scoring; not an isolated test of temporal-gate rejection |

| DEV-INPUT-01 | Insufficient input | A required identity attribute is unavailable before the rule can evaluate the candidate | Insufficient input for the evidence-interpretation task | Separate interpretation evaluation required |

The NEG-CTRL profiles are opt-in via
`--include-negative-control-profiles` and do not alter the default dataset.
All three have no ground-truth authentication-success events, so candidate
predictions can count as false positives.

**Scope limitation:** NEG-CTRL-03 is an out-of-window distractor condition.
In the current implementation, its candidate is generated directly from
the endpoint session-creation observation and has no correlated observation
IDs. It does not independently establish that the temporal correlation gate
rejected a match.


## 3. Held-out structural profiles

Reserve these profiles before rule development is complete. Do not use their
results to change rules, thresholds, expected labels, or acceptance criteria.

| Profile ID | Family | Reserved structure | Intended scoring treatment |
|---|---|---|---|
| HOLD-COMP-01 | Complete records | Three sessions interleaved across two hosts, with variable event order and unrelated records; direct success records identify each target event | Event matching eligible |
| HOLD-MISS-01 | Missing record | Two candidate sessions for one identity, one with an endpoint record and one without; authentication record absent under documented coverage | Diagnostic-only unless independent evidence identifies the target event |
| HOLD-OUTAGE-01 | Logging disabled | Coverage gap begins and ends at different times relative to several endpoint events | Diagnostic-only unless target events are independently identifiable |
| HOLD-TIME-01 | Conflicting timestamps | A clock-offset calibration observation bounds the affected source's offset; reconciliation is scoreable only where those bounds justify it | Eligible only for identifiable event relationships |
| HOLD-ENTITY-01 | Multiple entities | Several users share a host and have overlapping events; distinct explicit session identifiers prevent identity leakage | Event matching eligible for directly identified events |
| HOLD-AMB-01 | Ambiguous evidence | Distractor process and session records fit multiple event histories; no direct authentication-success record resolves the alternatives | Diagnostic-only |
| HOLD-NEG-01 | Negative control | A failed authentication is followed by benign session activity and an unrelated user's successful authentication | Eligible for the absence of the target user's success event, with the evaluation window and coverage explicitly specified |
| HOLD-INPUT-01 | Insufficient input | A required observation cannot be parsed or is only partially parsed, while unrelated valid records remain | Separate interpretation evaluation required |

Held-out profiles are reserved designs, not proof of generalization by
themselves. Their actual observations, labels, and scoring rules must be
frozen before the confirmatory run.

## 4. Structural-diversity requirements

A new seed is not considered a new structural profile merely because user,
host, timestamp, or identifier values change.

For each generated scenario, the generator should be able to describe,
evaluator-side:
- Number and ordering of observations.
- Number of entities, sessions, and target events.
- Observation sources and source-coverage conditions.
- Supporting, unrelated, contradictory, omitted, and malformed records.
- Explicit correlation identifiers and whether they are shared or distinct.
- Temporal ordering, timestamp uncertainty, and calibration evidence.
- Historical ground truth separately from expected evidence interpretation.
- Event-matching eligibility and the reason for that eligibility.

Tests should assert meaningful differences between profiles, not just
different scenario identifiers.

## 5. Scoring boundaries

- Directly observed and identifiable target events can enter event matching
  under the frozen criteria.
- Negative controls can enter event matching when the time window,
  required coverage, and absence of a target event are explicit.
- A hidden event that is not identifiable from the observations must not
  enter primary event-matching scores.
- Diagnostic-only cases must remain visible in per-scenario outputs.
- Interpretation labels for such cases require an evidence-case evaluator
  that does not silently equate a matching hidden event with a justified
  interpretation.
- Zero scored interpretation comparisons means accuracy is undefined,
  represented as JSON null.
- Historical event detection, evidence interpretation, provenance
  completeness, and operational performance must be reported separately.

## 6. Implementation gate

Do not implement the held-out set as ordinary development templates.
Before the confirmatory experiment:
1. Review this matrix and the interpretation-label policy independently
   of new model outputs.
2. Implement profile generation and test structural variation.
3. Add an evidence-interpretation evaluator separate from event matching,
   where needed.
4. Verify that evaluator-only fields never enter method input.
5. Freeze the held-out profile definitions, scoring criteria, and run
   configuration.
6. Run the full test suite before generating new reports.

This matrix is a proposal. It makes no claim that the current generator,
adapter, or inference engine already supports all these profiles.
