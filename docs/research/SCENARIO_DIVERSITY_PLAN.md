# TRACEE Scenario Diversity and Held-Out Evaluation Plan

**Status:** Design draft; not yet implemented or approved.

## 1. Objective

Expand the synthetic forensic benchmark so that different random seeds
produce meaningfully different evidence structures, not merely different
users, hosts, timestamps, and identifiers.

Expected interpretation labels must follow
`docs/research/INTERPRETATION_LABEL_POLICY.md`. Labels must not be changed
to improve a method's results.

## 2. Scenario variation matrix

| Scenario family | Structural variations to implement | Expected interpretation principle |
|---|---|---|
| Complete records | Vary the number and order of observations, event delays, source combinations, irrelevant records, and interleaved sessions. Include repeated activity by the same user on the same host. | Corroborated only when the declared supporting evidence and identity relationships justify it. |
| Missing record | Include multiple sessions for one identity, unrelated authentication records, nearby events, and session identifiers that distinguish relevant from irrelevant records. | Challenged when a record is absent under documented coverage and the policy declares that absence material counterevidence. |
| Logging disabled | Separate a documented logging outage from partial coverage and completely unknown coverage. Vary the duration and timing of the coverage gap. | Underdetermined when the missing record cannot distinguish event absence from unavailable logging. |
| Conflicting timestamps | Separate unresolved clock disagreement from cases with observable calibration data or a bounded offset. Vary which source is affected and whether the available bounds permit reconciliation. | Do not require merging events without observable justification. Keep unresolved cases diagnostic-only unless their truth and scoring are identifiable. |
| Multiple entities | Vary the number of entities, overlapping event times, shared hosts, repeated sessions, and distinct session identifiers. Interleave observations rather than grouping them by entity. | Corroborated per event only when the observations support that event and identity. |
| Ambiguous evidence | Include distractors, pre-existing session activity, incomplete event sequences, and different hypotheses consistent with the same observations. | Underdetermined when the observable evidence cannot resolve the competing explanations. |
| Negative control | Include authentication failure alone, unrelated endpoint activity, benign activity near a failure, and successful authentication belonging to a different identity or session. | No target event where the supplied scenario truth contains no target authentication success. Any predicted target event counts as a false positive. |
| Insufficient input | Add separate cases with missing required identity attributes, failed or partial parsing, and unavailable minimum inputs. Vary which required input is missing. | Insufficient input only when the pre-declared requirements prevent meaningful interpretation. |

These are design requirements, not claims that every variation is already
supported by the current generator or inference engine.

## 3. Separate scenario structure from random values

The generator should explicitly select a scenario profile containing the
structure of the evidence case. Random values may then populate that profile.

A profile should define:
- The underlying event history.
- The observable records and their sources.
- Missing, contradictory, irrelevant, and supporting records.
- Source coverage and expected-artifact assessments.
- Timestamp uncertainty and any observable clock calibration.
- Ground-truth events and interpretation expectations.
- Whether event matching is eligible and why.

Changing a seed must not be treated as evidence of structural diversity
unless the resulting evidence relationships actually differ.

## 4. Development and held-out scenarios

Development scenarios may be used to improve rules and fix software.

Held-out scenarios must use structural profiles reserved before rule
development is complete. They must not be used to tune rules, choose
thresholds, or revise expected labels.

Using different seeds with the same scenario template is not, by itself,
a held-out evaluation.

The method receives only `BenchmarkInput`. Evaluator-only truth, scenario
conditions, expected labels, and reserved-profile metadata must remain
outside the method input.

## 5. Evaluation requirements

Before a confirmatory run:
1. Approve and freeze the interpretation-label policy.
2. Freeze the scenario profiles and expected labels independently of
   method predictions.
3. Freeze seeds, scenario counts, temporal tolerances, unknown-time
   handling, and definitive-state criteria.
4. Give all methods equivalent observable input for each scenario.
5. Keep unidentified cases out of primary event-matching metrics, with
   documented reasons and separate diagnostic outputs.
6. Report candidate matching, definitive detection, interpretation-state
   scoring, provenance checks, and family-level failures separately.
7. Represent interpretation-state accuracy as undefined when zero
   comparisons were scored, including in aggregate summaries.
8. Preserve raw per-scenario and per-seed results.
9. Do not describe synthetic benchmark results as real-world validation.

## 6. Acceptance criteria

The expanded generator is ready for a new evaluation only when:
- Tests verify structural differences between profile types.
- Expected labels are validated against the frozen policy.
- At least one dedicated insufficient-input case exists.
- Clock reconciliation requires observable calibration evidence.
- Negative controls cover materially different distractor patterns.
- Held-out structures are distinct from development structures.
- Repeated-seed runs and the held-out run can be reproduced.
- The full test suite passes.

Passing these criteria supports a more rigorous synthetic experiment.
It does not, by itself, establish research novelty or real-world forensic
accuracy.
