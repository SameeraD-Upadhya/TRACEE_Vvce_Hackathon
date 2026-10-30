# TRACEE Interpretation-Label Policy

**Policy version:** 1.1 (draft amendment)
**Policy date:** 2026-10-13
**Purpose:** Define interpretation-state expectations for future
confirmatory synthetic benchmark runs.

## 1. Scope and limitation

An interpretation label describes how the available evidence supports
or challenges a candidate hypothesis. It does not, by itself, state
whether the underlying historical event actually occurred.

Event-matching eligibility is adjudicated separately. A hidden event
in the simulator is not sufficient reason to score a method on that
event if multiple materially different histories fit the supplied
evidence equally well.

This policy was drafted after exploratory benchmark runs had already
been inspected. Therefore, those runs are not confirmatory results under
a pre-declared policy. Apply this policy to future evaluations only
after freezing the scenario definitions, expected labels, scoring rules,
and seeds before running the methods being compared.

## 2. Label definitions

### corroborated

The required positive evidence is observed, relevant source coverage
and provenance are sufficient for the scenario's declared criteria, and
no material unresolved contradiction prevents the interpretation.

Corroboration is bounded by the evidence and criteria actually supplied.
It is not a claim of absolute certainty.

### challenged

There is some evidence supporting a candidate, but material
counterevidence conflicts with it.

For the current missing-record scenario, the expected authentication
artifact is not observed, the source reports known coverage over the
entire declared expected extent, and the rule explicitly treats that
absence as counterevidence. The candidate remains available for
investigation but must not be presented as a corroborated event.

The label does not mean the event was historically impossible. A
separate removal or tampering hypothesis would require supporting
evidence; it must not be assumed merely to excuse an absent record.

### underdetermined

The supplied evidence permits materially different interpretations
because key source coverage, temporal relationships, or corroborating
evidence is unknown or ambiguous. The available evidence is insufficient
to resolve the competing interpretations, and the declared criteria do
not justify treating the uncertainty as decisive counterevidence.

Unknown coverage must not be silently treated as known absence.

### insufficient_input

The available inputs do not satisfy the declared minimum requirements
for evaluating the candidate. Examples include unavailable required
attributes, a required input that cannot be parsed, or missing
investigation inputs needed to apply the rule.

Use this label only when the scenario's pre-declared criteria establish
that the input limitation prevents a meaningful interpretation. Do not
use it interchangeably with underdetermined or challenged.

The current scenario set does not yet independently exercise every
possible insufficient-input condition. Dedicated cases must be added
before claiming validated performance on this state.

## 3. Expected outcomes for current scenario families

| Scenario family | Observable condition | Expected interpretation | Event-matching treatment |
|---|---|---|---|
| complete_records | Explicit authentication-success observation and matching endpoint session creation with the declared shared session identifier; expected artifact observed | corroborated | Eligible |
| missing_record | Endpoint session creation is observed; expected authentication record is absent under documented coverage | challenged | Diagnostic-only with current observables; eligible for event matching only if independent observable evidence identifies the successful-authentication event |
| logging_disabled | Endpoint activity remains, but authentication evidence is unavailable or coverage is unknown | underdetermined | Diagnostic-only unless separate observable evidence makes the target event identifiable |
| ambiguous_evidence | Indirect activity exists, but the evidence and coverage do not resolve whether authentication succeeded | underdetermined | Diagnostic-only when multiple event histories remain consistent with the supplied evidence |
| multiple_entities | Separate explicit authentication-success observations identify the corresponding entities and events | corroborated per event | Eligible |
| conflicting_timestamps | Records have conflicting times, and no observable clock-offset evidence establishes reconciliation | no expected interpretation state | Diagnostic-only unless the scenario and scoring policy are redesigned |
| negative_control | The supplied records do not establish a target authentication-success event | no target event | Any target-event prediction counts as a false positive |

The table specifies intended expectations for the current synthetic
templates. It is not evidence that real-world artifacts always justify
these labels. Scenario-specific assumptions and source-coverage claims
must be stated explicitly in the generated data and evaluation
documentation.

## 4. Adjudication rules

1. Define observable facts, hidden event truth, source coverage, expected
   artifacts, and expected interpretation separately.
2. Assign the expected state from the observable evidence and this policy,
   not from the state produced by TRACEE or a baseline.
3. Keep event matching separate from interpretation-state scoring.
4. Do not score an interpretation state when the expected state is
   unspecified or when no valid prediction-to-truth match exists.
5. Represent accuracy as undefined when zero state comparisons were
   evaluated. Do not report this case as zero accuracy.
6. Record unmatched and unscored ground-truth events separately.
7. Treat unsupported clock reconciliation, assumed tampering, and
   inferred source coverage as unresolved assumptions, not observed facts.
8. Do not revise expected labels after examining results to improve a
   method's score. Any justified policy change requires a new version and
   a new evaluation run.

## 5. Status of existing results

The reports generated before this policy was documented remain
exploratory. In particular, the missing-record expected state was changed
during implementation development after TRACEE's output was inspected.

The current scores must not be represented as independent confirmation
of interpretation-state correctness under this policy.

## 6. Requirements before the next confirmatory run

- Review and approve this policy independently of model outputs.
- Audit every generated scenario against the policy.
- Add structurally diverse scenarios and dedicated input-insufficiency
  cases.
- Declare seeds, scenario counts, time tolerance, unknown-time handling,
  and definitive-state rules before running methods.
- Keep held-out scenarios separate from scenarios used to develop rules.
- Preserve per-seed, per-family, and failure-case reports.
- Do not treat repeated instances of the same template as independent
  real-world incidents.

Passing these requirements improves experimental defensibility. It does
not by itself establish research novelty or real-world forensic accuracy.
