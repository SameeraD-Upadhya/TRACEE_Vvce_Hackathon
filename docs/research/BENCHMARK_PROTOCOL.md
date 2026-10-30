# TRACEE Reconstruction Benchmark Protocol

**Version:** 0.2
**Status:** Provisional experimental protocol
**Protocol origin branch:** `research/uncertainty-aware-reconstruction`
**Active benchmark branch:** `research/benchmark-generator`

## 1. Objective

Evaluate whether explicit source-coverage and missing-observation handling improves retrospective incident reconstruction compared with simpler reconstruction methods.

The benchmark must use known ground truth, reproducible scenario generation, and comparable inputs for each method.

The benchmark must not be used to claim real-world effectiveness without validation on suitable real forensic data.

## 2. Research question

When event records are incomplete or inconsistent, does TRACEE's reconstruction method reduce unsupported definitive conclusions while retaining useful reconstruction recall and appropriate evidence provenance?

## 3. Benchmark separation

Maintain separate representations for:

1. Hidden ground truth describing the events that actually occurred in each synthetic scenario.
2. Observable source records provided to each reconstruction method.
3. Source-coverage metadata and known collection conditions.
4. Reconstruction outputs.
5. Evaluation results calculated by comparing outputs with ground truth.

The reconstruction methods must never receive hidden ground-truth labels as input.

## 4. Initial scenario families

Generate reproducible scenarios covering:

- Complete source records.
- Individual missing records.
- Logging disabled during specified intervals.
- Partial source coverage.
- Unavailable sources.
- Unknown timestamps and timezone information.
- Clock offsets and conflicting timestamp observations.
- Duplicate and reordered records.
- Failed or unsupported parsing.
- Contradictory observations.
- Positive indicators of possible record removal.
- Multiple users or hosts with otherwise similar activities.
- Ambiguous cases in which available evidence cannot identify the underlying explanation.

Each scenario must record its generation seed and ground-truth metadata.

## 5. Baselines

### Baseline A — Chronology-only

Sort available observations by their available normalized timestamps. Do not assert causality based solely on adjacent or similar timestamps.

### Baseline B — Basic rule correlation

Apply documented event-matching rules to observable records without explicit source-coverage-aware missing-observation reasoning.

### Method C — TRACEE

Use the reconstruction engine, versioned inference rules, relevant source-coverage declarations, scoped artifact assessments, and explicit uncertainty states.

All methods must receive the same underlying observable records. Any additional metadata used by TRACEE must be documented as part of the method and reflected in the interpretation of results.

The baseline implementations must be sufficiently documented to be independently reproduced. They must not be represented as exact reproductions of published tools unless that equivalence has been established.

## 6. Ground-truth event model

For every scenario, record:

- Scenario identifier and random seed.
- Underlying event identifiers and event types.
- Relevant entity attributes.
- Actual event-time bounds where known.
- Source records that should be generated.
- Logging and collection conditions.
- Omission, duplication, corruption, or reordering operations applied.
- Whether the underlying event can be uniquely inferred from the resulting evidence.

Hidden labels must be stored separately from the records supplied to reconstruction methods.

## 7. Evaluation metrics

### Reconstruction precision, recall, and F1

Compare reconstructed event hypotheses with ground-truth events using pre-defined event-type, entity, and time-matching criteria.

Report precision, recall, and F1 for each scenario family and overall.

### Unsupported definitive-hypothesis rate

Measure the fraction of hypotheses marked as definitive under a predefined output-state mapping that do not match supported ground-truth events.

TRACEE's `CORROBORATED` state is not automatically a claim of absolute historical truth. Any mapping from the model's states to evaluation categories must be specified explicitly.

### Missing-observation classification

Measure whether the method correctly characterizes observable coverage and missingness conditions without receiving hidden labels.

### Appropriate abstention

Measure whether genuinely ambiguous cases remain unresolved rather than being assigned unsupported explanations.

### Provenance completeness

Check whether inferred events retain the required source references, rule version, supporting and contradictory observations, and relevant unresolved conditions.

### Reproducibility

Run identical inputs, rule versions, configuration, and program versions repeatedly. Verify that outputs are equivalent.

### Performance

Measure runtime and memory use for each method on comparable inputs and record the environment used.

## 8. Ablation experiments

Evaluate the effect of removing one feature at a time:

- Explicit source-coverage modeling.
- Artifact-persistence metadata, once specified and implemented.
- Contradiction tracking.
- Scoped observation assessments.
- Explicit derivation metadata.

Do not implement an ablation until the feature being removed has a defined behavior and an implemented equivalent in the full method.

## 9. Experimental safeguards

- Specify event-matching rules and metrics before final evaluation.
- Keep hidden ground truth out of method inputs.
- Use fixed and recorded random seeds.
- Separate development scenarios from held-out evaluation scenarios.
- Report results by scenario family, not only by aggregate averages.
- Report precision, recall, and abstention together.
- Document limitations of synthetic data.
- Do not invent probabilities or confidence intervals without a valid statistical basis.
- Publish negative or inconclusive results honestly.
- Do not claim superiority over existing forensic tools based only on comparisons with simplified baselines.

## 10. Decision criteria

The candidate research contribution remains provisional until the experiment shows whether the proposed method has a meaningful advantage under specified conditions.

A lower unsupported-conclusion rate is insufficient if recall collapses or the method abstains on almost every case.

If the method does not improve upon appropriate baselines, revise the method or research question rather than claim an unsupported contribution.

## 11. Next implementation stages

The list below records the original implementation order. Prototype components now exist on the active benchmark branch, but implementation and passing software tests do not establish that the benchmark meets the acceptance criteria in this protocol.

1. Implement the hidden ground-truth scenario model.
2. Implement a deterministic synthetic scenario generator.
3. Implement documented chronology-only and basic rule-correlation baselines.
4. Connect TRACEE through a common benchmark adapter.
5. Evaluate outputs using pre-defined metrics.
6. Run ablations and held-out tests.
7. Document results and limitations.

The benchmark is an experimental instrument. Passing its software tests establishes implementation correctness for tested cases, not research novelty or real-world forensic accuracy.


## 12. Current implementation audit

The benchmark currently has prototype implementations for the synthetic
scenario model and generator, chronology-only and rule-correlation baselines,
the TRACEE adapter, the prediction evaluator, and the experiment runner.

These components have passed the reported automated test suite. The current
60-scenario report is a development result, not an accepted comparative
evaluation.

The following issues remain open.

### Scenario identifiability

Every scored scenario must distinguish the underlying truth from what can
reasonably be inferred from observable input. Where multiple event histories
are consistent with the evidence, the benchmark must not require a method to
recover one hidden history as though it were uniquely identifiable.

### Timestamp disagreement

Maintain separate cases for unresolved clock disagreement and supported
clock reconciliation. The first measures appropriate uncertainty handling.
The second must supply observable calibration or bounded-time evidence that
justifies reconciliation.

The current case with two authentication-success records separated by
45 minutes has one hidden ground-truth event but no observable clock-offset
evidence. It is therefore not evidence that an algorithm should merge those
records. Its expected uncertainty label and scoring policy must be specified
before it is used to judge reconstruction quality.

### Negative controls

Add scenarios with no target authentication-success event, including
unrelated session activity and records that could be mistaken for the target.
A method must not receive credit for producing a target event in these cases.

### Interpretation-state evaluation

Counting interpretation states is not sufficient. Each scenario needs an
evaluation-only expected outcome describing whether a matching event should
be corroborated, challenged, underdetermined, or left with insufficient input.

Score interpretation-state correctness separately from event matching.
Do not label an uncertain candidate as a confirmed detection merely because
its event type, identity, and time match hidden ground truth.

### Time-matching policy

The main experiment must document its timestamp tolerance and unknown-time
policy. The current default permits matching when either side has unknown
time. Disable this in the primary evaluation unless a scenario-specific
justification is documented; report a separately labelled sensitivity
analysis if unknown-time matching is also evaluated.

### Provenance scope

Validate every prediction's source-observation references against the input
provided to the method. Report missing and invalid references separately.

Reference validity is only a baseline provenance check. It does not establish
that cited observations support the conclusion, that required contradictions
were retained, or that the inference rule and unresolved conditions are
adequately documented. Do not describe identifier validity alone as complete
forensic provenance.

### Repeated-seed evaluation

Run the benchmark using multiple pre-declared seeds and identical scenario
counts and scoring policies for all methods. Preserve per-seed reports and
per-family results. Report variability across runs before making comparative
claims; do not treat scenarios generated from the same template as wholly
independent real-world incidents.

### Operational performance

Runtime and memory measurements remain separate from reconstruction
accuracy. Record the environment and measurement procedure before comparing
operational performance.

## 13. Benchmark acceptance gate

Do not treat the benchmark as a completed comparative evaluation until:

1. Method inputs are separated from evaluator-only labels and metadata.
2. Scenario identifiers do not directly encode family names or seeds.
3. Positive, negative, ambiguous, and timestamp scenarios have explicit,
   testable ground-truth and interpretation expectations.
4. Unknown-time matching and definitive-state policies are pre-declared.
5. The evaluator validates evidence references against supplied input IDs.
6. Interpretation-state correctness and event matching are reported
   separately.
7. All methods receive equivalent observable inputs for the target task.
8. Results are reproducible across multiple seeds and broken down by
   scenario family.
9. Failure cases, limitations, and metric definitions are included with
   the results.

Meeting these gates establishes a more defensible synthetic experiment.
It does not by itself establish research novelty or performance on real
forensic investigations.
