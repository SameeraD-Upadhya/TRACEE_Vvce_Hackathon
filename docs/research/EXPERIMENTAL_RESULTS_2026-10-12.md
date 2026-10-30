# Exploratory Synthetic Benchmark Results — 2026-10-12

## Status

These are exploratory development results, not an accepted comparative
evaluation. They do not establish research novelty, real-world forensic
accuracy, or generalizability.

## Experimental setup

The benchmark was run with 10 scenarios per family and seeds 101, 211,
307, 401, and 503. The generator includes complete records, missing
records, disabled logging, conflicting timestamps, multiple entities,
ambiguous evidence, and a negative-control family.

Each seed generates 70 scenario instances. The conflicting-timestamp
family is diagnostic-only for event matching because its hidden
single-event history is not identifiable from the supplied evidence
without clock-offset evidence. Aggregate event-matching results therefore
exclude those 10 cases per seed, leaving 60 eligible scenario instances
per seed.

The reports in
`benchmark-results/multiseed-eval-2026-10-12-evaluator-fix/`
were generated after the correction that represents interpretation-state
accuracy as null when no comparisons were scored.

## Pooled event-matching results

Across the five seeds:

| Method | Evaluation | TP | FP | FN | Precision | Recall | F1 |
|---|---|---:|---:|---:|---:|---:|---:|
| Chronology-only | Candidate matching | 150 | 0 | 150 | 1.000 | 0.500 | 0.667 |
| Rule correlation | Candidate matching | 150 | 0 | 150 | 1.000 | 0.500 | 0.667 |
| TRACEE | Candidate matching | 300 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| Chronology-only | Definitive detection | 150 | 0 | 150 | 1.000 | 0.500 | 0.667 |
| Rule correlation | Definitive detection | 150 | 0 | 150 | 1.000 | 0.500 | 0.667 |
| TRACEE | Definitive detection | 150 | 0 | 150 | 1.000 | 0.500 | 0.667 |

The generated benchmark shows greater candidate-event recall for TRACEE than
for the two implemented baselines, while definitive-detection recall is
the same. These figures measure performance on the current synthetic
templates only.

## Family-level results

Across the five seeds, eligible positive ground-truth counts are:
- Complete records: 50.
- Missing record: 50.
- Logging disabled: 50.
- Ambiguous evidence: 50.
- Multiple entities: 100.

TRACEE matched all 300 of these positive events in the current runs,
without unmatched positive predictions in the aggregate. The baselines
matched complete-record and multiple-entity events but missed the positive
events in the missing-record, logging-disabled, and ambiguous-evidence
families.

The negative-control family produced no target-event predictions in these
runs. Zero observed false positives on these templates is not evidence
of a zero real-world false-positive rate.

## Interpretation-state scoring

The corrected aggregation reports:
- Chronology-only: 150 scored comparisons, 150 correct.
- Rule correlation: 150 scored comparisons, 150 correct.
- TRACEE: 300 scored comparisons, 300 correct.

These accuracies are not directly comparable because the methods have
different sets of matched events and therefore different scored subsets.
Scenario-level results with zero scored comparisons correctly serialize
accuracy as JSON null, not zero.

### Label-policy caveat

During development, the expected interpretation for the missing-record
scenario was changed from `insufficient_input` to `challenged` after
observing the implementation's output. `challenged` is consistent with
the current rule policy when an expected artifact is not observed under
documented coverage and is explicitly declared as absence counterevidence.
However, because the scenario expectation was changed during development,
the current interpretation-state accuracy must be treated as descriptive,
not as confirmatory validation of the interpretation policy.

The expected-state policy must be justified and frozen independently of
model outputs before a future confirmatory run.

## Reproducibility and limitations

All five seeds produced identical precision, recall, and F1 values for
each method. This indicates no measured outcome variation across these
seeded instances under the current scenario templates. It does not show
robustness across realistic, independently designed forensic cases.

The benchmark acceptance gate remains open. Priorities include:
1. Independently specifying and freezing ground-truth interpretation
   labels before the next evaluation.
2. Increasing structural diversity rather than varying only identifiers
   and other scenario details.
3. Adding clock-disagreement cases with observable calibration evidence.
4. Testing broader negative controls and distractor evidence.
5. Running a held-out evaluation after scenario and label policies are
   frozen.
6. Reporting failure cases and comparing methods with equivalent input
   evidence.

Passing software tests establishes correctness for the tested software
cases, not research novelty or real-world forensic performance.
