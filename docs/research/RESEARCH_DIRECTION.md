# TRACEE Research Direction

- **Project:** TRACEE — Threat Reconstruction & Cyber Evidence Engine
- **Document status:** Provisional research specification
- **Version:** 0.1
- **Date:** 2026-10-09
- **Research novelty:** Not yet established
**Implementation status:** Proposed; not implemented as a complete reconstruction method

---

## 1. Executive Summary

TRACEE is being developed as a digital forensics and incident
response platform. Its existing foundation supports evidence
ingestion, SHA-256 integrity checking, metadata, evidence-chain
verification, application services, and a command-line interface.

Those capabilities provide a basis for preserving and examining
evidence. They do not yet constitute a complete incident-reconstruction
system.

The proposed research direction is retrospective incident
reconstruction from heterogeneous security logs when:

- the original logs do not contain explicit causal identifiers;
- timestamps may be imprecise, inconsistent, or unreliable;
- some records may be absent;
- source coverage and logging configuration may be unknown;
- different sources may support conflicting interpretations; and
- higher-level conclusions must remain traceable to source evidence.

The candidate contribution is a deterministic reconstruction method
that explicitly represents temporal constraints, coverage uncertainty,
supporting and contradictory observations, and inference provenance.

The goal is not to claim that these individual ideas are new. The
goal is to determine whether a specific combination, representation,
and reconstruction method can be implemented and shown experimentally
to reduce unsupported conclusions while retaining useful reconstruction
coverage.

No accuracy, detection, performance, or novelty claims may be made
before the corresponding research has been completed.

---

## 2. Current Product Baseline

### 2.1 Implemented foundation

The current codebase includes:

- deterministic metadata canonicalization;
- streaming SHA-256 hashing;
- evidence ID generation and validation;
- structured evidence metadata;
- filesystem evidence storage and staging;
- evidence ingestion and duplicate detection;
- hash-linked chain records;
- chain verification;
- metadata-to-chain binding verification;
- unified evidence verification;
- application services;
- a CLI and Python packaging configuration;
- automated unit, integration, and tamper tests.

The last reported full test run passed 264 tests.

This test result validates the tested implementation behavior. It does
not prove enterprise readiness, universal source compatibility,
forensic authenticity, or reconstruction accuracy.

### 2.2 Not yet established as an active integrated capability

The following remain research and engineering work:

- a stable normalized event schema;
- reviewed and integrated production parsers;
- explicit source-coverage representation;
- an uncertainty and temporal-constraint model;
- evidence-backed high-level hypothesis generation;
- a complete reconstruction and evaluation pipeline;
- reproducible ground-truth benchmarks;
- empirical comparisons with baseline methods.

Archived prototypes may be inspected and selectively reused after review.
Their existence does not mean that their behavior is currently integrated
or validated in the active foundation.

---

## 3. Preliminary Literature Position

The literature already addresses several ideas close to TRACEE's
original concept. The research must therefore be framed around a
specific method and its evaluation, not a broad claim that incident
reconstruction, provenance, or uncertainty handling is new.

### 3.1 Automated high-level event reconstruction

Hargreaves and Patterson (2012) describe a system that reconstructs
high-level events from lower-level forensic observations. Their work
preserves provenance from reconstructed events through lower-level
events to the raw evidence. It also discusses supporting, contradictory,
and expected-but-absent observations.

Implication for TRACEE:

A graph of events, a rule-based reconstruction engine, or links from
inferred events to source records are not sufficient novelty claims.

Reference:
https://doi.org/10.1016/j.diin.2012.05.006

### 3.2 Uncertainty in timeline-based reconstruction

Breitinger, Studiawan, and Hargreaves (2025) provide a systematization
of knowledge on timeline-based event reconstruction. They identify
uncertainty propagation across the reconstruction process, questions
about missing artifacts, timeline verification, and the distinction
between extracted facts and inferred events as relevant research
directions.

Implication for TRACEE:

The research must specify how uncertainty is represented, how it
affects inference, how unknown coverage changes a conclusion, and how
the evaluation measures these effects.

Reference:
https://doi.org/10.1016/j.fsidi.2025.301932

Open paper:
https://dfrws.org/wp-content/uploads/2025/05/SoK-Timeline-based-event-reconstruction-for-digital-forensics-Terminology-methodology-and-current-challenges.pdf

### 3.3 Causal information in logs

Olegård, Axelsson, and Li (2025) study logging sufficiency and propose
a mechanism using causal identifiers, called "gretel numbers", to track
causal information across applications. Their prototype focuses on
capturing causal information as activity is logged.

Implication for TRACEE:

The proposed problem differs in its emphasis on retrospective analysis
of existing logs that may not contain those identifiers. This distinction
does not by itself establish novelty; the literature review must identify
and compare prior retrospective methods.

Reference:
https://doi.org/10.1016/j.fsidi.2025.301877

### 3.4 Existing timeline systems

Plaso extracts timestamped events from supported sources and creates
forensic timelines. Timesketch supports collaborative timeline analysis.

Implication for TRACEE:

Timeline extraction, event sorting, filtering, tagging, and a timeline
interface should be treated as existing capabilities in the field,
not as the core research contribution.

References:
https://plaso.readthedocs.io/en/latest/
https://github.com/google/timesketch

### 3.5 Investigation representation and interoperability

CASE/UCO provides established representations for cyber-investigation
objects, relationships, provenance, and investigative activity.

Implication for TRACEE:

The project must evaluate whether to reuse CASE/UCO concepts or provide
an explicit mapping. Inventing a competing representation without a
clear need would increase complexity without demonstrating research
value.

References:
https://caseontology.org/
https://caseontology.org/ontology/start.html

### 3.6 Literature-review status

This review is preliminary and is not exhaustive.

A literature matrix must be developed before asserting novelty. It must
include relevant work on:

- automated timeline and event reconstruction;
- causal and cross-source correlation;
- clock skew and temporal uncertainty;
- missing, incomplete, and conflicting artifacts;
- provenance and evidence reliability;
- event hypothesis generation and testing;
- forensic benchmarks and ground truth;
- existing open-source tools and investigation standards.

For each source, record the research question, input assumptions,
algorithm or method, representation of uncertainty, provenance model,
handling of absent artifacts, evaluation dataset, metrics, limitations,
and relationship to the proposed TRACEE method.

The literature review must actively search for counterexamples to the
candidate contribution.

---

## 4. Candidate Research Problem

### 4.1 Problem statement

Retrospective incident reconstruction may require investigators to
combine heterogeneous logs that were not designed to encode a common
causal history.

A chronological ordering of records is not equivalent to a causal
reconstruction. Correlation based only on shared identifiers or time
windows can produce plausible but unsupported relationships.

A missing record also has several possible explanations. It may never
have been generated, may not have been collected, may have expired
under retention policy, may be unavailable due to acquisition failure,
or may have been removed or modified. Absence alone cannot determine
which explanation is correct.

The candidate problem is to develop and evaluate a reconstruction
method that makes these distinctions explicit and propagates their
consequences into every inferred incident step.

### 4.2 Proposed research question

How can a deterministic retrospective reconstruction method combine
temporal constraints, source-coverage information, contradictions, and
inference provenance to produce more defensible incident hypotheses
from heterogeneous logs that lack pre-recorded causal identifiers?

### 4.3 Sub-questions

RQ1. How should temporal uncertainty and source ordering be represented
without forcing every event into an unjustifiably precise timestamp?

RQ2. How should the method distinguish an observation that was not
found from an event that can reasonably be considered absent under
known source coverage?

RQ3. How should supporting and contradictory observations affect a
higher-level event hypothesis?

RQ4. Can the complete derivation of each hypothesis be recorded in a
machine-readable form and independently reproduced?

RQ5. Under controlled missing-record, clock-skew, and contradictory-source
conditions, how does the proposed method compare with simpler baselines?

### 4.4 Candidate contribution statement

The proposed contribution is a deterministic, coverage-aware and
provenance-preserving retrospective reconstruction method that represents
temporal constraints, supporting evidence, contradictory evidence,
observation coverage, and derivation rules for every inferred event.

It is designed for investigations in which the original logs may lack
explicit causal identifiers.

Whether this represents a novel contribution must be decided only after
the related-work review and comparison with existing methods.

---

## 5. Scope and Assumptions

### 5.1 Initial scope

The first implementation should support a deliberately narrow dataset:

- Linux authentication events;
- JSON-formatted process events;
- JSON-formatted network-connection events;
- controlled synthetic incidents with known ground truth.

This makes it possible to define expected behavior and evaluate the
method without first implementing a universal collector.

Initial incident patterns may include:

- repeated authentication failures followed by a successful login;
- account use followed by process activity;
- suspicious process activity followed by a network connection;
- interrupted or missing event sequences;
- conflicting timestamps or event attributes.

These are test scenarios, not claims of a production-grade attack
detection capability.

### 5.2 Assumptions

The initial research assumes:

1. Evidence files are supplied to TRACEE for retrospective analysis.
2. The evidence-integrity layer validates the stored artifacts separately
   from semantic event reconstruction.
3. Ground truth is available for generated evaluation scenarios.
4. Source coverage may be known, unknown, or explicitly incomplete.
5. Timestamps and correlation attributes may be wrong or missing.
6. Inferences are generated by deterministic, versioned rules.
7. An analyst remains responsible for consequential conclusions.

### 5.3 Non-goals for the first research prototype

The first prototype will not:

- claim to identify every possible cyberattack;
- claim to replace a SIEM, EDR, or existing forensic suite;
- execute real attacks to generate evidence;
- use an LLM as the source of forensic truth;
- silently convert temporal proximity into causality;
- assign numeric confidence values without a defensible calibration method;
- conclude that an event occurred solely because a rule expects it;
- conclude that an event never occurred solely because no record was found;
- infer malicious intent from a single event without adequate support;
- claim enterprise immutability from filesystem permissions alone.

---

## 6. Proposed Data Model

The model must distinguish raw observations, normalized events, constraints,
source coverage, and investigator-facing hypotheses.

### 6.1 Source observation

A source observation represents a record extracted from supplied evidence.
It must retain:

- stable observation identifier;
- evidence ID;
- raw source record or a reliable reference to it;
- byte offset, line number, or other source locator where applicable;
- parser identifier and parser version;
- original timestamp text;
- extracted attributes;
- parsing status and errors.

A source observation records what the supplied source contains. It is not
automatically proof that the underlying activity occurred exactly as
described by the record.

### 6.2 Normalized event

A normalized event provides a common representation of the interpreted
observation.

Minimum fields:

- normalized event ID;
- event type;
- source observation references;
- entity references;
- raw timestamp;
- normalized timestamp or time interval;
- timestamp parsing status;
- timezone and clock assumptions;
- normalized attributes;
- schema version.

Normalization must preserve the raw value and the source provenance.

### 6.3 Temporal constraints

A point timestamp should not be forced when the source does not justify
one.

The model should support:

- explicit timestamp;
- lower and upper temporal bounds where justified;
- known ordering constraints;
- unresolved ordering;
- unknown timezone or clock properties;
- the source of each temporal constraint.

Ordering constraints inferred from log position or protocol semantics must
be distinguishable from explicit timestamps.

An interval does not imply a probability distribution. Numeric uncertainty
or confidence must not be invented from a mere time range.

### 6.4 Source coverage declaration

The model needs a record of what sources were expected, collected, and
available for a time interval.

Possible coverage states:

- `KNOWN_COVERAGE`
- `PARTIAL_COVERAGE`
- `COVERAGE_UNKNOWN`
- `SOURCE_UNAVAILABLE`

Coverage records should include their basis, applicable time period,
source identity, collection information, and assumptions.

Coverage status does not itself prove that an event occurred or did not
occur.

### 6.5 Observation availability states

For an expected observation, distinguish:

- `OBSERVED`
- `NOT_OBSERVED_WITH_KNOWN_COVERAGE`
- `NOT_OBSERVED_WITH_UNKNOWN_COVERAGE`
- `SOURCE_UNAVAILABLE`
- `POSSIBLE_REMOVAL_WITH_SUPPORTING_INDICATORS`

`POSSIBLE_REMOVAL_WITH_SUPPORTING_INDICATORS` may only be used when
positive evidence supports possible removal or manipulation. A missing
record alone is insufficient.

### 6.6 Event hypothesis

An event hypothesis describes a candidate higher-level activity inferred
from one or more observations.

Required fields:

- hypothesis ID;
- event type and attributes;
- inference rule identifier and version;
- supporting observation IDs;
- contradictory observation IDs;
- expected observation descriptions;
- expected observations not found;
- coverage state for relevant sources;
- temporal constraints;
- assumptions;
- inference derivation;
- limitations and unresolved questions;
- review status.

The hypothesis must be reproducible from the inputs and rule version.

### 6.7 Relationship types

Relationships must distinguish at least:

- `OBSERVED_RELATION`: directly represented by a source record;
- `TEMPORAL_CONSTRAINT`: one observation constrains the ordering of
  another;
- `RULE_INFERRED_ASSOCIATION`: a versioned rule links observations
  according to stated conditions;
- `HYPOTHESIZED_CAUSAL_RELATION`: a candidate causal explanation that
  still requires evidential justification.

A shared IP address, account name, or nearby timestamp is not, by itself,
proof of a causal relationship.

### 6.8 Uncertainty representation

For the initial prototype, uncertainty should be represented as explicit
dimensions with supporting reasons, rather than a single opaque score.

Candidate dimensions:

- temporal uncertainty;
- source-coverage uncertainty;
- relationship or causal uncertainty;
- source reliability concerns;
- contradiction status;
- parser or normalization limitations.

Each dimension must record its basis and provenance.

Numeric probabilities may be considered later only if the underlying
method defines them and experiments support calibration.

---

## 7. Proposed Reconstruction Method

The initial method will be deterministic and rule-driven.

### Stage 1: Integrity gate

Verify that evidence artifacts meet the configured integrity requirements.
Do not perform semantic reconstruction on evidence known to have failed
the relevant integrity checks without explicitly marking and isolating
that condition.

Preserve the difference between integrity status and semantic reliability.

### Stage 2: Parsing and normalization

Extract source observations and normalize supported event types.

Preserve original values, timestamps, record locations, parser versions,
and error states.

Unrecognized or malformed records must be reported, not silently
discarded.

### Stage 3: Temporal constraint construction

Build explicit timestamp and ordering constraints.

Preserve conflicting timestamp information rather than forcing an
arbitrary total order. Represent the ordering of events as unresolved
when the available constraints do not justify a decision.

### Stage 4: Entity resolution

Resolve identifiers across supported event types using explicit,
documented rules.

Record the attributes and reasoning used to associate entities.
Ambiguous entity matches must remain distinguishable from confirmed
matches.

### Stage 5: Candidate hypothesis generation

Generate candidate high-level events through versioned rules.

Every rule must declare:

- required observations or predicates;
- optional supporting observations;
- expected observations;
- contradiction conditions;
- required temporal constraints;
- coverage requirements;
- assumptions and known limitations.

### Stage 6: Support and contradiction analysis

For each candidate hypothesis, record supporting and contradictory
observations.

Where an expected observation was not found, use the coverage model to
state what the absence does and does not establish.

Do not treat missing evidence as automatic disproof. Do not treat a
missing contradictory record as automatic confirmation.

### Stage 7: Uncertainty propagation

Propagate unresolved temporal constraints, unknown coverage, conflicting
observations, and inference limitations into the resulting hypothesis.

Do not let an event hypothesis appear more certain than its required
supporting conditions justify.

### Stage 8: Derivation generation

Produce a machine-readable derivation linking every inferred event to:

- its source observations;
- the evidence objects containing those observations;
- the normalization process;
- the rule and rule version;
- the temporal constraints;
- supporting and contradictory observations;
- coverage declarations;
- assumptions and limitations.

### Stage 9: Deterministic output

For identical evidence, configuration, and software versions, produce
reproducible reconstruction results.

The output must include its method and schema versions. Any change to
rules or assumptions must be reflected in the resulting provenance.

---

## 8. Research Hypotheses

These hypotheses are provisional and must be operationalized before the
final experiments begin.

### H1: Unsupported definitive conclusions

Under controlled missing-record and incomplete-coverage conditions,
the proposed method will produce fewer unsupported definitive
hypotheses than the selected baseline methods.

### H2: Temporal reconstruction

Under controlled clock shifts and conflicting timestamps, the proposed
method will reduce unjustified event-ordering decisions while retaining
correct ordering information when it is available.

### H3: Missingness interpretation

When source coverage varies, the proposed method will more accurately
distinguish confirmed coverage from unknown or incomplete coverage, and
will not infer malicious deletion from absence alone.

### H4: Provenance completeness

Every emitted inferred event will have a complete, machine-readable
derivation to its supporting input observations and rule version.

H4 is also a structural software invariant and should be enforced by
automated tests.

These are not established findings. They must be tested and reported,
including negative results.

---

## 9. Benchmark and Ground Truth

### 9.1 Dataset construction

Create a controlled synthetic evidence generator whose output is tied
to a ground-truth representation.

Each scenario must record:

- scenario ID and generator version;
- random seed;
- ground-truth event sequence;
- entities and relationships;
- source records generated for each event;
- source coverage and logging assumptions;
- deliberate omissions;
- clock shifts and timestamp changes;
- contradictions and duplicated records;
- any tampering indicators;
- expected reconstruction outcomes.

The evidence generator must be separate from the reconstruction method.
The reconstruction code must not read hidden ground-truth labels.

### 9.2 Initial experimental scenarios

Start with controlled versions of:

1. Complete logs with consistent timestamps.
2. Selected event records missing.
3. Known source coverage with expected events not observed.
4. Unknown or incomplete source coverage.
5. Fixed clock offsets.
6. Variable clock drift.
7. Missing timezone information.
8. Conflicting timestamps across sources.
9. Duplicate or reordered records.
10. Contradictory observations.
11. Altered records with detectable integrity failures.
12. Combinations of the preceding conditions.

Pilot the scenarios and define the final parameter values before the
confirmatory experiment. Do not adjust them after seeing results without
reporting the change.

### 9.3 Reproducibility

Use deterministic seeds and version all scenario definitions.

Maintain separate development and evaluation scenarios. Evaluation
scenarios must not be used to tune rules after their results are viewed.

If the project uses only synthetic data, state that limitation clearly
and do not imply validation on real-world incident logs.

---

## 10. Baselines and Ablation Study

Compare the proposed method with simple, explicitly documented methods.

### Baseline A: Chronology-only

Parse timestamps and sort observations chronologically, without
coverage-aware or hypothesis-level uncertainty propagation.

This baseline measures what can be achieved by simple timeline ordering.

### Baseline B: Basic rule correlation

Use cross-source identifiers and time-window rules to associate
observations, but do not propagate the full proposed uncertainty model.

This baseline must have documented rules and the same input evidence.

### Proposed method

Use temporal constraints, source coverage, contradiction handling,
explicit inference derivation, and uncertainty propagation.

### Ablations

Disable one component at a time to evaluate its contribution:

- remove coverage-aware missingness handling;
- remove temporal interval or partial-order constraints;
- remove explicit contradiction propagation;
- remove inference-provenance requirements.

Use identical input scenarios and ground truth for fair comparisons.

The purpose is to establish which components produce measurable effects,
not merely to show that the complete implementation runs.

---

## 11. Evaluation Metrics

Define the metric implementation and denominator before running the
confirmatory benchmark.

### 11.1 Reconstruction precision, recall, and F1

Compare emitted high-level event hypotheses with ground-truth events
using a pre-defined matching rule for event type, entity attribution,
and temporal compatibility.

Report precision, recall, and F1, broken down by scenario category.
Do not treat events that differ only because the ground truth allows
multiple valid temporal orderings as automatically incorrect.

### 11.2 Unsupported definitive-hypothesis rate

Measure the fraction of hypotheses presented as definitive that fail
their pre-defined evidential support requirements under ground truth.

The definition of "definitive" and the support requirements must be
documented before evaluation.

### 11.3 Temporal relation accuracy

Evaluate predicted before/after/concurrent/unresolved relations against
the ground-truth constraints.

Report accuracy for determined relations separately from appropriate
unresolved results.

### 11.4 Missingness classification

Compare the system's classification of expected observations with the
controlled ground truth for known coverage, unknown coverage, source
unavailability, and simulated removal indicators.

Do not score "possible removal" as correct merely because an event is
absent. Ground truth must include the reason for absence.

### 11.5 Provenance completeness

Measure the percentage of emitted hypotheses whose derivation includes
all required input observations, rule versions, and assumptions.

For the core invariant, the target is 100%: a hypothesis without the
required derivation must not be emitted as a completed result.

### 11.6 Reproducibility

Run identical inputs with identical configuration and software versions.
Compare normalized output records and derivation graphs.

Any expected nondeterminism must be identified in advance.

### 11.7 Performance

Record execution time and peak memory use against dataset size and
scenario complexity.

Report the machine, runtime, parameters, and measurement procedure.
Do not invent scaling results or benchmarks.

### 11.8 Uncertainty and abstention

When the engine reports unresolved or inconclusive results, measure how
often those outcomes are appropriate according to the ground truth.

If numeric confidence scores are introduced later, evaluate their
calibration separately. Do not convert qualitative labels into
probabilities without a defined and validated method.

---

## 12. Experimental Protocol

Before the confirmatory evaluation:

1. Freeze the reconstruction method and rule versions.
2. Define the scenario generator and ground-truth schema.
3. Publish the baseline descriptions and matching rules.
4. Define the metrics, denominators, and exclusions.
5. Fix the scenario parameter ranges and seeds.
6. Separate development scenarios from held-out evaluation scenarios.
7. Record the test environment.
8. Run all methods over the same scenarios.
9. Preserve raw results and analysis scripts.
10. Report failed scenarios, limitations, and negative results.

For aggregate metrics, report suitable uncertainty intervals or other
statistical summaries. Explain the statistical unit and avoid treating
correlated events from one scenario as independent samples without
justification.

---

## 13. Security and Forensic Correctness Invariants

The reconstruction implementation must maintain the following
invariants:

1. Raw evidence remains separate from normalized and inferred data.
2. Integrity verification is distinct from semantic interpretation.
3. Every source observation points to its evidence source and location
   where the format allows such a location.
4. Every inferred event points to the observations and versioned rules
   that produced it.
5. Every contradiction remains inspectable.
6. Unknown source coverage is not silently treated as confirmed absence.
7. Temporal proximity alone does not establish causation.
8. A failed integrity check is not silently ignored.
9. Rule changes are versioned and reproducible.
10. No unsupported event is presented as an observed fact.
11. Verification and reconstruction do not modify the original evidence.
12. Results remain reviewable by a human investigator.

A normal filesystem and SHA-256 hash chain do not by themselves provide
true immutable storage or prove the original authenticity of evidence.
These controls need separate threat analysis and validation.

---

## 14. Proposed Implementation Sequence

The following modules are proposed, not yet guaranteed to exist.

### R0 — Research specification and literature review

Deliverables:

- this research-direction document;
- literature matrix;
- related-work comparison;
- refined research questions;
- explicit inclusion and exclusion criteria for the review.

Exit condition:
The specific contribution is distinguished from the closest prior work,
and the review contains documented counterexamples and limitations.

### R1 — Normalized observation model

Candidate module:
`src/tracee/events.py`

Deliverables:

- versioned observation and normalized-event data models;
- raw timestamp preservation;
- source provenance fields;
- parser status and error representation;
- schema validation tests.

Exit condition:
Supported sample records can be parsed without losing source references
or raw values.

### R2 — Temporal constraints and coverage model

Candidate modules:

- `src/tracee/temporal.py`
- `src/tracee/coverage.py`

Deliverables:

- temporal interval and ordering representation;
- clock and timezone assumption handling;
- coverage declarations;
- explicit observation availability states;
- tests for ambiguous and conflicting timing information.

Exit condition:
Unknown time or coverage is preserved as unknown, not silently replaced
with a convenient value.

### R3 — Deterministic parsers

Candidate modules:

- `src/tracee/parsers/`
- Linux authentication parser;
- JSON event parser.

Deliverables:

- parser interfaces;
- normalized output;
- error handling;
- raw-record references;
- deterministic parser tests.

Exit condition:
Fixtures with known expected output produce reproducible observations.

### R4 — Inference provenance and hypothesis model

Candidate module:
`src/tracee/hypotheses.py`

Deliverables:

- hypothesis representation;
- support and contradiction links;
- rule identifier and version;
- source-coverage references;
- temporal constraints;
- derivation serialization.

Exit condition:
Every hypothesis can be explained and traced back to source observations.

### R5 — Reconstruction engine

Candidate module:
`src/tracee/reconstruction.py`

Deliverables:

- deterministic candidate-generation rules;
- evidence support and contradiction analysis;
- coverage-aware interpretation of unobserved expectations;
- uncertainty propagation;
- unresolved-result handling;
- complete derivation graphs.

Exit condition:
Controlled fixtures produce the specified hypotheses and handle
incomplete or conflicting inputs according to the formal specification.

### R6 — Benchmark implementation

Candidate directory:
`research/benchmark/` or an explicitly documented equivalent.

Deliverables:

- scenario generator;
- ground-truth schema;
- baseline implementations;
- ablation configurations;
- evaluation scripts;
- raw results and environment metadata.

Exit condition:
Every experiment can be rerun from versioned inputs and scripts.

### R7 — Integrated evaluation

Deliverables:

- held-out scenario evaluation;
- quantitative comparisons;
- error analysis;
- validity threats;
- reproducible result tables.

Exit condition:
Results support a clear conclusion about whether the proposed method
outperforms the chosen baselines on the stated research questions.

### R8 — Research paper

Write the paper only after the experiments and literature review are
sufficiently mature.

The paper must accurately distinguish design decisions, measured
findings, assumptions, and limitations.

---

## 15. Threats to Validity

The research must explicitly address:

- synthetic scenarios may not capture real-world incident complexity;
- the generator and reconstruction rules may share assumptions;
- a narrow set of Linux and JSON event sources limits generalization;
- ground truth may be ambiguous for certain event types;
- baseline implementations may be too weak or unfairly constrained;
- source coverage may be unknown or misrepresented;
- time intervals may reflect model assumptions rather than actual clock
  behavior;
- the method may abstain too frequently to be useful;
- a lower unsupported-conclusion rate may come at the cost of recall;
- deterministic rules may fail on unanticipated incident patterns.

These threats must be assessed and reported rather than hidden.

---

## 16. Research Decision Gates

### Gate A — Gap confirmation

Proceed only after the literature matrix and close comparisons clarify
whether the specific method is materially distinguishable from prior
work.

If it is not, refine or abandon the novelty claim.

### Gate B — Formal model

Freeze the observation, time, coverage, hypothesis, and provenance
semantics before implementing complex inference rules.

### Gate C — Prototype correctness

Require automated tests for schema correctness, deterministic results,
provenance completeness, contradictions, missingness, and uncertainty.

### Gate D — Experimental validity

Require reproducible datasets, documented baselines, pre-defined
metrics, held-out scenarios, and preserved raw results.

### Gate E — Contribution evidence

Claim a research contribution only when measured results establish what
the method improves, where it does not improve, and at what cost.

A negative or mixed result is preferable to an unsupported claim.

---

## 17. Current Decision

The confirmed problem area is retrospective event reconstruction under
uncertain, incomplete, or conflicting digital evidence.

The proposed research contribution remains provisional:
a deterministic, provenance-preserving reconstruction method combining
temporal constraints, coverage-aware missingness handling, and explicit
support/contradiction propagation for logs without pre-recorded causal
identifiers.

The next deliverable is a literature matrix and close comparison with
the most relevant prior methods.

Do not begin a large reconstruction implementation until the literature
review and formal data model provide a defensible specification.

---

## References

1. Hargreaves, C. and Patterson, J. (2012).
   An automated timeline reconstruction approach for digital forensic
   investigations. Digital Investigation, 9(Supplement), S69–S79.
   https://doi.org/10.1016/j.diin.2012.05.006

2. Breitinger, F., Studiawan, H., and Hargreaves, C. (2025).
   SoK: Timeline based event reconstruction for digital forensics:
   Terminology, methodology, and current challenges.
   Forensic Science International: Digital Investigation, 53, 301932.
   https://doi.org/10.1016/j.fsidi.2025.301932

3. Olegård, J., Axelsson, S., and Li, Y. (2025).
   When is logging sufficient? Tracking event causality for improved
   forensic analysis and correlation.
   Forensic Science International: Digital Investigation, 52, 301877.
   https://doi.org/10.1016/j.fsidi.2025.301877

4. Plaso documentation.
   https://plaso.readthedocs.io/en/latest/

5. Timesketch source repository and documentation.
   https://github.com/google/timesketch

6. Cyber-investigation Analysis Standard Expression (CASE).
   https://caseontology.org/
