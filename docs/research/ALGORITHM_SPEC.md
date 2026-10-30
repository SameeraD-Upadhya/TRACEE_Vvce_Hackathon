# TRACEE Reconstruction Algorithm Specification

**Version:** 0.1
**Status:** Provisional technical specification
**Research branch:** `research/uncertainty-aware-reconstruction`
**Implementation status:** Not implemented by this specification
**Novelty status:** Unconfirmed

## 1. Purpose

Specify a deterministic, retrospective event-reconstruction method that preserves the distinction between extracted observations and inferred events.

The candidate method explicitly represents source coverage, expected artifact behavior, temporal constraints, supporting observations, contradictory observations, and unresolved conditions.

The objective is to investigate whether these representations improve the defensibility of reconstructed incident hypotheses when evidence is incomplete or inconsistent.

This specification is a design proposal. Its contribution must be assessed against existing reconstruction approaches before any novelty claim is made.

## 2. Scope

The initial implementation will accept previously collected digital evidence and structured observations extracted from supported sources.

It will not require causal identifiers to have been inserted into applications before an incident. When such identifiers exist, they may be treated as additional observed relationships.

The initial implementation is rule-based and deterministic. Machine learning, autonomous claims about attacker intent, and numerical probabilities of malicious activity are out of scope.

The first prototype should use a small, documented collection of event types and source formats rather than claim universal source compatibility.

## 3. Inputs

### 3.1 Evidence manifest

Each evidence source must retain:

- Evidence identifier.
- Content integrity hash where available.
- Source type and originating host or system.
- Source location or evidence-file reference.
- Acquisition status and known limitations.
- Collection interval, where known.
- Relevant logging configuration and retention information, where known.
- Parser identity and version used during analysis.

Unknown values must be explicitly represented as unknown. They must not be filled with assumed defaults.

### 3.2 Source observations

A source observation represents information extracted from a particular evidence location.

Required fields:

- Observation identifier.
- Evidence identifier.
- Source locator, such as a record ID or file offset.
- Original record or reference to preserved source data.
- Parser name and version.
- Event type and normalized attributes, where extraction succeeds.
- Original timestamp value and format.
- Normalized temporal representation, when justified.
- Parse status and parsing errors.

Observation identifiers must be stable within an investigation. Observations must not silently overwrite one another when their attributes or timestamps conflict.

### 3.3 Temporal representation

A time value must retain its known precision and uncertainty.

Examples include:

- An exact timestamp with known timezone.
- A timestamp with known precision but unknown timezone.
- A bounded time interval.
- An ordering constraint established by explicit source semantics.
- An unresolved temporal relationship.

An unknown timezone must not be silently treated as UTC.

If two event intervals overlap, their ordering is unresolved unless additional evidence establishes it. Temporal proximity alone must not establish causality.

### 3.4 Source coverage

The initial model uses these states:

- `KNOWN_COVERAGE`: The relevant source scope and collection conditions are documented sufficiently for the specific investigation question.
- `PARTIAL_COVERAGE`: Some relevant periods, records, or source regions are known to be missing or excluded.
- `COVERAGE_UNKNOWN`: Available information does not establish how completely the source represents the event period.
- `SOURCE_UNAVAILABLE`: The relevant source could not be examined or acquired.

A coverage declaration must identify the time interval, source, host or system, and applicable scope.

`KNOWN_COVERAGE` must not automatically mean that every event capable of occurring would necessarily have generated a record. That expectation requires separate evidence about logging behavior.

## 4. Expected Artifact Model

An expected artifact is a record or artifact that a documented rule predicts might be produced by an event under specified conditions.

Each expectation rule must identify:

- Rule identifier and version.
- Candidate event type.
- Required observations.
- Supporting observation patterns.
- Contradictory observation patterns.
- Expected artifact type and source.
- Conditions under which the artifact should be generated.
- Relevant logging configuration.
- Relevant source coverage.
- Known artifact persistence or retention behavior.
- Parser capability required to locate the artifact.
- Limitations and assumptions.

Expected artifact behavior must be grounded in documented source behavior, configuration, or controlled testing.

If the rule author cannot justify whether an artifact should have been generated or preserved, the expectation must remain uncertain.

The specification does not assume that a universal numeric artifact-lifetime model exists.

## 5. Interpretation of Missing Observations

The method must distinguish the following outcomes.

### 5.1 `OBSERVED`

The expected artifact was located and successfully interpreted.

### 5.2 `EXPECTED_NOT_FOUND`

The relevant search did not locate an expected artifact.

This state does not, by itself, indicate whether the underlying event occurred.

### 5.3 `NOT_FOUND_COVERAGE_UNKNOWN`

The artifact was not located, and the source's relevant coverage is unknown or incomplete.

The absence must not be treated as reliable negative evidence.

### 5.4 `SOURCE_UNAVAILABLE`

The relevant source could not be inspected. No conclusion about whether the artifact existed may be drawn from that source's unavailability.

### 5.5 `POSSIBLE_REMOVAL_WITH_INDICATORS`

Independent, positive observations provide reasons to investigate possible deletion, truncation, or tampering.

Examples may include explicit deletion records, documented truncation indicators, or independently corroborated inconsistencies.

Missingness alone must never produce this state.

### 5.6 Conditions for an informative absence

Before an absence can count against a hypothesis, the rule must evaluate:

1. Was the source available and relevant to the investigation interval?
2. Was the applicable logging capability enabled or otherwise expected to operate?
3. Would the candidate event be expected to produce the artifact under the documented conditions?
4. Is the relevant retention and persistence behavior sufficiently understood?
5. Was the source acquired and searched successfully?
6. Does the parser support the relevant artifact and record format?
7. Are there contradictory observations or known alternative explanations?

If important conditions remain unknown, the absence must remain unresolved.

Even when all conditions are satisfied, absence is not automatically proof that the event never occurred. Its significance depends on the documented rule and evidence.

## 6. Candidate Reconstruction Algorithm

### Stage 1 — Evidence integrity gate

Verify the available evidence integrity metadata before interpreting source records.

If a required integrity verification fails, preserve the failure and follow the investigation policy for handling affected evidence. Do not silently treat the affected evidence as verified.

The integrity gate must not claim that a correct hash alone proves the original evidence was authentic before acquisition.

### Stage 2 — Parse and normalize

Convert supported source records into source observations.

Preserve the connection between every observation and its original evidence location. Record parser failures explicitly.

Do not discard malformed records silently.

### Stage 3 — Build temporal constraints

Represent supported time values as timestamps, intervals, or unresolved constraints.

Derive definite ordering only when the available temporal information justifies it.

A timestamp difference alone must not produce a causal edge.

### Stage 4 — Construct entity relationships

Extract entities such as accounts, hosts, processes, files, addresses, and network connections when the source supports them.

Distinguish:

- Directly observed relationships.
- Rule-derived associations.
- Explicit causal relationships recorded in the evidence.
- Hypothesized causal relationships requiring further support.

Entity matches based on ambiguous attributes must retain the ambiguity rather than silently merge unrelated entities.

### Stage 5 — Generate candidate event hypotheses

Apply versioned inference rules to relevant source observations and entity relationships.

Every generated hypothesis must identify the triggering rule and its required conditions.

Candidate generation must be deterministic for the same observations, rule versions, and configuration.

### Stage 6 — Evaluate support and contradictions

For every candidate hypothesis:

1. Record its supporting observations.
2. Record its contradictory observations.
3. Evaluate expected artifacts against actual source coverage.
4. Evaluate relevant persistence, retention, and parser limitations.
5. Identify unresolved conditions and alternative explanations.
6. Determine whether the available evidence supports a conclusion, challenges it, or leaves it underdetermined.

The method must not make contradictions disappear merely because other observations support the hypothesis.

### Stage 7 — Propagate uncertainty

Preserve the source of each uncertainty, including:

- Temporal uncertainty.
- Unknown logging or collection coverage.
- Unknown artifact persistence.
- Parsing limitations.
- Ambiguous entity resolution.
- Contradictory observations.
- Rule assumptions.

The initial implementation must not invent statistical probabilities or combine these dimensions into an uncalibrated confidence score.

### Stage 8 — Produce derivations

Each inferred event must have a machine-readable derivation identifying:

- Input observation identifiers.
- Relevant source evidence and locators.
- Inference rule identifier and version.
- Supporting and contradictory observations.
- Expected observations and their availability states.
- Temporal constraints.
- Assumptions and unknown conditions.
- Known limitations.
- Final interpretation and review status.

An inferred event must never be presented as a directly extracted fact.

### Stage 9 — Emit deterministic results

For equivalent inputs, rule versions, configuration, and software version, produce equivalent normalized results.

Sort output deterministically where ordering is not itself meaningful. Generate stable identifiers from documented inputs or use stable stored identifiers.

The output must preserve enough information to reproduce and inspect each inference.

## 7. Output Contract

Each event hypothesis must provide:

- Hypothesis identifier.
- Event type and normalized attributes.
- Supporting observation identifiers.
- Contradictory observation identifiers.
- Expected-artifact evaluation results.
- Temporal bounds or unresolved temporal constraints.
- Entity relationships and their semantics.
- Inference rule identifier and version.
- Assumptions and limitations.
- Interpretation state.
- Investigator review state.
- Derivation information.

### Interpretation states

Use the following initial states:

- `CORROBORATED`: The specified rule's requirements are met and the available observations provide support, subject to recorded limitations.
- `CHALLENGED`: The available observations conflict with the candidate hypothesis under a documented rule.
- `UNDERDETERMINED`: The evidence is insufficient to distinguish relevant alternatives.
- `INSUFFICIENT_INPUT`: Required source or parsing information is unavailable for the rule to be evaluated.

These labels describe the state of the evidence under the selected rules. They do not establish absolute historical truth.

`CORROBORATED` must not be treated as a synonym for proven.

## 8. Initial Inference Example

Consider a candidate hypothesis that an account successfully authenticated to a host during a specified interval.

The relevant evidence includes authentication logs and information about the logging service.

**Case A: Logging disabled**

If logging was disabled during the interval, the absence of a corresponding authentication record cannot reliably challenge the candidate. The outcome remains dependent on other evidence.

**Case B: Relevant log coverage established**

If the source covers the interval, parsing succeeded, the logging configuration and expected record behavior are documented, and no corresponding record exists, the absence may be evaluated as counterevidence under the applicable rule.

The hypothesis must not automatically be rejected without evaluating alternative logging and artifact-generation explanations.

**Case C: Positive indication of truncation**

If separate observations indicate truncation, the system may flag possible removal for investigator review. It must distinguish observed truncation indicators from the unproven explanation that an attacker deliberately removed the record.

This example is illustrative. It is not evidence that the algorithm has been implemented or experimentally validated.

## 9. Correctness Invariants

The implementation and its tests must enforce these invariants:

1. Every inferred event refers to a versioned inference rule.
2. Every inferred event retains its derivation to source observations.
3. Missing records alone never establish malicious deletion.
4. Unknown coverage is not interpreted as complete coverage.
5. Temporal proximity alone never establishes causality.
6. Unknown timezone information is not silently converted into a known timezone.
7. Conflicting observations remain visible.
8. Unsupported confidence scores are not generated.
9. Input parsing failures are preserved as explicit outcomes.
10. Deterministic runs produce equivalent results for identical inputs and configuration.
11. Hash verification failures are surfaced before affected evidence is treated as verified.
12. The result distinguishes an observation from an inference.

## 10. Experimental Plan

### Dataset

Construct reproducible synthetic scenarios with known underlying events, artifact-generation conditions, source-coverage states, and known manipulation or omission operations.

The reconstruction process must not receive hidden ground-truth labels.

Include scenarios with:

- Known complete and partial source coverage.
- Unknown coverage and unavailable sources.
- Logging disabled during selected intervals.
- Controlled retention and artifact-persistence conditions.
- Duplicate, reordered, and conflicting records.
- Timestamp skew and unknown timezone.
- Unsupported parsers.
- Expected observations that are present or absent.
- Positive indicators of deletion or truncation.
- Intentionally ambiguous cases.

### Baselines

Compare against:

1. Chronology-only reconstruction.
2. Basic rule-based correlation.
3. An expected-artifact baseline inspired by existing forensic reconstruction research.
4. The proposed method with coverage and persistence semantics.

The expected-artifact baseline must document its rules and must not be represented as an exact reproduction of another research system unless equivalence has been established.

### Evaluation metrics

Measure:

- Event reconstruction precision, recall, and F1.
- Unsupported definitive-hypothesis rate.
- Missing-observation classification accuracy.
- Correct abstention when the cause of missingness is not identifiable.
- Temporal relation accuracy.
- Provenance completeness.
- Reproducibility.
- Runtime and memory consumption.

Perform ablation experiments to assess the effect of coverage semantics, artifact-persistence information, contradiction handling, and derivation tracking.

A lower unsupported-conclusion rate is not sufficient if the method achieves it merely by refusing to reconstruct events. Report recall and abstention alongside that metric.

## 11. Implementation Mapping

After review and approval of this specification, the proposed implementation sequence is:

1. Define the observation and event data models.
2. Define temporal constraints and source-coverage models.
3. Implement deterministic parser adapters for a limited number of supported sources.
4. Define expected-artifact and inference rules.
5. Implement candidate generation and evidence evaluation.
6. Produce auditable derivations.
7. Build a controlled scenario generator and baseline implementations.
8. Run evaluation and ablation experiments.
9. Decide whether results support a research contribution.

No implementation stage is considered complete merely because the module imports or its basic tests pass. Each stage needs explicit unit tests, integration tests, and tests for its relevant correctness invariants.

## 12. Research Decision

The specification defines a candidate method, not a proven advance over prior art.

Before claiming novelty, the literature review must determine whether a sufficiently similar coverage- and persistence-aware retrospective reconstruction model already exists.

Before claiming improved accuracy or reliability, the implementation must be compared against documented baselines using reproducible test data.

If the proposed method does not demonstrate an advantage, revise the research question or report the negative result rather than assert an unsupported contribution.

## 13. References

1. Hargreaves, C., and Patterson, J. (2012). *An Automated Timeline Reconstruction Approach for Digital Forensic Investigations*. https://doi.org/10.1016/j.diin.2012.05.006
2. Breitinger, F., Studiawan, H., and Hargreaves, C. (2025). *SoK: Timeline Based Event Reconstruction for Digital Forensics: Terminology, Methodology, and Current Challenges*. https://doi.org/10.1016/j.fsidi.2025.301932
3. Olegård, J., Axelsson, S., and Li, Y. (2025). *When Is Logging Sufficient? Tracking Event Causality for Improved Forensic Analysis and Correlation*. https://doi.org/10.1016/j.fsidi.2025.301877
4. Hargreaves, C., Nelson, A., and Casey, E. (2024). *An Abstract Model for Digital Forensic Analysis Tools: A Foundation for Systematic Error Mitigation Analysis*. https://doi.org/10.1016/j.fsidi.2023.301679
