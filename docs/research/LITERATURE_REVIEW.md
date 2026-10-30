# TRACEE Literature Review and Research-Gap Assessment

**Project:** TRACEE — Threat Reconstruction & Cyber Evidence Engine
**Review version:** 0.1
**Review date:** 2026-10-09
**Status:** Preliminary literature review; full review and novelty assessment pending
**Research branch:** `research/uncertainty-aware-reconstruction`

## 1. Purpose

This document compares established research, practical forensic tools, and investigation-data standards relevant to TRACEE's proposed reconstruction method.

The aim is not to demonstrate that event reconstruction is a new idea. It is to identify what existing approaches already provide, distinguish their assumptions and limitations, and determine whether a narrower contribution can be operationalized and evaluated experimentally.

This review is preliminary, not an exhaustive systematic literature review. Some sources have been examined through accessible full text, while others have only had their abstracts, publication records, or official documentation examined. The review status of each source must be updated as further reading is completed.

No claim of global research novelty is established by this document.

## 2. Candidate Research Problem

### 2.1 Provisional problem statement

During retrospective digital investigations, analysts may find incomplete logs, inconsistent records, conflicting artifacts, timestamps with uncertain reliability, and missing observations whose causes are not known.

A missing observation can have multiple explanations, including disabled logging, incomplete collection, retention expiry, unsupported parsing, artifact deletion, or an event that did not produce the expected artifact. The absence alone does not establish which explanation is correct.

Existing research already considers event inference, expected artifacts, contradictory observations, timestamp uncertainty, and provenance. The candidate research direction is to examine whether these concepts can be operationalized together through an explicit source-coverage and artifact-persistence model and evaluated under controlled evidence-loss conditions.

### 2.2 Provisional primary research question

**RQ1:** Under controlled conditions involving incomplete and inconsistent retrospective logs, does an explicit source-coverage and artifact-persistence model reduce unsupported incident hypotheses relative to simpler reconstruction baselines, while preserving reproducible links from each inference to its source evidence?

### 2.3 Supporting research questions

- **RQ2:** How accurately can the method distinguish known collection gaps, unknown coverage, and observations with positive indicators of possible removal?
- **RQ3:** How does the method preserve temporal uncertainty and avoid asserting causal relationships based only on temporal proximity?
- **RQ4:** Can each inferred event be reproduced from its input observations, rule version, temporal constraints, assumptions, supporting evidence, and contradictions?
- **RQ5:** What trade-offs arise between unsupported conclusions, reconstruction recall, abstention, and computational cost?

These questions are provisional and must be revised after examining the closest related work.

## 3. Literature Review Matrix

### 3.1 Foundational reconstruction and hypothesis testing

| Source | Established contribution | Overlap with TRACEE | Remaining question for our review |
|---|---|---|---|
| Carrier and Spafford (2004), *Defining Event Reconstruction of Digital Crime Scenes* | Establishes event reconstruction as a structured part of digital investigations. | Reconstruction of past activities from digital evidence. | Which later methods operationalize inference and validation beyond the foundational process model? |
| Schatz, Mohay, and Clark (2006), *A Correlation Method for Establishing Provenance of Timestamps in Digital Evidence* | Examines timestamp provenance and the effects of clock skew, drift, timezone, and clock manipulation. | Temporal reliability and cross-source correlation. | Which temporal uncertainty representations are most appropriate for our initial scope? |
| Willassen (2008), *Hypothesis-Based Investigation of Digital Timestamps* | Defines clock hypotheses and tests their consistency against timestamp evidence. | Explicit hypotheses and temporal consistency testing. | Which parts of temporal hypothesis testing can be reused or represented as constraints? |
| Batten et al. (2012), *Hypothesis Generation and Testing in Event Profiling for Digital Forensic Investigations* | Proposes an architecture to support hypothesis generation and testing in digital investigations. | Candidate incident hypotheses and evidence-driven investigation. | Which inference and hypothesis-evaluation functions overlap with our intended method? |
| Hargreaves and Patterson (2012), *An Automated Timeline Reconstruction Approach for Digital Forensic Investigations* | Reconstructs high-level events from low-level timeline observations using patterns and preserves the inference path to the underlying evidence. The publication also discusses expected artifacts that are present or absent and supporting or contradictory observations. | Strongest direct baseline for automated event reconstruction and evidence provenance. | Can explicit source coverage and artifact persistence improve the interpretation of missing expected evidence beyond the established pattern-based method? |
| Chabot et al. (2014), *A Complete Formalized Knowledge Representation Model for Advanced Digital Forensics Timeline Analysis* | Provides a formal model, semantic event representation, and operators for timeline reconstruction and analysis. | Formal representation of incidents, event relationships, and automated analysis. | Can our model interoperate with or map to existing formal representations rather than invent another incompatible schema? |
| Chabot et al. (2015), *Event Reconstruction: A State of the Art* | Reviews established reconstruction concepts and issues, including data volume and heterogeneity. | Background for method design and comparison. | Which limitations remain after accounting for subsequent research, especially the 2025 survey? |
| Soltani and Seno (2019), *A Formal Model for Event Reconstruction in Digital Forensic Investigation* | Uses temporal-logic model checking to evaluate digital-forensic properties and prove or refute hypotheses in a modeled system. | Hypothesis verification, consistency, and reproducibility. | Which claims can be checked deterministically, and where is a constraint-based model practical for our prototype? |

**Critical finding:** Hargreaves and Patterson (2012) already establish two capabilities that would otherwise be easy to mistake for novel contributions: high-level event reconstruction with provenance and consideration of expected artifacts that are absent. TRACEE must compare against these capabilities explicitly.

### 3.2 Trace semantics, reliability, and tool validation

| Source | Established contribution | Overlap with TRACEE | Remaining question for our review |
|---|---|---|---|
| Jaquet-Chiffelle and Casey (2021), *A Formalized Model of the Trace* | Defines formal concepts for events, scenes, and traces across forensic disciplines, including digital evidence. | Separating real events from observable traces and interpretations. | Which definitions should inform our observation and inference model? |
| Vanini, Breitinger, and Hargreaves (2023), *A Discussion of Sources and Quality/Reliability of Events for Timelines* | Examines source quality and the reliability of timeline events, emphasizing uncertainties that may affect reconstruction. | Source-aware reliability and propagation of uncertainty. | Which reliability dimensions can be operationalized without unjustified numeric scores? |
| Hargreaves, Nelson, and Casey (2024), *An Abstract Model for Digital Forensic Analysis Tools: A Foundation for Systematic Error Mitigation Analysis* | Models forensic-tool processing stages and argues for intermediate standardized representations to support validation and analysis of error propagation. | Pipeline validation, traceable transformations, and error propagation. | How can TRACEE make each transformation independently testable and expose parsing errors to later stages? |
| Vanini et al. (2024), *Was the Clock Correct? Exploring Timestamp Interpretation through Time Anchors for Digital Forensic Event Reconstruction* | Uses time anchors and related timestamp evidence to investigate system-clock correctness and timestamp anomalies. | Temporal consistency and event-ordering uncertainty. | How should our first implementation represent bounded or unresolved event ordering without overclaiming clock correction? |

### 3.3 Recent research most relevant to the candidate gap

| Source | Established contribution or finding | Consequence for TRACEE |
|---|---|---|
| Breitinger, Studiawan, and Hargreaves (2025), *SoK: Timeline Based Event Reconstruction for Digital Forensics: Terminology, Methodology, and Current Challenges* | Presents the TER-Model and identifies research directions involving uncertainty propagation, artifact persistence, automated inference, timeline verification, and the distinction between extracted data and inferred events. It specifically discusses uncertainty about whether absent data reflects configuration, tampering, or the passage of time. | This is the principal starting point for our gap assessment. We must read its proposed research gaps and compare our proposal against them rather than repeat them as our own discovery. |
| Olegård, Axelsson, and Li (2025), *When Is Logging Sufficient? Tracking Event Causality for Improved Forensic Analysis and Correlation* | Introduces causal identifiers, called gretel numbers, to track relationships across instrumented applications and associated logs. Its proof of concept uses eBPF and Nginx and measures resource overhead. | Distinguish retrospective reconstruction from systems that record additional causal information before an incident. Consider missing causal identifiers when evaluating cross-source correlation. |
| Hargreaves, van Beek, and Casey (2025), *SOLVE-IT: A Proposed Digital Forensic Knowledge Base Inspired by MITRE ATT&CK* | Organizes forensic investigation techniques, weaknesses, and mitigations in a structured knowledge base. | Existing forensic knowledge bases should be reviewed before inventing an unsupported technique taxonomy or claiming the first catalog of reconstruction limitations. |

### 3.4 Existing tools and standards

| Tool or standard | Established purpose | Implication for TRACEE |
|---|---|---|
| [Plaso / log2timeline](https://github.com/log2timeline/plaso) | Extracts and aggregates events from disk images, files, and other supported evidence sources into forensic timelines. | Treat mature timeline extraction as an existing capability. TRACEE's research should concern reconstruction semantics and evaluation, not merely event sorting. |
| [Timesketch](https://github.com/google/timesketch) | Supports collaborative analysis of forensic timelines, including querying, annotation, and analyzers. | A future TRACEE interface should complement investigation workflows rather than claim that timelines or event tagging are new. |
| [CASE / UCO](https://caseontology.org/) | Provides standardized concepts and representations for exchanging cyber-investigation information across tools. | Review compatibility before finalizing our observation, entity, and inference schema. |
| [SOLVE-IT](https://solveit-df.org/) | Structures established forensic techniques, weaknesses, and mitigations. | Use it to identify investigation pitfalls and articulate failure conditions where appropriate. |

## 4. What the Literature Actually Supports

### 4.1 Already established

Based on the sources reviewed so far, none of the following can serve as TRACEE's standalone research novelty:

1. Reconstructing high-level events from low-level artifacts.
2. Preserving links between inferred events and source evidence.
3. Recording expected, supporting, or contradictory artifacts.
4. Testing hypotheses against temporal or formal constraints.
5. Representing events and investigation entities using formal schemas.
6. Investigating timestamp provenance, skew, or clock manipulation.
7. Building timelines from multiple sources.
8. Using causal identifiers to improve correlation where systems can be instrumented.

These capabilities must be treated as established prior art, even though specific implementation details and capabilities vary between publications and tools.

### 4.2 More specific research opportunity

The 2025 SoK paper describes a relevant unresolved challenge: assessing artifact persistence and determining whether missing data reflects configuration, tampering, or the passage of time. It also notes that Hargreaves and Patterson had already developed an approach involving expected artifacts, including absent observations and evidence contradictions. The survey identifies artifact longevity as a potentially relevant factor when interpreting absent expected evidence, while noting that appropriate numerical assessments remain unclear.

This suggests a narrow candidate:

**A coverage-aware and persistence-aware missing-observation model, integrated with evidence-backed event inference and evaluated against existing-style reconstruction baselines under controlled evidence loss.**

The distinction is not simply that TRACEE records something as missing. It is whether an explicit model of observation coverage, source availability, expected artifact behavior, and uncertainty produces more defensible inferences in measurable circumstances.

The contribution remains unconfirmed until we review competing methods closely enough to establish that the proposed model is meaningfully distinct.

## 5. Proposed Technical Questions to Resolve

Before implementation, the full-text review should resolve the following.

### 5.1 Observation states

Can the implementation explicitly distinguish:

- `OBSERVED`: the expected record is present.
- `NOT_OBSERVED_WITH_KNOWN_COVERAGE`: the relevant source was available and its applicable coverage is known, but the record was not found.
- `NOT_OBSERVED_WITH_UNKNOWN_COVERAGE`: source coverage is insufficiently characterized to interpret absence reliably.
- `SOURCE_UNAVAILABLE`: the relevant source could not be examined.
- `POSSIBLE_REMOVAL_WITH_SUPPORTING_INDICATORS`: positive evidence suggests possible removal or tampering; this must not be assigned solely because a record is missing.

The exact states and their semantics must be validated against relevant prior art and formalized before coding.

### 5.2 Expected artifact behavior

For an expected artifact, determine what is known about:

- which action or system state could produce it;
- which source and parser should expose it;
- whether logging was enabled;
- whether the source covers the period in question;
- whether retention and artifact persistence make later observation plausible;
- whether the relevant source was acquired successfully;
- whether contradictory observations exist;
- whether the artifact's expected behavior has been independently tested.

Unknown values must remain unknown. No numeric confidence or probability should be assigned without a defensible and appropriately calibrated method.

### 5.3 Inference provenance

Each inferred event should identify the observations and source locations used, inference rule and version, temporal constraints, supporting and contradictory observations, missing expected observations, assumptions, known limitations, and review status.

The design must distinguish observations directly extracted from evidence from the events hypothesized by the reconstruction engine.

## 6. Candidate Experimental Design

This is a provisional plan, not a completed evaluation.

### 6.1 Controlled data

Create reproducible synthetic scenarios with known ground-truth events and known source-generation conditions. Introduce controlled variations such as:

- records omitted from otherwise complete logs;
- entire sources unavailable;
- logging disabled for specified intervals;
- retention expiry or artifact persistence differences;
- clock skew, drift, and unknown timezone information;
- conflicting timestamps and event records;
- duplicate or reordered records;
- unsupported parsers and parsing failures;
- genuine positive indicators of record removal or tampering.

The generator must retain separate ground truth for the underlying event, source coverage, and cause of any introduced omission. The reconstruction algorithm must not receive hidden ground-truth labels as input.

Crucially, some scenarios should be intentionally ambiguous. If the available observations do not identify why a record is absent, an unresolved result should count as a valid outcome rather than forcing the system to guess.

### 6.2 Baselines

**Baseline A — Chronology-only:** Sort normalized observations and emit no causal conclusion unless the method explicitly supports it. This establishes the value and limitations of simple chronological ordering.

**Baseline B — Basic rule correlation:** Apply documented event-correlation rules without explicit coverage- and persistence-aware reasoning.

**Baseline C — Expected-artifact rule baseline:** Implement a documented rule-based baseline inspired by prior work on expected artifacts, supporting evidence, contradictory evidence, and absence. Clearly identify this as an independently implemented approximation rather than a reproduction of an original implementation unless equivalence can be demonstrated.

**Proposed method:** Add explicit coverage and persistence semantics, preserve temporal constraints, separate observation from inference, and record reproducible derivations.

**Ablation studies:** Disable one proposed component at a time to investigate whether any observed improvement actually depends on coverage modeling, persistence information, contradiction handling, or derivation tracking.

### 6.3 Evaluation metrics

| Metric | Purpose |
|---|---|
| Reconstruction precision, recall, and F1 | Measure how accurately inferred event hypotheses match ground truth. |
| Unsupported definitive-hypothesis rate | Measure how often outputs presented as definitive are inconsistent with the ground truth. |
| Missing-observation classification accuracy | Evaluate classifications against known coverage and source-generation conditions. |
| Appropriate abstention | Measure whether the system leaves genuinely ambiguous cases unresolved instead of making unsupported claims. |
| Temporal relation accuracy | Evaluate ordering constraints, including cases where the true ordering cannot be uniquely determined. |
| Provenance completeness | Verify whether every emitted inference contains the required derivation fields. This is a software correctness invariant, not by itself evidence of novelty. |
| Reproducibility | Check whether the same inputs, rule versions, and configuration produce the same outputs. |
| Runtime and memory | Measure the overhead introduced by the proposed method. |

Metrics and decision thresholds should be specified before examining the final test results. Report results by scenario category, not only as an overall average.

### 6.4 Threats to validity

Synthetic logs may not represent the full complexity of real investigations. Rules may overfit the scenarios used to define them. Baselines may be too weak or may lack comparable information. Higher precision may be obtained by abstaining too often. A model may appear effective because the generator makes missingness easier to classify than it is in real evidence.

The final study should disclose these limitations and avoid generalizing results beyond the evaluated conditions.

## 7. Review Method and Completion Criteria

### 7.1 Search and screening

Search combinations of these terms:

- digital forensic event reconstruction;
- timeline inference and hypothesis testing;
- evidence provenance and forensic reproducibility;
- missing artifacts and artifact persistence;
- source reliability and logging coverage;
- uncertainty propagation in forensic reconstruction;
- causal correlation in retrospective logs;
- forensic tool validation and error propagation.

Relevant sources include Google Scholar, publisher records, DFRWS publications, arXiv, NIST publications, Plaso and Timesketch documentation, and CASE/UCO documentation.

The initial searches support a targeted literature review. They do not establish that every relevant publication has been found.

### 7.2 Required review record

For each important source, record:

1. Full citation, publication date, DOI or official URL.
2. Whether the full text was read, or only the abstract and metadata.
3. The source's research question and assumptions.
4. Its algorithm, model, or method.
5. Its treatment of missing or contradictory artifacts, temporal uncertainty, source reliability, and provenance.
6. Its experimental data, baseline comparisons, and limitations.
7. Direct overlap with TRACEE.
8. What remains genuinely unaddressed, if anything.
9. The evidence supporting any proposed distinction.

Do not infer that a method lacks a feature merely because its abstract does not mention it. Mark unverified details as unresolved until the full text or implementation has been examined.

### 7.3 Research-gap decision gate

The candidate gap is acceptable only if:

- close related work has been reviewed in sufficient detail;
- existing methods and tools have been compared on the specific proposed capability;
- the claimed distinction does not merely rename an established technique;
- the proposed method has a formal, testable specification;
- the benchmark can fairly compare the method with appropriate baselines;
- the intended contribution remains meaningful if its measured performance improvement is small or absent.

If the comparison shows that the proposed method already exists, revise the research question rather than claiming novelty. If the experiments do not show an advantage, report that result honestly.

## 8. Provisional Decision

**Status: Candidate gap only — not confirmed.**

The most promising current direction is coverage- and persistence-aware interpretation of missing observations within retrospective event reconstruction, with explicit uncertainty handling and evidence-backed inference derivations.

The proposed contribution is an integration and empirical-evaluation hypothesis, not a claim that each component is new.

The next research task is a close full-text review of the 2025 SoK paper and the 2012 Hargreaves–Patterson paper, followed by a detailed comparison with timestamp-hypothesis methods, formal reconstruction models, and the 2025 causal-logging approach.

**Implementation gate:** Do not begin the new reconstruction algorithm until the related-work review has sufficiently narrowed the contribution and the algorithm's input states, rules, and expected outputs have been specified.

## 9. References

1. Carrier, B. D., and Spafford, E. H. (2004). *Defining Event Reconstruction of Digital Crime Scenes*. Journal of Forensic Sciences, 49(6), 1291–1298. https://doi.org/10.1520/JFS2004127

2. Schatz, B. L., Mohay, G. M., and Clark, A. (2006). *A Correlation Method for Establishing Provenance of Timestamps in Digital Evidence*. Digital Investigation, 3, Supplement, 98–107. https://doi.org/10.1016/j.diin.2006.06.009

3. Willassen, S. Y. (2008). *Hypothesis-Based Investigation of Digital Timestamps*. Advances in Digital Forensics IV. https://doi.org/10.1007/978-0-387-84927-0_7

4. Batten, L., Pan, L., Khan, N., and collaborators (2012). *Hypothesis Generation and Testing in Event Profiling for Digital Forensic Investigations*. International Journal of Digital Crime and Forensics, 4(4), 1–14. https://doi.org/10.4018/jdcf.2012100101

5. Hargreaves, C., and Patterson, J. (2012). *An Automated Timeline Reconstruction Approach for Digital Forensic Investigations*. Digital Investigation, 9, Supplement, S69–S79. https://doi.org/10.1016/j.diin.2012.05.006

6. Chabot, Y., Bertaux, A., Nicolle, C., and Kechadi, M.-T. (2014). *A Complete Formalized Knowledge Representation Model for Advanced Digital Forensics Timeline Analysis*. Digital Investigation, 11, Supplement 2, S95–S105. https://doi.org/10.1016/j.diin.2014.05.009

7. Chabot, Y., Bertaux, A., Nicolle, C., and Kechadi, M.-T. (2015). *Event Reconstruction: A State of the Art*. Handbook of Research on Digital Crime, Cyberspace Security, and Information Assurance. https://doi.org/10.4018/978-1-4666-6324-4

8. Soltani, S., and Seno, S. A. H. (2019). *A Formal Model for Event Reconstruction in Digital Forensic Investigation*. Digital Investigation, 30, 148–160. https://doi.org/10.1016/j.diin.2019.07.006

9. Jaquet-Chiffelle, D.-O., and Casey, E. (2021). *A Formalized Model of the Trace*. Forensic Science International, 327, 110941. https://doi.org/10.1016/j.forsciint.2021.110941

10. Vanini, C., Breitinger, F., and Hargreaves, C. (2023). *A Discussion of Sources and Quality/Reliability of Events for Timelines*. DFRWS EU 2023. https://dfrws.org/presentation/a-discussion-of-sources-and-quality-reliability-of-events-for-timelines/

11. Hargreaves, C., Nelson, A., and Casey, E. (2024). *An Abstract Model for Digital Forensic Analysis Tools: A Foundation for Systematic Error Mitigation Analysis*. Forensic Science International: Digital Investigation, 48, 301679. https://doi.org/10.1016/j.fsidi.2023.301679

12. Vanini, C., and collaborators (2024). *Was the Clock Correct? Exploring Timestamp Interpretation through Time Anchors for Digital Forensic Event Reconstruction*. Forensic Science International: Digital Investigation, 49, 301759. https://doi.org/10.1016/j.fsidi.2024.301759

13. Breitinger, F., Studiawan, H., and Hargreaves, C. (2025). *SoK: Timeline Based Event Reconstruction for Digital Forensics: Terminology, Methodology, and Current Challenges*. Forensic Science International: Digital Investigation, 53, 301932. https://doi.org/10.1016/j.fsidi.2025.301932. Open preprint: https://arxiv.org/abs/2504.18131

14. Olegård, J., Axelsson, S., and Li, Y. (2025). *When Is Logging Sufficient? Tracking Event Causality for Improved Forensic Analysis and Correlation*. Forensic Science International: Digital Investigation, 52, 301877. https://doi.org/10.1016/j.fsidi.2025.301877

15. Hargreaves, C., van Beek, H., and Casey, E. (2025). *SOLVE-IT: A Proposed Digital Forensic Knowledge Base Inspired by MITRE ATT&CK*. Forensic Science International: Digital Investigation, 52, 301864. https://doi.org/10.1016/j.fsidi.2025.301864

16. Plaso (log2timeline). Official documentation and source repository. https://plaso.readthedocs.io/en/latest/ and https://github.com/log2timeline/plaso

17. Timesketch. Official source repository and documentation. https://github.com/google/timesketch

18. Cyber-investigation Analysis Standard Expression (CASE). Official ontology and specifications. https://caseontology.org/

19. SOLVE-IT. Digital forensics knowledge base. https://solveit-df.org/ and https://github.com/SOLVE-IT-DF/solve-it
