# TRACEE Core Paper Analysis

**Review date:** 2026-10-09
**Status:** Initial full-text comparison completed; candidate research contribution remains unconfirmed.

## 1. Purpose

This document records the main findings from examining two central publications relevant to TRACEE's proposed retrospective incident-reconstruction method.

The purpose is to distinguish established prior art from a possible research contribution. This is a targeted review of two papers, not an exhaustive literature review or proof of global novelty.

## 2. Paper A: Hargreaves and Patterson (2012)

**Title:** An Automated Timeline Reconstruction Approach for Digital Forensic Investigations

**Publication:** Digital Investigation, 9 (Supplement), S69–S79.

**DOI:** https://doi.org/10.1016/j.diin.2012.05.006

**Accessible full text:**
https://dfrws.org/sites/default/files/session-files/2012_USA_paper-an_automated_timeline_reconstruction_approach_for_digital_forensic_investigations.pdf

### 2.1 Research objective and approach

The paper addresses the challenge of extracting large numbers of low-level digital events and turning them into more useful, high-level events for forensic investigators.

Its PyDFT prototype uses two major stages:

1. Low-level event extraction from file systems and supported artifacts within files.
2. Rule-based reconstruction of higher-level events from the resulting timeline.

The reconstruction stage uses analyzer plugins that describe patterns of observations expected for a particular high-level event.

A matching event can trigger a working hypothesis that a higher-level activity occurred. Additional observations can then support or contradict that hypothesis.

### 2.2 Existing capabilities directly overlapping with TRACEE

The paper already establishes the following:

- High-level event inference from low-level observations.
- Predefined rules and patterns for reconstructing activities.
- Combining related artifacts from different sources.
- Recording triggering observations.
- Recording supporting and contradictory artifacts.
- Recording artifacts expected by an analyzer but not found.
- Preserving provenance from inferred events to lower-level observations and raw source data.
- Representing earliest and latest possible event times.

The reported provenance mechanisms include file byte offsets, text-file line numbers, database query and record identifiers, and source-file identification.

Consequently, neither high-level event reconstruction nor traceability to underlying evidence can be claimed as TRACEE's standalone novelty.

### 2.3 Temporal assumptions and limitations

The paper describes its method as temporal-proximity pattern matching. An analyzer can search for related events inside a configured time interval around a trigger, with an example using ten seconds on either side.

This introduces a critical design consideration for TRACEE: a temporal relationship is not automatically a causal relationship.

The paper's documented limitations include:

- An assumption that the investigated system clock is correct.
- No existing mechanism in the prototype for detecting deliberate clock manipulation.
- Dependence on human-authored analyzers and patterns.
- A need for broader validation of low-level extraction and high-level reconstruction accuracy.
- A need to test the approach against more real-world data.
- Opportunities to investigate more advanced inference methods.

These limitations are reported in the 2012 paper. They do not establish that every later system retains the same weaknesses.

### 2.4 Implications for TRACEE

A fair comparison must include, or carefully approximate, a predefined-rule reconstruction baseline that records supporting and contradictory evidence and preserves provenance.

The literature review must investigate whether later methods have addressed the identified temporal, validation, and generalization limitations.

TRACEE must not claim to introduce expected-artifact reasoning, contradiction recording, or inference provenance as new concepts.

## 3. Paper B: Breitinger, Studiawan, and Hargreaves (2025)

**Title:** SoK: Timeline Based Event Reconstruction for Digital Forensics: Terminology, Methodology, and Current Challenges

**Publication:** Forensic Science International: Digital Investigation, 53, article 301932.

**DOI:** https://doi.org/10.1016/j.fsidi.2025.301932

**Accessible full text:**
https://arxiv.org/html/2504.18131

### 3.1 Purpose and methodology

The paper proposes a unified model of timeline-based event reconstruction, harmonizes terminology, classifies challenges, and identifies potential directions for future work.

Its review methodology used combinations of search terms and reviewed the first two pages of Google Scholar results for each query, screening approximately 200 articles.

The authors acknowledge possible omissions and misclassification arising from manual screening, reliance on limited search-result pages, emphasis on abstracts and introductions when extracting challenges, and subjective categorization.

Implication: this survey is a valuable source for research-gap discovery, but its existence does not guarantee that every relevant publication has been captured. TRACEE's review should extend the search and investigate the specific papers closest to the proposed method.

### 3.2 Research gaps directly relevant to TRACEE

**Research Gap 1 — Uncertainty propagation**

The survey identifies a need to understand uncertainty introduced at different stages of reconstruction and how that uncertainty propagates through the process.

Potential TRACEE connection: preserve separate uncertainty dimensions across extraction, source interpretation, temporal constraints, and event inference instead of collapsing them into an unsupported confidence number.

**Research Gap 3 — Artifact persistence and missing data**

The survey identifies limited work on artifact persistence and determining whether absent data results from configuration, tampering, or the passage of time.

It identifies artifact longevity as a potentially relevant factor in assessing absent expected evidence and notes uncertainty about precise numerical assessments.

Potential TRACEE connection: explicitly represent known source coverage, source availability, relevant artifact behavior, and unknown conditions, then test their effect on inference decisions.

**Research Gap 4 — Timeline generation, timing information, and tampering**

The survey identifies further work on artifact research, timing information beyond explicit timestamps, visualization, inconsistencies, and tamper detection.

Potential TRACEE connection: preserve timestamp uncertainty and contradictions rather than forcing every observation into an unquestioned chronological order. This broad gap is not sufficiently specific to serve as the proposed contribution by itself.

**Research Gap 6 — Automated event inference at scale**

The survey notes the challenge of automatically inferring events from timeline entries when operating systems, applications, and environments change.

Potential TRACEE connection: make parser and inference-rule versions explicit and test the method under changing input formats and incomplete sources.

**Research Gap 7 — Facts versus hypotheses**

The survey calls for a clear distinction between extracted timestamp values treated as facts and inferred events treated as working hypotheses, together with transparent communication of residual uncertainty.

Potential TRACEE connection: distinguish source observations from inferred events in both the data model and every inference derivation.

### 3.3 Other relevant observations

The survey explains that missing observations can arise from multiple mechanisms, including insufficient logging, suppression, crashes, resource exhaustion, log rotation, subsequent overwriting, and deliberate deletion.

It also emphasizes source reliability, inconsistent observations, cross-source correlation, investigator interpretation, and the risks of overreliance on automated tools.

Therefore, absence should not be represented as a binary proof that an event did or did not occur. Its meaning depends on the expected behavior and limitations of the observation source.

## 4. Comparison of the Two Papers

| Capability or challenge | Hargreaves and Patterson (2012) | Breitinger et al. (2025) | Consequence for TRACEE |
|---|---|---|---|
| High-level event inference | Demonstrated using predefined patterns | Reviews event-inference methods and challenges | Not standalone novelty |
| Evidence provenance | Explicitly maintained to raw data | Identifies provenance and context as important to investigation | Required engineering property |
| Supporting artifacts | Recorded | Reviews support for hypotheses | Established capability |
| Contradictory artifacts | Recorded | Discusses conflicting observations and artifact reliability | Established concept |
| Expected artifacts absent | Considered in rule-based reconstruction | Identifies artifact persistence as an unresolved research direction | Strongly relevant, but direct overlap must be examined |
| Temporal uncertainty | Represents earliest/latest time bounds, while assuming a correct system clock | Reviews clock, timing, and uncertainty challenges | Requires a method beyond basic time bounds |
| Uncertainty propagation | Not the central contribution of the paper | Explicitly identified as a research gap | Potentially relevant to a narrowed contribution |
| Changing source environments | Limited analyzer-based approach | Identified as a challenge for automation | Relevant evaluation dimension |
| Ground-truth and validation | Identifies a need for broader validation | Identifies research gaps and challenges in validation and inference | TRACEE should use controlled, reproducible experiments |

## 5. Revised Candidate Contribution

The broad idea of coverage-aware and persistence-aware missing-observation interpretation is already motivated by the 2025 survey. It cannot be presented as a newly discovered gap based on these two papers.

A narrower candidate is:

**Design and experimentally evaluate a reproducible retrospective reconstruction method that incorporates explicit source-coverage and artifact-persistence metadata into expected-observation analysis, propagates the resulting uncertainty into event hypotheses, and records the derivation for independent review.**

The potential contribution is the formalization and evaluated behavior of this method, if the complete review shows that it is sufficiently distinct from related work.

The evaluation should compare the method against a predefined-rule baseline with expected-artifact checks and a chronology-only baseline, and use controlled test scenarios with known ground truth.

Relevant outcomes include unsupported definitive-hypothesis rate, reconstruction precision and recall, missing-observation interpretation accuracy, appropriate abstention, derivation completeness, reproducibility, and runtime.

A decrease in unsupported conclusions must not be celebrated without also examining recall and abstention. A method that simply declines to infer anything could have a low unsupported-conclusion rate while offering little practical value.

## 6. Important Unresolved Questions

Before implementation, the review must determine:

1. Which existing approaches already use source coverage or artifact persistence explicitly?
2. How is artifact longevity or expected artifact behavior currently documented or modeled?
3. What established reliability models or formal methods should inform the representation?
4. What is the correct baseline for comparing missing-observation interpretation?
5. Which aspects can be validated using synthetic ground truth, and which require real-world forensic cases?
6. Can the proposed method demonstrate a reproducible advantage rather than merely adding metadata?

Do not assign numerical likelihoods to hypotheses without a defensible model and appropriate calibration.

Do not infer malicious deletion from absence alone.

Do not label temporal proximity as causality.

## 7. Review Decision

**Decision: Continue the literature review; do not begin the reconstruction implementation yet.**

The closest two papers show that the general building blocks are established. The 2025 survey supplies explicit open research directions, including missing-artifact interpretation and uncertainty propagation.

The next review should examine the prior work that is closest to these topics, especially:

- Adedayo and Olivier (2015), on log settings and reconstruction.
- Vanini et al. (2023), on event source quality and reliability.
- Willassen (2008), on hypothesis-based investigation of digital timestamps.
- Chabot et al. (2014, 2015), on formal event and timeline representations.
- Hargreaves et al. (2024), on tool transparency and systematic error mitigation.
- Olegård, Axelsson, and Li (2025), on causality information in logs.

After this comparison, either sharpen the research question to a defensible, testable contribution or revise the direction if prior art already covers it.

## 8. References

1. Hargreaves, C., and Patterson, J. (2012). *An Automated Timeline Reconstruction Approach for Digital Forensic Investigations*. Digital Investigation, 9, Supplement, S69–S79. https://doi.org/10.1016/j.diin.2012.05.006

2. Breitinger, F., Studiawan, H., and Hargreaves, C. (2025). *SoK: Timeline Based Event Reconstruction for Digital Forensics: Terminology, Methodology, and Current Challenges*. Forensic Science International: Digital Investigation, 53, 301932. https://doi.org/10.1016/j.fsidi.2025.301932. Open full text: https://arxiv.org/html/2504.18131
