---
name: data-analysis-and-visualization
description: Analyze datasets with explicit assumptions, quality checks and visuals that do not overstate evidence.
triggers:
  - Events/logs/metrics need summaries or charts
  - Dataset underpins detection evaluation or research
---

# Data Analysis and Visualization

## Purpose
Analyze datasets with explicit assumptions, quality checks and visuals that do not overstate evidence.

## Use When
- Events/logs/metrics need summaries or charts
- Dataset underpins detection evaluation or research

## Do Not Load When
- No dataset or quantitative claim is involved.

## Required Context and Prerequisites
Task brief, project instructions and the code touched. Active testing needs written scope and stop conditions first. See `instructions/COMMON_SKILL_RULES.md`.

## First 5-Minute Actions
Source/schema, time basis, labels, missingness, workload and interpretation goal.

## Procedure
1. Profile row/column count, missing/duplicate values, timestamp range and basic distributions.
2. Make the analysis re-runnable from raw input to figures; fix random seeds.
3. Choose chart types that match the question; label synthetic versus real data; show sample size and uncertainty.
4. Cross-check a subset against an independent calculation.
5. Stamp figures with units and data source; avoid misleading axes.

## Decision Rules and Stop Conditions
- Preserve raw input and transform a separate copy.
- Normalize types/timezones carefully and record inclusion/exclusion logic.
- Choose aggregation that answers the stated question; verify denominators and class balance.
- Label charts with units, time range, aggregation and data origin.
- Check outputs against hand-calculable examples and disclose data-quality limits.

## Tooling and Fallbacks
Use existing tooling and offline fixtures first. If something is unavailable, take the simplest credible fallback and say what it cannot verify (`instructions/COMMON_SKILL_RULES.md`).

## Implementation Patterns / Examples
Correlation is not causation; synthetic data does not establish operational performance. Missing labels are not negatives by default. Report distinct incident count and raw event volume so deduplication does not hide repeated activity.

## Verification and Acceptance Criteria
Summaries reconcile to source records; visual encodings and filtering are transparent.

Label evidence as reviewed, generated, mocked or executed, and record exact commands and outcomes (`instructions/COMMON_SKILL_RULES.md`, Evidence).

## Failure Modes and Troubleshooting
Timezone errors, double-counting, misleading axis, hidden filters, unvalidated labels.

On failure keep the error and identify its layer; after two similar failures change method or stop (`instructions/COMMON_SKILL_RULES.md`, Failure).

## Outputs to Record
Profiling results, transformation steps, chart/table and caveats.

Record evidence compactly (source, command, fact, interpretation, confidence, limit); redact secrets and personal data.

## Related Skills and Activation Triggers
digital-forensics-and-pcap; soc-siem-and-threat-detection; testing-and-verification.

Load a related skill only when its trigger is observed and it changes the next action.

## Completion Checklist
- [ ] Trigger matches; scope and assumptions recorded.
- [ ] Smallest workflow run; claims tied to evidence.
- [ ] Checks run, or skipped ones labeled.
- [ ] Limits and next action recorded.

**Time-box advice:** Check data quality before polishing charts; stop when the question is answered.
