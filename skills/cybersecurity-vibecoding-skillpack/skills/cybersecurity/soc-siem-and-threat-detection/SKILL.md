---
name: soc-siem-and-threat-detection
description: Create explainable detections and alert workflows with data-quality checks, deduplication and analyst feedback.
triggers:
  - Telemetry becomes alerts/cases
  - SOC dashboard or detection logic must be built/evaluated
---

# SOC, SIEM and Threat Detection

## Purpose
Create explainable detections and alert workflows with data-quality checks, deduplication and analyst feedback.

## Use When
- Telemetry becomes alerts/cases
- SOC dashboard or detection logic must be built/evaluated

## Do Not Load When
- One-off forensic report with no ongoing detection pipeline.

## Required Context and Prerequisites
Task brief, project instructions and the code touched. Active testing needs written scope and stop conditions first. See `instructions/COMMON_SKILL_RULES.md`.

## First 5-Minute Actions
Event schema/source, live-vs-fixture label, detection objective, labels/baseline and retention needs.

## Procedure
1. Define one detection behavior and prepare positive, benign and edge-case fixtures.
2. Write the rule in a portable form first (Sigma-style: log source, selection, condition, false positives, level), then convert to the platform query.
3. Map to MITRE ATT&CK technique IDs as a classification aid, not as proof of attacker behavior.
4. Run the rule over positive, benign and noisy fixtures; record true and false positives and justify each exclusion.
5. Build the alert, case, evidence and response flow end to end; show dedupe counts and ingestion health.

## Decision Rules and Stop Conditions
- Normalize events while preserving source fields/timestamps; reject or quarantine malformed records.
- Document detection conditions, required fields, time window, exclusions and rationale.
- Deduplicate with stable event IDs or justified bounded correlation keys; keep linked raw evidence and counts.
- Add severity rationale, evidence references, ownership, status transitions and feedback.
- Evaluate false positives/negatives only when labels and data support it.
- Bound queues, sizes, retention and log volume; expose ingestion lag/errors.

## Tooling and Fallbacks
Use existing tooling and offline fixtures first. If something is unavailable, take the simplest credible fallback and say what it cannot verify (`instructions/COMMON_SKILL_RULES.md`).

## Implementation Patterns / Examples
Synthetic fixture scores are not real-world performance. Automated containment needs authorization, audit, preview and rollback. Three duplicate deliveries should produce a single incident with linked evidence and a visible duplicate count, not endless duplicate logs.

## Verification and Acceptance Criteria
Positive/negative fixtures, explainable alert reason, bounded incident behavior and source labels all exist.

Label evidence as reviewed, generated, mocked or executed, and record exact commands and outcomes (`instructions/COMMON_SKILL_RULES.md`, Evidence).

## Failure Modes and Troubleshooting
Alert storms, hidden dropped events, rule overfit, unbounded logs, unsupported severity.

On failure keep the error and identify its layer; after two similar failures change method or stop (`instructions/COMMON_SKILL_RULES.md`, Failure).

## Outputs to Record
Rule spec, fixtures, evaluation methodology/results/limits, correlation logic and metrics.

Record evidence compactly (source, command, fact, interpretation, confidence, limit); redact secrets and personal data.

## Related Skills and Activation Triggers
incident-response-and-dfir; digital-forensics-and-pcap; performance-and-reliability; threat-intelligence-and-risk-prioritization.

Load a related skill only when its trigger is observed and it changes the next action.

## Completion Checklist
- [ ] Trigger matches; scope and assumptions recorded.
- [ ] Smallest workflow run; claims tied to evidence.
- [ ] Checks run, or skipped ones labeled.
- [ ] Limits and next action recorded.

**Time-box advice:** Start with one rule and its false-positive controls before adding many rules.
