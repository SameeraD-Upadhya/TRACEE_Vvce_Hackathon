---
name: osint-and-evidence-correlation
description: Correlate lawful public-source observations with provenance, source reliability and privacy minimization.
triggers:
  - Public information must be corroborated
  - Entities/events need a defensible relation graph
---

# OSINT and Evidence Correlation

## Purpose
Correlate lawful public-source observations with provenance, source reliability and privacy minimization.

## Use When
- Public information must be corroborated
- Entities/events need a defensible relation graph

## Do Not Load When
- Request seeks doxxing, stalking or sensitive details about a private person without legitimate authorization.

## Required Context and Prerequisites
Task brief, project instructions and the code touched. Active testing needs written scope and stop conditions first. See `instructions/COMMON_SKILL_RULES.md`.

## First 5-Minute Actions
Purpose, legal scope, sources, identifiers, timestamps and data-minimization needs.

## Procedure
1. Define the precise claim and collect the smallest attributable set of sources.
2. Use only public, lawful sources and respect terms of use; never access private accounts or bypass access controls.
3. Archive each observation (source, time, hash or screenshot) in an evidence record; keep copies of ephemeral pages.
4. Grade each link in the evidence graph (direct, corroborated, circumstantial) and show competing identity matches.
5. Minimize personal data in outputs and keep the question organizational, defensive or research-oriented.

## Decision Rules and Stop Conditions
- Capture source, URL/name, retrieval/publication time and exactly what was observed.
- Normalize entities carefully; do not merge by name alone when identifiers conflict.
- Check independent corroboration and note copied/circular sources.
- Separate direct observation, inference and unresolved identity matching.
- Minimize personal details and represent relationships with typed edges, provenance and confidence.

## Tooling and Fallbacks
Use existing tooling and offline fixtures first. If something is unavailable, take the simplest credible fallback and say what it cannot verify (`instructions/COMMON_SKILL_RULES.md`).

## Implementation Patterns / Examples
Public availability is not unlimited ethical permission. Avoid doxxing or unnecessary collection of sensitive personal data. A domain/IP/time relation is a lead with provenance, not proof of actor identity.

## Verification and Acceptance Criteria
Every edge has evidence and confidence; alternative explanations and excluded data are noted.

Label evidence as reviewed, generated, mocked or executed, and record exact commands and outcomes (`instructions/COMMON_SKILL_RULES.md`, Evidence).

## Failure Modes and Troubleshooting
Entity conflation, stale sources, circular corroboration, false precision, overcollection.

On failure keep the error and identify its layer; after two similar failures change method or stop (`instructions/COMMON_SKILL_RULES.md`, Failure).

## Outputs to Record
Source ledger, entity table, relation graph, confidence notes and minimized report.

Record evidence compactly (source, command, fact, interpretation, confidence, limit); redact secrets and personal data.

## Related Skills and Activation Triggers
digital-forensics-and-pcap; reconnaissance-and-scope-management; security-reporting-and-remediation; threat-intelligence-and-risk-prioritization.

Load a related skill only when its trigger is observed and it changes the next action.

## Completion Checklist
- [ ] Trigger matches; scope and assumptions recorded.
- [ ] Smallest workflow run; claims tied to evidence.
- [ ] Checks run, or skipped ones labeled.
- [ ] Limits and next action recorded.

**Time-box advice:** Set claim and privacy boundaries before collection; stop when remaining uncertainty is explicit.
