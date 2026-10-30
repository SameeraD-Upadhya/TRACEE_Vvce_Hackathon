---
name: digital-forensics-and-pcap
description: Preserve and interpret artifacts with provenance, repeatability, timeline awareness and bounded conclusions.
triggers:
  - Disk/log/PCAP/memory/browser artifacts provided
  - Forensic timeline or incident reconstruction requested
---

# Digital Forensics and PCAP Evidence

## Purpose
Preserve and interpret artifacts with provenance, repeatability, timeline awareness and bounded conclusions.

## Use When
- Disk/log/PCAP/memory/browser artifacts provided
- Forensic timeline or incident reconstruction requested

## Do Not Load When
- Pure UI prototype without evidence-analysis claims.

## Required Context and Prerequisites
Task brief, project instructions and the code touched. Active testing needs written scope and stop conditions first. See `instructions/COMMON_SKILL_RULES.md`.

## First 5-Minute Actions
Original artifact, collection context, timestamps/timezone, custody needs and permitted tools.

## Procedure
1. Inventory and hash the source artifact where appropriate; analyze copies.
2. Work from read-only copies; compare the digest before and after analysis to show the source was not altered.
3. Build the timeline in one normalized timezone (UTC) while keeping original timestamps; mark clock-skew uncertainty.
4. Cite the source record (file, offset, packet or line number) for every finding so another analyst can reproduce it.
5. State confidence and alternative explanations; keep observation and conclusion apart in the report.

## Decision Rules and Stop Conditions
- Record source, collector, acquisition time, digest and handling steps.
- Keep raw records alongside normalized output; note parser/version and failures.
- Preserve original timestamp and timezone while normalizing for comparison; document clock uncertainty.
- Correlate on entity/time/source and distinguish direct linkage from coincidence.
- Document data gaps, retention limits and alternative explanations.
- Reproduce key timeline events against source evidence.

## Tooling and Fallbacks
Use existing tooling and offline fixtures first. If something is unavailable, take the simplest credible fallback and say what it cannot verify (`instructions/COMMON_SKILL_RULES.md`).

## Implementation Patterns / Examples
Absence of a log is not proof of absence. A digest shows matching bytes, not trustworthy acquisition or benign provenance. Two nearby events with same username may be a lead, not proof of common actor without host/session evidence.

## Verification and Acceptance Criteria
Evidence remains unmodified; conclusions reference source records and state confidence and time uncertainty.

Label evidence as reviewed, generated, mocked or executed, and record exact commands and outcomes (`instructions/COMMON_SKILL_RULES.md`, Evidence).

## Failure Modes and Troubleshooting
Work on originals, mix timezones, trust parsers blindly, overstate correlations.

On failure keep the error and identify its layer; after two similar failures change method or stop (`instructions/COMMON_SKILL_RULES.md`, Failure).

## Outputs to Record
Evidence inventory, hashes, timeline, normalized records, custody notes and report caveats.

Record evidence compactly (source, command, fact, interpretation, confidence, limit); redact secrets and personal data.

## Related Skills and Activation Triggers
network-and-protocol-analysis; osint-and-evidence-correlation; incident-response-and-dfir.

Load a related skill only when its trigger is observed and it changes the next action.

## Completion Checklist
- [ ] Trigger matches; scope and assumptions recorded.
- [ ] Smallest workflow run; claims tied to evidence.
- [ ] Checks run, or skipped ones labeled.
- [ ] Limits and next action recorded.

**Time-box advice:** Preserve provenance first; validate parsing on a small sample before processing all data.
