---
name: incident-response-and-dfir
description: Support evidence-preserving triage, controlled containment, recovery and post-incident learning.
triggers:
  - A possible incident must be managed
  - Case lifecycle, response actions or evidence retention are required
---

# Incident Response and DFIR

## Purpose
Support evidence-preserving triage, controlled containment, recovery and post-incident learning.

## Use When
- A possible incident must be managed
- Case lifecycle, response actions or evidence retention are required

## Do Not Load When
- Simulated display with no incident-process claims.

## Required Context and Prerequisites
Task brief, project instructions and the code touched. Active testing needs written scope and stop conditions first. See `instructions/COMMON_SKILL_RULES.md`.

## First 5-Minute Actions
Incident authority/scope, assets, evidence sources, severity policy and recovery owner.

## Procedure
1. Preserve available evidence and establish an owner, time basis and immediate safety constraints.
2. Triage severity and scope from evidence (what, when, which assets); open a case record and a timestamped action log.
3. Contain with the least disruptive effective action approved by the owner; capture volatile evidence first when feasible.
4. Remove the root cause and recover from known-good sources; monitor for recurrence.
5. Close with a blameless review: timeline, detection gaps, fixes with owners and detection rules to add.

## Decision Rules and Stop Conditions
- Separate reported facts, confirmed indicators and investigation leads.
- Preserve artifacts/logs and document acquisition, hashes and gaps before changing systems where feasible.
- Build timeline, affected assets/accounts, attack-path hypotheses and confidence.
- Plan containment with impact, approval, rollback and evidence-preservation trade-offs.
- Record each action with owner, approval, timestamp and observed result.
- Verify recovery and document lessons and outstanding detection gaps.

## Tooling and Fallbacks
Use existing tooling and offline fixtures first. If something is unavailable, take the simplest credible fallback and say what it cannot verify (`instructions/COMMON_SKILL_RULES.md`).

## Implementation Patterns / Examples
Do not perform destructive containment or production changes without explicit authority. Escalate ongoing harm or legal/privacy questions per local process. A containment plan lists asset, rationale, likely side effect, approver, action log and rollback before execution.

## Verification and Acceptance Criteria
Case lifecycle is auditable; evidence is preserved; closure records recovery verification and open issues.

Label evidence as reviewed, generated, mocked or executed, and record exact commands and outcomes (`instructions/COMMON_SKILL_RULES.md`, Evidence).

## Failure Modes and Troubleshooting
Premature cleanup, unauthorized containment, mixed clocks, treating hypotheses as confirmed.

On failure keep the error and identify its layer; after two similar failures change method or stop (`instructions/COMMON_SKILL_RULES.md`, Failure).

## Outputs to Record
Timeline, evidence index, action/approval log, recovery tests and lessons learned.

Record evidence compactly (source, command, fact, interpretation, confidence, limit); redact secrets and personal data.

## Related Skills and Activation Triggers
digital-forensics-and-pcap; soc-siem-and-threat-detection; security-reporting-and-remediation; secrets-and-audit-logging; threat-intelligence-and-risk-prioritization.

Load a related skill only when its trigger is observed and it changes the next action.

## Completion Checklist
- [ ] Trigger matches; scope and assumptions recorded.
- [ ] Smallest workflow run; claims tied to evidence.
- [ ] Checks run, or skipped ones labeled.
- [ ] Limits and next action recorded.

**Time-box advice:** Prioritize immediate safety and preservation; make high-impact decisions explicit.
