---
name: demo-and-judging
description: Present real implementation evidence in a focused walkthrough tied to published criteria.
triggers:
  - Judged demo, review or stakeholder handoff
  - Risk that demo uses unverified or simulated success
---

# Demo and Judging

## Purpose
Present real implementation evidence in a focused walkthrough tied to published criteria.

## Use When
- Judged demo, review or stakeholder handoff
- Risk that demo uses unverified or simulated success

## Do Not Load When
- Code-only change with no user walkthrough or presentation context.

## Required Context and Prerequisites
Task brief, project instructions and the code touched. Active testing needs written scope and stop conditions first. See `instructions/COMMON_SKILL_RULES.md`.

## First 5-Minute Actions
Rubric, time, working build, fixtures, setup, allowed fallback methods.

## Procedure
1. Choose one end-to-end path that demonstrates the strongest scored outcome.
2. Keep a claims ledger (`templates/claims-ledger.md`): every feature, metric or security claim gets evidence (test, artifact, run) and a status; remove or relabel unsupported claims.
3. Reset to a documented known state and run the chosen path end to end once; fix or cut whatever fails.
4. Prepare answers to likely judge questions: problem and users, real versus simulated parts, security risks, trade-offs, limits and future work.
5. Present differentiation only as far as evidence supports it; do not claim novelty, accuracy or impact that was not measured.

## Decision Rules and Stop Conditions
- Map each criterion to a screen, artifact, test or explanation.
- Use prepared fixtures and label simulations; start from a known state.
- Show user outcome before architecture details and visual polish.
- Rehearse one failure/recovery path and a valid fallback.
- State what is implemented, mocked, untested and limited.
- Freeze scope and rerun checks affected by final changes.

## Tooling and Fallbacks
Use existing tooling and offline fixtures first. If something is unavailable, take the simplest credible fallback and say what it cannot verify (`instructions/COMMON_SKILL_RULES.md`).

## Implementation Patterns / Examples
Never fake telemetry, test outcomes or status indicators. Use recordings/fixtures only when allowed and label them. Show duplicate alerts grouped into one incident with linked evidence and visible raw-event count.

## Verification and Acceptance Criteria
Every demo claim maps to current observable behavior or an explicit limitation.

Label evidence as reviewed, generated, mocked or executed, and record exact commands and outcomes (`instructions/COMMON_SKILL_RULES.md`, Evidence).

## Failure Modes and Troubleshooting
External service fails live, buttons do nothing, reset corrupts state, rubric claims have no evidence.

On failure keep the error and identify its layer; after two similar failures change method or stop (`instructions/COMMON_SKILL_RULES.md`, Failure).

## Outputs to Record
Demo script, rubric matrix, setup/fallback checklist and limitations.

Record evidence compactly (source, command, fact, interpretation, confidence, limit); redact secrets and personal data.

## Related Skills and Activation Triggers
hackathon-prioritization; testing-and-verification; release-and-packaging.

Load a related skill only when its trigger is observed and it changes the next action.

## Completion Checklist
- [ ] Trigger matches; scope and assumptions recorded.
- [ ] Smallest workflow run; claims tied to evidence.
- [ ] Checks run, or skipped ones labeled.
- [ ] Limits and next action recorded.

**Time-box advice:** Rehearse early enough to cut scope, then freeze before submission.
