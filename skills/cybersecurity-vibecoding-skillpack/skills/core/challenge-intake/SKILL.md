---
name: challenge-intake
description: Turn an informal request, challenge brief or rubric into a traceable definition of success.
triggers:
  - Broad/ambiguous task
  - Formal rubric, deadline or required submission
---

# Challenge Intake and Task Contract

## Purpose
Turn an informal request, challenge brief or rubric into a traceable definition of success.

## Use When
- Broad/ambiguous task
- Formal rubric, deadline or required submission

## Do Not Load When
- Narrow task whose acceptance checks are already explicit.

## Required Context and Prerequisites
Task brief, project instructions and the code touched. Active testing needs written scope and stop conditions first. See `instructions/COMMON_SKILL_RULES.md`.

## First 5-Minute Actions
Extract objective, user, deliverables, deadlines, constraints and unknown terms.

## Procedure
1. Rewrite the objective as a user outcome, not a technology list.
2. Convert each explicit requirement into an observable pass/fail check.
3. Separate must-have, should-have, optional and out-of-scope items.
4. Rank missing information by consequence and choose a reversible assumption when safe.
5. Return a short task contract and compare it back to the original brief.
6. Extract judging criteria and weights, constraints, deadlines, permitted tools and data, and required deliverables into one table; for an unfamiliar domain add a five-line glossary and the facts a domain expert would check first.
7. State the problem, target user and measurable impact in one sentence each before choosing a solution; never invent impact figures.

## Decision Rules and Stop Conditions
Pause when uncertainty affects authorization, sensitive data, irreversible action or a costly architecture choice. Otherwise state the smallest safe assumption and proceed.

## Tooling and Fallbacks
Use existing tooling and offline fixtures first. If something is unavailable, take the simplest credible fallback and say what it cannot verify (`instructions/COMMON_SKILL_RULES.md`).

## Implementation Patterns / Examples
For “make a security dashboard,” identify its user, data origin, response actions and whether alerts are synthetic or live before choosing a stack.

## Verification and Acceptance Criteria
Every deliverable has a check; exclusions and unknowns are explicit; no rubric requirement vanished from the summary.

Label evidence as reviewed, generated, mocked or executed, and record exact commands and outcomes (`instructions/COMMON_SKILL_RULES.md`, Evidence).

## Failure Modes and Troubleshooting
Keyword-matching can change the problem; assumptions quietly become requirements; impressive optional ideas displace scored work.

On failure keep the error and identify its layer; after two similar failures change method or stop (`instructions/COMMON_SKILL_RULES.md`, Failure).

## Outputs to Record
Task contract, acceptance checklist, assumptions, unknowns and exclusions.

Record evidence compactly (source, command, fact, interpretation, confidence, limit); redact secrets and personal data.

## Related Skills and Activation Triggers
requirements-and-acceptance when outcomes need test cases; hackathon-prioritization when time is tight; threat-modeling-and-abuse-cases.

Load a related skill only when its trigger is observed and it changes the next action.

## Completion Checklist
- [ ] Trigger matches; scope and assumptions recorded.
- [ ] Smallest workflow run; claims tied to evidence.
- [ ] Checks run, or skipped ones labeled.
- [ ] Limits and next action recorded.

**Time-box advice:** Spend the opening minutes resolving blockers; do not code while the goal is still unclear.
