---
name: dynamic-skill-selection
description: Select the minimum useful skill set from evidence, prerequisites, risk and the current milestone.
triggers:
  - Several disciplines or tools may apply
  - A new task starts or evidence changes the approach
---

# Dynamic Skill Selection

## Purpose
Select the minimum useful skill set from evidence, prerequisites, risk and the current milestone.

## Use When
- Several disciplines or tools may apply
- A new task starts or evidence changes the approach

## Do Not Load When
- A stable, narrow task with no meaningful routing decision.

## Required Context and Prerequisites
Task brief, project instructions and the code touched. Active testing needs written scope and stop conditions first. See `instructions/COMMON_SKILL_RULES.md`.

## First 5-Minute Actions
Identify the immediate deliverable and choose a primary skill based on observable evidence.

## Procedure
1. Map deliverables and repository evidence to candidate domains, not buzzwords.
2. Check prerequisites and authorization before selecting active assessment skills.
3. Choose one primary and normally at most three supporting skills for this pass.
4. Name an output for each loaded skill and defer speculative modules.
5. Re-route only when new evidence changes the next action; document the trigger.
6. Choose from `skills/INDEX.md` and `SKILL_ROUTER.md` without opening skill files; open only the skills chosen.

## Decision Rules and Stop Conditions
Never load a skill merely because a word appears in the prompt. Load scope guidance whenever active testing is possible. Add support skills only when they change the next action or control material risk.

## Tooling and Fallbacks
Use existing tooling and offline fixtures first. If something is unavailable, take the simplest credible fallback and say what it cannot verify (`instructions/COMMON_SKILL_RULES.md`).

## Implementation Patterns / Examples
PCAP plus timeline → forensics; API authentication change → identity/access plus backend and tests.

## Verification and Acceptance Criteria
Every loaded skill has a reason and output; deferred skills have a trigger for later activation.

Label evidence as reviewed, generated, mocked or executed, and record exact commands and outcomes (`instructions/COMMON_SKILL_RULES.md`, Evidence).

## Failure Modes and Troubleshooting
Context overload, redundant file scanning, rigidly treating three as a hard cap, routing from keywords alone.

On failure keep the error and identify its layer; after two similar failures change method or stop (`instructions/COMMON_SKILL_RULES.md`, Failure).

## Outputs to Record
Chosen skills, milestone, reasons, deferred skills and re-route evidence.

Record evidence compactly (source, command, fact, interpretation, confidence, limit); redact secrets and personal data.

## Related Skills and Activation Triggers
Any skill whose trigger appears in new evidence.

Load a related skill only when its trigger is observed and it changes the next action.

## Completion Checklist
- [ ] Trigger matches; scope and assumptions recorded.
- [ ] Smallest workflow run; claims tied to evidence.
- [ ] Checks run, or skipped ones labeled.
- [ ] Limits and next action recorded.

**Time-box advice:** Keep routing brief; prefer useful work over taxonomy debate.
