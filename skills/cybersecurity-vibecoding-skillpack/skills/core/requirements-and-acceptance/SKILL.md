---
name: requirements-and-acceptance
description: Translate desired behavior into measurable acceptance checks, negative cases and explicit non-goals.
triggers:
  - Requirements must become implementation tasks/tests
  - “Done” is disputed or too vague
---

# Requirements and Acceptance Criteria

## Purpose
Translate desired behavior into measurable acceptance checks, negative cases and explicit non-goals.

## Use When
- Requirements must become implementation tasks/tests
- “Done” is disputed or too vague

## Do Not Load When
- The requirements already map directly to observable tests.

## Required Context and Prerequisites
Task brief, project instructions and the code touched. Active testing needs written scope and stop conditions first. See `instructions/COMMON_SKILL_RULES.md`.

## First 5-Minute Actions
Write Given/When/Then checks for the highest-value user flow.

## Procedure
1. Group requirements by workflow and trust boundary.
2. For each, define inputs, output, errors, persistence and observable result.
3. Add negative/boundary checks and nonfunctional criteria only when relevant.
4. Mark criteria blocked by unavailable data, credentials, hardware or services.
5. Map implementation tasks, tests and demo evidence back to requirement IDs.
6. Write at least one security acceptance criterion per sensitive capability (who must be denied, what must be logged).

## Decision Rules and Stop Conditions
Replace vague terms such as “fast”, “secure” or “professional” with a scenario, bound, or review checklist; never invent numeric service targets.

## Tooling and Fallbacks
Use existing tooling and offline fixtures first. If something is unavailable, take the simplest credible fallback and say what it cannot verify (`instructions/COMMON_SKILL_RULES.md`).

## Implementation Patterns / Examples
“Alert list updates” becomes: ingest a fixture, persist an alert, refresh and verify a stable ID appears once.

## Verification and Acceptance Criteria
Every must-have criterion can be tested, has a state and defines mock-versus-real behavior.

Label evidence as reviewed, generated, mocked or executed, and record exact commands and outcomes (`instructions/COMMON_SKILL_RULES.md`, Evidence).

## Failure Modes and Troubleshooting
Over-specifying low-value features, omitting errors, treating a screenshot as persistence proof.

On failure keep the error and identify its layer; after two similar failures change method or stop (`instructions/COMMON_SKILL_RULES.md`, Failure).

## Outputs to Record
Requirements matrix, priorities, non-goals and unresolved acceptance questions.

Record evidence compactly (source, command, fact, interpretation, confidence, limit); redact secrets and personal data.

## Related Skills and Activation Triggers
challenge-intake; architecture-and-mvp; testing-and-verification.

Load a related skill only when its trigger is observed and it changes the next action.

## Completion Checklist
- [ ] Trigger matches; scope and assumptions recorded.
- [ ] Smallest workflow run; claims tied to evidence.
- [ ] Checks run, or skipped ones labeled.
- [ ] Limits and next action recorded.

**Time-box advice:** Specify the MVP flow first; do not design detailed tests for features not selected.
