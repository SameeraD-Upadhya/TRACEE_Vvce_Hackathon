---
name: testing-and-verification
description: Verify behavior and report exactly what passed, failed, was blocked or was not run.
triggers:
  - Change needs proof or demo confidence
  - Tests are missing, flaky or failing
---

# Testing and Verification

## Purpose
Verify behavior and report exactly what passed, failed, was blocked or was not run.

## Use When
- Change needs proof or demo confidence
- Tests are missing, flaky or failing

## Do Not Load When
- Pure brainstorming with no implementation/result claim yet.

## Required Context and Prerequisites
Task brief, project instructions and the code touched. Active testing needs written scope and stop conditions first. See `instructions/COMMON_SKILL_RULES.md`.

## First 5-Minute Actions
Select and run the smallest test for the main acceptance criterion.

## Procedure
1. Map requirements to unit, integration, UI, security or manual checks.
2. Verify setup prerequisites before blaming code for an environment failure.
3. Cover normal, invalid, boundary, failure and persistence states where relevant.
4. Record exact command, exit status and useful output; distinguish review from execution.
5. Run broader checks if time permits and inspect tests for weakened assertions.
6. Add negative tests for security-relevant behavior (denied role, malformed input, over-limit request) and keep them with the fix (security-testing-and-adversarial-validation); treat a flaky test as a defect to diagnose, not a reason to rerun until green.

## Decision Rules and Stop Conditions
A skipped test is not passed; static review is not execution; mock responses do not verify a live service.

## Tooling and Fallbacks
Use existing tooling and offline fixtures first. If something is unavailable, take the simplest credible fallback and say what it cannot verify (`instructions/COMMON_SKILL_RULES.md`).

## Implementation Patterns / Examples
Test duplicate fixture ingestion, malformed input rejection and persistence across refresh separately.

## Verification and Acceptance Criteria
Claims match executed evidence; each blocked check has a reason and fallback.

Label evidence as reviewed, generated, mocked or executed, and record exact commands and outcomes (`instructions/COMMON_SKILL_RULES.md`, Evidence).

## Failure Modes and Troubleshooting
Deleting failing tests, nondeterministic fixtures, unbounded retries, claiming whole-system validity from one unit test.

On failure keep the error and identify its layer; after two similar failures change method or stop (`instructions/COMMON_SKILL_RULES.md`, Failure).

## Outputs to Record
Test matrix, commands/results, failures, skipped checks and residual risk.

Record evidence compactly (source, command, fact, interpretation, confidence, limit); redact secrets and personal data.

## Related Skills and Activation Triggers
requirements-and-acceptance; debugging-and-root-cause; release-and-packaging; security-testing-and-adversarial-validation.

Load a related skill only when its trigger is observed and it changes the next action.

## Completion Checklist
- [ ] Trigger matches; scope and assumptions recorded.
- [ ] Smallest workflow run; claims tied to evidence.
- [ ] Checks run, or skipped ones labeled.
- [ ] Limits and next action recorded.

**Time-box advice:** Run targeted test first, relevant suite next, full suite when feasible.
