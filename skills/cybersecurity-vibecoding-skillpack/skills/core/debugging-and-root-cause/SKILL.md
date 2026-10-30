---
name: debugging-and-root-cause
description: Use reproducible evidence and distinguishing experiments to locate failure causes.
triggers:
  - Reported bug or failed test
  - Frontend state differs from stored/backend state
---

# Debugging and Root Cause Analysis

## Purpose
Use reproducible evidence and distinguishing experiments to locate failure causes.

## Use When
- Reported bug or failed test
- Frontend state differs from stored/backend state

## Do Not Load When
- New feature with no observed malfunction.

## Required Context and Prerequisites
Task brief, project instructions and the code touched. Active testing needs written scope and stop conditions first. See `instructions/COMMON_SKILL_RULES.md`.

## First 5-Minute Actions
Create the smallest reproduction and locate the first divergence from expected behavior.

## Procedure
1. Record exact steps, environment and error before changing code.
2. Trace the value across UI, API, worker, storage and rendering boundaries as relevant.
3. List competing hypotheses and the experiment that distinguishes them.
4. Change one causal factor at a time and add a regression test.
5. Repeat the reproduction and nearby checks; inspect side effects in the diff.
6. Check the project notes for the same symptom first; afterward record root cause and the distinguishing test so it is not diagnosed twice.

## Decision Rules and Stop Conditions
Do not call a hypothesis a root cause until a distinguishing test supports it. After two similar failed attempts, change diagnostic method.

## Tooling and Fallbacks
Use existing tooling and offline fixtures first. If something is unavailable, take the simplest credible fallback and say what it cannot verify (`instructions/COMMON_SKILL_RULES.md`).

## Implementation Patterns / Examples
Test whether reset cleared actual persistence/worker state instead of only asserting that a widget visually emptied.

## Verification and Acceptance Criteria
The same reproduction fails before the change and passes after it; a regression test guards the behavior.

Label evidence as reviewed, generated, mocked or executed, and record exact commands and outcomes (`instructions/COMMON_SKILL_RULES.md`, Evidence).

## Failure Modes and Troubleshooting
Symptom-only UI patch, stale build artifact, swallowed exception, test that cannot reproduce bug.

On failure keep the error and identify its layer; after two similar failures change method or stop (`instructions/COMMON_SKILL_RULES.md`, Failure).

## Outputs to Record
Reproduction, evidence, confirmed cause or remaining hypotheses, patch and regression result.

Record evidence compactly (source, command, fact, interpretation, confidence, limit); redact secrets and personal data.

## Related Skills and Activation Triggers
repository-audit; testing-and-verification; backend-api-and-data.

Load a related skill only when its trigger is observed and it changes the next action.

## Completion Checklist
- [ ] Trigger matches; scope and assumptions recorded.
- [ ] Smallest workflow run; claims tied to evidence.
- [ ] Checks run, or skipped ones labeled.
- [ ] Limits and next action recorded.

**Time-box advice:** Run short diagnostic loops and prioritize the most consequential reproducible failure.
