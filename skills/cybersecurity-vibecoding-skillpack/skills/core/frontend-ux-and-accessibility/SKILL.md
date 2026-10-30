---
name: frontend-ux-and-accessibility
description: Make the main workflow clear, responsive, accessible and truthful about system behavior.
triggers:
  - UI change or interaction failure
  - Dashboard needs clear loading/error states
---

# Frontend UX and Accessibility

## Purpose
Make the main workflow clear, responsive, accessible and truthful about system behavior.

## Use When
- UI change or interaction failure
- Dashboard needs clear loading/error states

## Do Not Load When
- Backend-only change with no UI/consumer impact.

## Required Context and Prerequisites
Task brief, project instructions and the code touched. Active testing needs written scope and stop conditions first. See `instructions/COMMON_SKILL_RULES.md`.

## First 5-Minute Actions
Trace one visible action to its actual result and identify missing or misleading states.

## Procedure
1. Map primary tasks, navigation, hierarchy and recovery paths.
2. Reuse existing design tokens/components and avoid redesigning unrelated modules.
3. Add loading, empty, success, partial, error and disabled states when applicable.
4. Provide keyboard access, focus indication, semantic labels, contrast and responsive layout.
5. Wire every control to behavior or label it mock/demo; validate data origin.
6. Check multiple viewport sizes and console/network errors.

## Decision Rules and Stop Conditions
Visual polish cannot compensate for incorrect data. Animation must not hide status or harm accessibility.

## Tooling and Fallbacks
Use existing tooling and offline fixtures first. If something is unavailable, take the simplest credible fallback and say what it cannot verify (`instructions/COMMON_SKILL_RULES.md`).

## Implementation Patterns / Examples
Acknowledge succeeds visually only after the API confirms; failure displays a retryable message.

## Verification and Acceptance Criteria
Core path works without a mouse, labels match actions, and UI surfaces backend errors accurately.

Label evidence as reviewed, generated, mocked or executed, and record exact commands and outcomes (`instructions/COMMON_SKILL_RULES.md`, Evidence).

## Failure Modes and Troubleshooting
Decorative buttons, fake live indicators, inaccessible dialogs, stale component state, unreadable contrast.

On failure keep the error and identify its layer; after two similar failures change method or stop (`instructions/COMMON_SKILL_RULES.md`, Failure).

## Outputs to Record
Flow sketch, UI changes, accessibility checks, viewport/browser results.

Record evidence compactly (source, command, fact, interpretation, confidence, limit); redact secrets and personal data.

## Related Skills and Activation Triggers
requirements-and-acceptance; backend-api-and-data; testing-and-verification.

Load a related skill only when its trigger is observed and it changes the next action.

## Completion Checklist
- [ ] Trigger matches; scope and assumptions recorded.
- [ ] Smallest workflow run; claims tied to evidence.
- [ ] Checks run, or skipped ones labeled.
- [ ] Limits and next action recorded.

**Time-box advice:** Correctness and functional states first; animation/polish after.
