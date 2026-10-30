---
name: coding-and-integration
description: Implement small coherent changes and connect components early.
triggers:
  - Changes span multiple modules
  - Existing pieces are implemented but disconnected
---

# Incremental Coding and Integration

## Purpose
Implement small coherent changes and connect components early.

## Use When
- Changes span multiple modules
- Existing pieces are implemented but disconnected

## Do Not Load When
- Read-only analysis with no code change requested.

## Required Context and Prerequisites
Task brief, project instructions and the code touched. Active testing needs written scope and stop conditions first. See `instructions/COMMON_SKILL_RULES.md`.

## First 5-Minute Actions
Implement a thin input-to-output path with one representative fixture.

## Procedure
1. Make one coherent change tied to an acceptance criterion.
2. Validate at boundaries and make success/error paths explicit.
3. Integrate adjacent pieces immediately instead of stacking disconnected code.
4. Run targeted checks after each meaningful milestone and inspect the diff.
5. Remove temporary mocks or label them before claiming completion.
6. Prove each boundary (interface, API, store) with one real call before polishing; never mask an integration failure with a hard-coded success value.

## Decision Rules and Stop Conditions
Avoid replacing whole files unnecessarily; preserve uncommitted changes and align IDs, data types and status semantics across layers.

## Tooling and Fallbacks
Use existing tooling and offline fixtures first. If something is unavailable, take the simplest credible fallback and say what it cannot verify (`instructions/COMMON_SKILL_RULES.md`).

## Implementation Patterns / Examples
Wire UI submit → validated API → persisted record → refreshed list; test a failed API response before adding bulk actions.

## Verification and Acceptance Criteria
Data and identifiers agree end-to-end; no dead handler or fake-success state remains.

Label evidence as reviewed, generated, mocked or executed, and record exact commands and outcomes (`instructions/COMMON_SKILL_RULES.md`, Evidence).

## Failure Modes and Troubleshooting
Opaque rewrites, swallowed errors, changed contracts with stale callers, deferred integration.

On failure keep the error and identify its layer; after two similar failures change method or stop (`instructions/COMMON_SKILL_RULES.md`, Failure).

## Outputs to Record
Patch, integration notes, commands/results and blocker notes.

Record evidence compactly (source, command, fact, interpretation, confidence, limit); redact secrets and personal data.

## Related Skills and Activation Triggers
architecture-and-mvp; debugging-and-root-cause; testing-and-verification.

Load a related skill only when its trigger is observed and it changes the next action.

## Completion Checklist
- [ ] Trigger matches; scope and assumptions recorded.
- [ ] Smallest workflow run; claims tied to evidence.
- [ ] Checks run, or skipped ones labeled.
- [ ] Limits and next action recorded.

**Time-box advice:** Prove the smallest path before expanding surface area.
