---
name: repository-audit
description: Establish the actual baseline and end-to-end feature state before changing an existing project.
triggers:
  - Unfamiliar or half-finished repository
  - Reported regressions, stale state, missing integration or uncertain feature claims
---

# Repository Audit

## Purpose
Establish the actual baseline and end-to-end feature state before changing an existing project.

## Use When
- Unfamiliar or half-finished repository
- Reported regressions, stale state, missing integration or uncertain feature claims

## Do Not Load When
- Empty new repository with no existing behavior to preserve.

## Required Context and Prerequisites
Task brief, project instructions and the code touched. Active testing needs written scope and stop conditions first. See `instructions/COMMON_SKILL_RULES.md`.

## First 5-Minute Actions
Record worktree state and inspect instructions, entry points and a key workflow read-only.

## Procedure
1. Inventory runtimes, manifests, scripts, routes, data stores, tests, CI and deployment configuration.
2. Trace input/UI → validation → logic → persistence → output/error handling.
3. Classify features as verified working, implemented unverified, partial, disconnected, missing, broken or N/A.
4. Separate confirmed defects from suspected causes and enhancement ideas.
5. Prioritize by impact, reproducibility, event relevance, effort and dependencies.
6. Run available tests, linters and secret scans read-only first and record which pass, fail or cannot run before proposing changes.

## Decision Rules and Stop Conditions
Do not reset, clean, mass-format or rewrite before understanding current local changes. Missing tests imply uncertainty, not automatically a bug.

## Tooling and Fallbacks
Use existing tooling and offline fixtures first. If something is unavailable, take the simplest credible fallback and say what it cannot verify (`instructions/COMMON_SKILL_RULES.md`).

## Implementation Patterns / Examples
For stale counters, trace their source of truth and reset path across UI, API, worker, cache and database.

## Verification and Acceptance Criteria
Findings cite paths or command evidence; implementation is not equated with working behavior.

Label evidence as reviewed, generated, mocked or executed, and record exact commands and outcomes (`instructions/COMMON_SKILL_RULES.md`, Evidence).

## Failure Modes and Troubleshooting
Trusting docs over code, inferring causes from symptoms, dumping huge search output, overwriting local edits.

On failure keep the error and identify its layer; after two similar failures change method or stop (`instructions/COMMON_SKILL_RULES.md`, Failure).

## Outputs to Record
Feature inventory, flow map, baseline results, ranked findings and patch boundaries.

Record evidence compactly (source, command, fact, interpretation, confidence, limit); redact secrets and personal data.

## Related Skills and Activation Triggers
debugging-and-root-cause; testing-and-verification; backend-api-and-data when relevant.

Load a related skill only when its trigger is observed and it changes the next action.

## Completion Checklist
- [ ] Trigger matches; scope and assumptions recorded.
- [ ] Smallest workflow run; claims tied to evidence.
- [ ] Checks run, or skipped ones labeled.
- [ ] Limits and next action recorded.

**Time-box advice:** Time-box inventory; trace the critical flow deeply rather than every file shallowly.
