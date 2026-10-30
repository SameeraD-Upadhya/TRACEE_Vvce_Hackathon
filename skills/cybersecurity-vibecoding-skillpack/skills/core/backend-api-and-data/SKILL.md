---
name: backend-api-and-data
description: Build APIs and persistence with validated schemas, consistent semantics and explicit failures.
triggers:
  - UI needs real APIs/storage
  - Records are duplicated, stale, lost or inconsistent
---

# Backend API and Data Design

## Purpose
Build APIs and persistence with validated schemas, consistent semantics and explicit failures.

## Use When
- UI needs real APIs/storage
- Records are duplicated, stale, lost or inconsistent

## Do Not Load When
- Explicit frontend-only prototype with no backend acceptance requirement.

## Required Context and Prerequisites
Task brief, project instructions and the code touched. Active testing needs written scope and stop conditions first. See `instructions/COMMON_SKILL_RULES.md`.

## First 5-Minute Actions
Trace a representative request from validated input to write and subsequent read.

## Procedure
1. Define request/response schema and reject invalid or oversized input.
2. Use stable IDs, bounded collection responses and consistent error semantics.
3. Make writes idempotent/transactional where supported; prevent duplicate retries.
4. Handle connection failures, timeouts, unavailable services and schema drift.
5. Enforce authorization server-side and test read/write behavior after refresh/restart.

## Decision Rules and Stop Conditions
Do not expose secrets/stack traces; never return success if the persistence operation failed. Use only transaction guarantees supported by the actual store.

## Tooling and Fallbacks
Use existing tooling and offline fixtures first. If something is unavailable, take the simplest credible fallback and say what it cannot verify (`instructions/COMMON_SKILL_RULES.md`).

## Implementation Patterns / Examples
Use source event IDs or a justified key for deduplicating alerts; do not compare display strings alone.

## Verification and Acceptance Criteria
Input rejection is predictable, claimed persistence is durable and sensitive actions are server-authorized.

Label evidence as reviewed, generated, mocked or executed, and record exact commands and outcomes (`instructions/COMMON_SKILL_RULES.md`, Evidence).

## Failure Modes and Troubleshooting
Schema mismatch, uncontrolled collection endpoints, duplicate writes, swallowed exceptions, unsafe resets.

On failure keep the error and identify its layer; after two similar failures change method or stop (`instructions/COMMON_SKILL_RULES.md`, Failure).

## Outputs to Record
API contract, schema notes, error behavior and integration tests.

Record evidence compactly (source, command, fact, interpretation, confidence, limit); redact secrets and personal data.

## Related Skills and Activation Triggers
architecture-and-mvp; identity-session-and-access-control; testing-and-verification.

Load a related skill only when its trigger is observed and it changes the next action.

## Completion Checklist
- [ ] Trigger matches; scope and assumptions recorded.
- [ ] Smallest workflow run; claims tied to evidence.
- [ ] Checks run, or skipped ones labeled.
- [ ] Limits and next action recorded.

**Time-box advice:** Build one route and one persistent entity before a broad CRUD surface.
