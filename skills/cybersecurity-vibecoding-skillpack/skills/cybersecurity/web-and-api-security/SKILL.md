---
name: web-and-api-security
description: Review web/API trust boundaries, input handling and access controls within authorized scope.
triggers:
  - Web app, REST/GraphQL API or user-supplied endpoint
  - Scoped security verification is permitted
---

# Web Application and API Security

## Purpose
Review web/API trust boundaries, input handling and access controls within authorized scope.

## Use When
- Web app, REST/GraphQL API or user-supplied endpoint
- Scoped security verification is permitted

## Do Not Load When
- Offline-only evidence review with no web target.

## Required Context and Prerequisites
Task brief, project instructions and the code touched. Active testing needs written scope and stop conditions first. See `instructions/COMMON_SKILL_RULES.md`.

## First 5-Minute Actions
Confirm allowed hosts/methods/accounts and identify routes, inputs and protected objects.

## Procedure
1. Map inputs, parsing, output sinks, server-side fetches, uploads, session handling and trust boundaries.
2. Prioritize object authorization, injection, SSRF-like fetches, deserialization, CSRF/CORS and error leaks where relevant.
3. Use allowlisted test systems, low-rate bounded requests, timeouts, redirect checks and synthetic records.
4. Verify with minimal proof; avoid changing persistent state or reading unrelated records.
5. Patch the vulnerable boundary and add a regression test.

## Decision Rules and Stop Conditions
No explicit scope means no active requests. Server-side object/action authorization is required; UI hiding is not a control.

## Tooling and Fallbacks
Use existing tooling and offline fixtures first. If something is unavailable, take the simplest credible fallback and say what it cannot verify (`instructions/COMMON_SKILL_RULES.md`).

## Implementation Patterns / Examples
With two permitted test accounts, verify a user cannot access another seeded test record merely by changing its ID.

## Verification and Acceptance Criteria
A finding has reproducible evidence, preconditions, impact rationale and a remediation check.

Label evidence as reviewed, generated, mocked or executed, and record exact commands and outcomes (`instructions/COMMON_SKILL_RULES.md`, Evidence).

## Failure Modes and Troubleshooting
Scope drift, aggressive fuzzing, real personal data, scanner output treated as proof.

On failure keep the error and identify its layer; after two similar failures change method or stop (`instructions/COMMON_SKILL_RULES.md`, Failure).

## Outputs to Record
Route/data-flow inventory, scoped evidence, targeted fix and regression result.

Record evidence compactly (source, command, fact, interpretation, confidence, limit); redact secrets and personal data.

## Related Skills and Activation Triggers
identity-session-and-access-control; vulnerability-assessment-authorized; secure-coding-and-code-review; threat-modeling-and-abuse-cases; security-testing-and-adversarial-validation.

Load a related skill only when its trigger is observed and it changes the next action.

## Completion Checklist
- [ ] Trigger matches; scope and assumptions recorded.
- [ ] Smallest workflow run; claims tied to evidence.
- [ ] Checks run, or skipped ones labeled.
- [ ] Limits and next action recorded.

**Time-box advice:** Start with static review and a few high-impact boundaries, not broad fuzzing.
