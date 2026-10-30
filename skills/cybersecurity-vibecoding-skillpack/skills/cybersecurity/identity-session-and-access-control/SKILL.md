---
name: identity-session-and-access-control
description: Evaluate authentication, sessions, roles and object-level/tenant authorization.
triggers:
  - Login, tokens/cookies, roles, permissions or tenant isolation
  - Possible IDOR/BOLA or privilege escalation
---

# Identity, Sessions and Access Control

## Purpose
Evaluate authentication, sessions, roles and object-level/tenant authorization.

## Use When
- Login, tokens/cookies, roles, permissions or tenant isolation
- Possible IDOR/BOLA or privilege escalation

## Do Not Load When
- No identity/permission boundary in the relevant path.

## Required Context and Prerequisites
Task brief, project instructions and the code touched. Active testing needs written scope and stop conditions first. See `instructions/COMMON_SKILL_RULES.md`.

## First 5-Minute Actions
Role matrix, seeded accounts, session lifecycle, protected routes/objects and policies.

## Procedure
1. Create an action × role × resource matrix and choose one allowed and one denied test.
2. Check credential handling: vetted slow password hashing, no secrets in URLs or logs, rate limiting and backoff without account enumeration.
3. Review sessions and tokens: unguessable identifiers, Secure/HttpOnly/SameSite cookies or equivalent, short expiry, server-side invalidation on logout and password change, rotation after login.
4. Test cross-user and cross-tenant object access, role escalation and unauthenticated paths with test accounts; confirm the status code of every denial.
5. Add each denial case as an automated regression test and record the permission matrix.

## Decision Rules and Stop Conditions
- Trace login, token/session storage, renewal, expiry, logout and invalidation.
- Check access on the server at object and action level, not only at route/UI level.
- Test least privilege and cross-user/tenant isolation with authorized test identities.
- Check privileged actions and errors for unintended data disclosure without account enumeration.
- Add negative regression checks for each permission invariant.

## Tooling and Fallbacks
Use existing tooling and offline fixtures first. If something is unavailable, take the simplest credible fallback and say what it cannot verify (`instructions/COMMON_SKILL_RULES.md`).

## Implementation Patterns / Examples
Authentication establishes identity; authorization decides permitted actions. Never use stolen or third-party credentials. A seeded role A cannot read or change role B’s seeded case even when the record ID is changed.

## Verification and Acceptance Criteria
Every sensitive action has a server-side policy and allowed/denied test.

Label evidence as reviewed, generated, mocked or executed, and record exact commands and outcomes (`instructions/COMMON_SKILL_RULES.md`, Evidence).

## Failure Modes and Troubleshooting
Hidden UI mistaken for security, happy-path-only login tests, tokens in logs, weak logout invalidation.

On failure keep the error and identify its layer; after two similar failures change method or stop (`instructions/COMMON_SKILL_RULES.md`, Failure).

## Outputs to Record
Role/action matrix, boundary evidence, patch and tests.

Record evidence compactly (source, command, fact, interpretation, confidence, limit); redact secrets and personal data.

## Related Skills and Activation Triggers
web-and-api-security; secure-coding-and-code-review; privacy-and-data-protection; secrets-and-audit-logging; security-testing-and-adversarial-validation.

Load a related skill only when its trigger is observed and it changes the next action.

## Completion Checklist
- [ ] Trigger matches; scope and assumptions recorded.
- [ ] Smallest workflow run; claims tied to evidence.
- [ ] Checks run, or skipped ones labeled.
- [ ] Limits and next action recorded.

**Time-box advice:** Prioritize object-level authorization and privilege-changing actions before cosmetic login work.
