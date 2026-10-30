---
name: secure-coding-and-code-review
description: Find reachable security-sensitive code paths and recommend minimal, behavior-preserving fixes.
triggers:
  - Source code/diff is available for security review
  - Files, secrets, queries, commands or untrusted inputs cross boundaries
---

# Secure Coding and Code Review

## Purpose
Find reachable security-sensitive code paths and recommend minimal, behavior-preserving fixes.

## Use When
- Source code/diff is available for security review
- Files, secrets, queries, commands or untrusted inputs cross boundaries

## Do Not Load When
- Source unavailable and only dynamic behavior can be examined.

## Required Context and Prerequisites
Task brief, project instructions and the code touched. Active testing needs written scope and stop conditions first. See `instructions/COMMON_SKILL_RULES.md`.

## First 5-Minute Actions
Diff, framework, data flow, security invariants, tests and trust boundaries.

## Procedure
1. Trace one untrusted value to a sensitive sink and inspect validation/authorization along the path.
2. Review by sink class (SQL/NoSQL, OS command, path, template/HTML, deserialization, SSRF, crypto, authorization) and search for the dangerous APIs of the stack in use.
3. Prefer fixes at the boundary: parameterized queries, allowlist validation, output encoding, safe APIs, central authorization.
4. Write a failing regression test that reproduces the issue, then make it pass with the patch.
5. Run available SAST, linters and secret scanners as hints and verify each result manually before reporting.

## Decision Rules and Stop Conditions
- Review input parsing, query/command construction, path handling, deserialization, secret use and error behavior.
- Assess attacker control, reachability, preconditions, impact and existing mitigations.
- Separate confirmed issues from suspicious patterns and generic hardening suggestions.
- Patch the narrow cause and add a security regression check.
- Review neighboring call sites and inspect the final diff.

## Tooling and Fallbacks
Use existing tooling and offline fixtures first. If something is unavailable, take the simplest credible fallback and say what it cannot verify (`instructions/COMMON_SKILL_RULES.md`).

## Implementation Patterns / Examples
A dangerous API pattern alone does not prove an exploitable issue. Avoid broad rewrites driven by checklist items. Use parameterized queries and server-side access policy rather than relying on display escaping alone.

## Verification and Acceptance Criteria
Findings cite code/data-flow evidence, preconditions, impact, fix and verification or explicitly state the gap.

Label evidence as reviewed, generated, mocked or executed, and record exact commands and outcomes (`instructions/COMMON_SKILL_RULES.md`, Evidence).

## Failure Modes and Troubleshooting
Pattern-only false positives, semantic regressions, errors hidden, only one of several shared sinks fixed.

On failure keep the error and identify its layer; after two similar failures change method or stop (`instructions/COMMON_SKILL_RULES.md`, Failure).

## Outputs to Record
Prioritized review notes, minimal patch, regression tests and unresolved concerns.

Record evidence compactly (source, command, fact, interpretation, confidence, limit); redact secrets and personal data.

## Related Skills and Activation Triggers
web-and-api-security; dependency-and-supply-chain; testing-and-verification; threat-modeling-and-abuse-cases; security-testing-and-adversarial-validation.

Load a related skill only when its trigger is observed and it changes the next action.

## Completion Checklist
- [ ] Trigger matches; scope and assumptions recorded.
- [ ] Smallest workflow run; claims tied to evidence.
- [ ] Checks run, or skipped ones labeled.
- [ ] Limits and next action recorded.

**Time-box advice:** Review changed code and critical reachable paths first; do not claim the whole repo is secure after a short pass.
