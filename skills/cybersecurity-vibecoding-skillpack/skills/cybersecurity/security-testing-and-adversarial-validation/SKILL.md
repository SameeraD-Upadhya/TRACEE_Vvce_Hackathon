---
name: security-testing-and-adversarial-validation
description: Turn threats and vulnerabilities into repeatable negative, abuse-case, regression and adversarial tests that prove controls work.
triggers:
  - A security fix needs a regression test, or authorization, validation, rate-limit or detection claims must be verified
  - Parsers, uploads or LLM features need adversarial or malformed-input cases before a demo or release
---

# Security Testing and Adversarial Validation

## Purpose
Convert threats, vulnerabilities and detection claims into repeatable negative, abuse-case, regression and adversarial tests that prove controls work and keep working.

## Use When
- A vulnerability fix needs a regression test
- Authorization, validation, rate-limit, session or detection claims must be verified
- Parsers, uploads or LLM features need malformed or adversarial inputs
- Security claims are about to be made in a demo, report or release

## Do Not Load When
- Ordinary functional testing with no security property (use testing-and-verification)
- The target is outside authorized scope

## Required Context and Prerequisites
The property to prove (from a threat model, finding or requirement), a local or disposable instance, synthetic users and data, and the project's test runner.

## First 5-Minute Actions
Write the list of security properties in plain sentences, each with an allowed case and a denied case.

## Procedure
1. List the properties to prove, for example: user A cannot read user B's record; invalid or expired tokens are rejected; over-limit uploads are refused; a rule fires on the malicious fixture and not on the benign one.
2. For each property write a test pair: an allowed case that passes and a denied or malicious case that must fail safely. Run against current code first to see the failure when the weakness exists.
3. Build synthetic fixtures: roles and tenants, malformed and oversized inputs, boundary values, replayed or expired tokens. For parsers add a bounded property or fuzz test with a fixed seed. For LLM features use an injection corpus and assert on side effects (tool not called, data not leaked), not on wording.
4. Run only against a local or disposable instance within authorized scope; cap rate and duration.
5. Fix at the boundary, rerun the whole security set, confirm no test was weakened or skipped, and commit the tests with the fix.
6. Wire the set into the project's normal test command or CI; record command and results and list the properties not covered.

## Decision Rules and Stop Conditions
- A test that cannot fail proves nothing: see it fail first, or briefly break the control in a throwaway copy.
- Never edit expectations to hide a failure; a flaky security test is a defect to fix (seed, timing), not to ignore.
- Tests contain no real secrets and never touch third-party systems.
- Detection results are counts on the fixture, not general accuracy claims.

## Tooling and Fallbacks
Use existing tooling and offline fixtures first. If something is unavailable, take the simplest credible fallback and say what it cannot verify (`instructions/COMMON_SKILL_RULES.md`).

## Implementation Patterns / Examples
Parametrize authorization as a table of (role, resource owner, action, expected status). Parser property: for 1000 random inputs up to 1 MB with seed 1, `parse` returns a result or a typed error and never an uncaught exception or unbounded memory use.

## Verification and Acceptance Criteria
Each property has an allowed and a denied test; at least one test was observed failing before the fix or on a mutated control; commands and outcomes are recorded; skipped or blocked tests are listed.

## Failure Modes and Troubleshooting
Only happy-path tests; asserting a status code but not the response body or side effect; UI-only checks; shared state between tests; timing-dependent rate-limit tests; unbounded fuzzing.

## Outputs to Record
Property list, test files, exact commands and results, coverage gaps.

## Related Skills and Activation Triggers
testing-and-verification; web-and-api-security; identity-session-and-access-control; secure-coding-and-code-review; ai-llm-and-agent-security; threat-modeling-and-abuse-cases.

## Completion Checklist
- [ ] Trigger matches; scope and assumptions recorded.
- [ ] Smallest workflow run; claims tied to evidence.
- [ ] Checks run, or skipped ones labeled.
- [ ] Limits and next action recorded.

**Time-box advice:** Write the denied-case test first; it is the one that protects the product.
