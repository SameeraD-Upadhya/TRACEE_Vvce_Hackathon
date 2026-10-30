---
name: deployment-and-environment
description: Make startup, configuration and runtime behavior reproducible and safe.
triggers:
  - Fails on another machine or clean shell
  - Release/demo requires environment setup
---

# Deployment and Runtime Environment

## Purpose
Make startup, configuration and runtime behavior reproducible and safe.

## Use When
- Fails on another machine or clean shell
- Release/demo requires environment setup

## Do Not Load When
- No execution or deployment environment is part of the task.

## Required Context and Prerequisites
Task brief, project instructions and the code touched. Active testing needs written scope and stop conditions first. See `instructions/COMMON_SKILL_RULES.md`.

## First 5-Minute Actions
Runtime, lockfiles, scripts, env samples, service dependencies, target platform and ports. Run the documented startup path in a clean shell and capture the first real failure.

## Procedure
1. Confirm runtime/package manager from repository evidence.
2. Document config with placeholders and validate required values without printing secrets.
3. Use least-privilege credentials, explicit timeouts and bounded shutdown.
4. Add readiness checks only for real dependencies; document migration/rollback steps if relevant.
5. Reproduce setup and exercise one health or functional path.
6. Validate configuration at startup, commit `.env.example` with placeholders only, add a health check and a rollback step, and handle secrets per secrets-and-audit-logging.

## Decision Rules and Stop Conditions
Do not upgrade all dependencies to solve one startup problem. Local run is not proof of production deployment.

## Tooling and Fallbacks
Use existing tooling and offline fixtures first. If something is unavailable, take the simplest credible fallback and say what it cannot verify (`instructions/COMMON_SKILL_RULES.md`).

## Implementation Patterns / Examples
Check runtime versions and existing lockfiles; use local fixtures if external services are unavailable. A database error should name the missing setting/service but never print the connection string.

## Verification and Acceptance Criteria
Startup docs match actual scripts; configuration failures are actionable and safe.

Label evidence as reviewed, generated, mocked or executed, and record exact commands and outcomes (`instructions/COMMON_SKILL_RULES.md`, Evidence).

## Failure Modes and Troubleshooting
Hidden manual steps, unpinned dependencies, hard-coded local ports, leaked keys, false deployment claims.

On failure keep the error and identify its layer; after two similar failures change method or stop (`instructions/COMMON_SKILL_RULES.md`, Failure).

## Outputs to Record
Environment matrix, commands, safe config sample, outcomes and rollback/limitations.

Record evidence compactly (source, command, fact, interpretation, confidence, limit); redact secrets and personal data.

## Related Skills and Activation Triggers
dependency-and-supply-chain; release-and-packaging; testing-and-verification; secrets-and-audit-logging.

Load a related skill only when its trigger is observed and it changes the next action.

## Completion Checklist
- [ ] Trigger matches; scope and assumptions recorded.
- [ ] Smallest workflow run; claims tied to evidence.
- [ ] Checks run, or skipped ones labeled.
- [ ] Limits and next action recorded.

**Time-box advice:** Reproduce the basic environment before pursuing advanced deployment automation.
