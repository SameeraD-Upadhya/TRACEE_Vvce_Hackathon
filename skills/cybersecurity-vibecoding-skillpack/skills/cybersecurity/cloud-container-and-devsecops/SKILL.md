---
name: cloud-container-and-devsecops
description: Review cloud identities, container configuration, CI pipelines and release security.
triggers:
  - Cloud/IAM/container/CI/CD config in scope
  - Build pipeline needs security guardrails
---

# Cloud, Containers and DevSecOps

## Purpose
Review cloud identities, container configuration, CI pipelines and release security.

## Use When
- Cloud/IAM/container/CI/CD config in scope
- Build pipeline needs security guardrails

## Do Not Load When
- No deployment or cloud surface exists.

## Required Context and Prerequisites
Task brief, project instructions and the code touched. Active testing needs written scope and stop conditions first. See `instructions/COMMON_SKILL_RULES.md`.

## First 5-Minute Actions
Manifests, IAM, Dockerfiles, CI rules, registries, secret flows and allowed environment.

## Procedure
1. Inventory permissions and configuration before changing pipelines or cloud resources.
2. Review IaC, Dockerfiles and workflows statically first: pinned base images and actions, non-root user, no secrets in layers or logs, minimal token permissions.
3. Add a pipeline gate for a defined policy violation, with a passing and a failing fixture proving the gate fires.
4. Keep production credentials out of CI logs and forks; use short-lived scoped credentials where the platform supports them.
5. Build and run the artifact locally or in a disposable environment; document rollback.

## Decision Rules and Stop Conditions
- Review least privilege, public exposure, network rules, secrets, base images and container privileges.
- Check provenance, pinning and reproducibility assumptions for images/dependencies/actions.
- Review CI triggers, untrusted contributions, token scopes, artifacts and approval gates.
- Add policy/tests with clear failure messages and positive/negative config fixtures.
- Test locally and preserve rollback; do not mutate production resources without approval.

## Tooling and Fallbacks
Use existing tooling and offline fixtures first. If something is unavailable, take the simplest credible fallback and say what it cannot verify (`instructions/COMMON_SKILL_RULES.md`).

## Implementation Patterns / Examples
Do not deploy or alter cloud resources without explicit authority. Never print real secrets or paste tokens into issues/logs. A test flags privileged mode in a sample manifest; that is not proof the entire cloud estate is secure.

## Verification and Acceptance Criteria
Policy checks have positive/negative fixtures and the exact pipeline stage is documented.

Label evidence as reviewed, generated, mocked or executed, and record exact commands and outcomes (`instructions/COMMON_SKILL_RULES.md`, Evidence).

## Failure Modes and Troubleshooting
Overbroad IAM, unpinned dependencies, secrets in CI logs, scanner alerts without context.

On failure keep the error and identify its layer; after two similar failures change method or stop (`instructions/COMMON_SKILL_RULES.md`, Failure).

## Outputs to Record
Permission/config review, narrow patch, pipeline test results and residual risk.

Record evidence compactly (source, command, fact, interpretation, confidence, limit); redact secrets and personal data.

## Related Skills and Activation Triggers
dependency-and-supply-chain; deployment-and-environment; secure-coding-and-code-review; secrets-and-audit-logging.

Load a related skill only when its trigger is observed and it changes the next action.

## Completion Checklist
- [ ] Trigger matches; scope and assumptions recorded.
- [ ] Smallest workflow run; claims tied to evidence.
- [ ] Checks run, or skipped ones labeled.
- [ ] Limits and next action recorded.

**Time-box advice:** Review exposure and secret paths first; leave broad migrations for a controlled plan.
