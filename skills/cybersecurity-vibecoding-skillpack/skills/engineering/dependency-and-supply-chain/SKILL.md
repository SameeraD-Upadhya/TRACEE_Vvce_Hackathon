---
name: dependency-and-supply-chain
description: Review dependency provenance, versions, advisories and build inputs without blind upgrade churn.
triggers:
  - Manifest/lockfile/CI action may create risk
  - Release needs reproducibility or dependency review
---

# Dependency and Supply Chain Security

## Purpose
Review dependency provenance, versions, advisories and build inputs without blind upgrade churn.

## Use When
- Manifest/lockfile/CI action may create risk
- Release needs reproducibility or dependency review

## Do Not Load When
- No external package or build artifact is involved.

## Required Context and Prerequisites
Task brief, project instructions and the code touched. Active testing needs written scope and stop conditions first. See `instructions/COMMON_SKILL_RULES.md`.

## First 5-Minute Actions
Manifests/lockfiles, package manager, license rules, CI configuration and approved advisory sources.

## Procedure
1. Inventory direct/transitive dependencies and check lockfile consistency.
2. Generate or maintain an SBOM from lockfiles where tooling exists; record versions and hashes.
3. Before adding a dependency check for typosquats, abandonment, install scripts and unexpected maintainer changes.
4. Pin versions and verify integrity (lockfile hashes, image digests, pinned CI action commits).
5. Prefer removing an unused dependency over patching it.

## Decision Rules and Stop Conditions
- Check relevant advisories and support status using available trusted sources.
- Review package names, registry, install scripts, pinned actions/images and provenance.
- Assess reachability/exposure and prioritize contextualized findings.
- Prefer narrow updates with changelog/compatibility review; update lockfiles coherently.
- Run tests/build after changes and record offline or unavailable checks.
- Document accepted risk and review trigger when not fixed.

## Tooling and Fallbacks
Use existing tooling and offline fixtures first. If something is unavailable, take the simplest credible fallback and say what it cannot verify (`instructions/COMMON_SKILL_RULES.md`).

## Implementation Patterns / Examples
An advisory match does not itself prove reachability or exploitability. Avoid mass updates without a regression budget. A transitive vulnerable component in an unexposed test path differs from an exposed runtime path; document evidence and context.

## Verification and Acceptance Criteria
Dependencies remain reproducible, tests are run or blockers disclosed, licenses/provenance considered.

Label evidence as reviewed, generated, mocked or executed, and record exact commands and outcomes (`instructions/COMMON_SKILL_RULES.md`, Evidence).

## Failure Modes and Troubleshooting
Unreviewed bulk upgrades, stale lockfiles, untrusted install scripts, missing transitive context.

On failure keep the error and identify its layer; after two similar failures change method or stop (`instructions/COMMON_SKILL_RULES.md`, Failure).

## Outputs to Record
Dependency inventory, evidence, narrow patch, test results and caveats.

Record evidence compactly (source, command, fact, interpretation, confidence, limit); redact secrets and personal data.

## Related Skills and Activation Triggers
cloud-container-and-devsecops; deployment-and-environment; release-and-packaging; threat-intelligence-and-risk-prioritization.

Load a related skill only when its trigger is observed and it changes the next action.

## Completion Checklist
- [ ] Trigger matches; scope and assumptions recorded.
- [ ] Smallest workflow run; claims tied to evidence.
- [ ] Checks run, or skipped ones labeled.
- [ ] Limits and next action recorded.

**Time-box advice:** Prioritize exposed reachable runtime packages and fixes that can be retested.
