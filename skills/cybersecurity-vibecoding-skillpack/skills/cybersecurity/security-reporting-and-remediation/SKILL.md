---
name: security-reporting-and-remediation
description: Create actionable, reproducible findings with evidence, proportional impact and tested fixes.
triggers:
  - Security finding needs reporting or prioritization
  - Fix needs independent retest
---

# Security Reporting and Remediation

## Purpose
Create actionable, reproducible findings with evidence, proportional impact and tested fixes.

## Use When
- Security finding needs reporting or prioritization
- Fix needs independent retest

## Do Not Load When
- No reportable finding exists.

## Required Context and Prerequisites
Task brief, project instructions and the code touched. Active testing needs written scope and stop conditions first. See `instructions/COMMON_SKILL_RULES.md`.

## First 5-Minute Actions
Scope, affected version, reproduction, evidence, impact context and remediation constraints.

## Procedure
1. Summarize the finding in one sentence and attach strongest reproducible evidence.
2. Rate severity with the agreed scheme (CVSS or a documented impact-by-likelihood matrix) and state the inputs.
3. Write reproduction steps a developer can follow in minutes, with expected versus actual behavior and minimal evidence.
4. Pair each finding with a fix, owner and retest condition; keep the executive summary to risk and decisions.
5. Follow the scope owner's disclosure process; do not publish details of unfixed issues beyond the agreed audience.

## Decision Rules and Stop Conditions
- Record scope, preconditions, affected component/version and reproduction steps.
- Separate direct observation from inferred impact and state assumptions.
- Prioritize by impact, exploitability, exposure and data sensitivity under the agreed scheme.
- Recommend a concrete minimal fix plus regression check.
- Redact secrets and unrelated personal data.
- Retest and label fixed/mitigated/accepted/unresolved/not retested with evidence.

## Tooling and Fallbacks
Use existing tooling and offline fixtures first. If something is unavailable, take the simplest credible fallback and say what it cannot verify (`instructions/COMMON_SKILL_RULES.md`).

## Implementation Patterns / Examples
Scanner output or suspicious patterns are not proof alone. Avoid “fully secure” claims and unsupported severity precision. When reachability is unverified, say “potentially unsafe; reachability not verified” rather than assert exploitability.

## Verification and Acceptance Criteria
Engineers can reproduce and understand the fix; confidence matches evidence.

Label evidence as reviewed, generated, mocked or executed, and record exact commands and outcomes (`instructions/COMMON_SKILL_RULES.md`, Evidence).

## Failure Modes and Troubleshooting
Missing preconditions, inflated impact, no retest, leaked sensitive payloads, duplicate findings.

On failure keep the error and identify its layer; after two similar failures change method or stop (`instructions/COMMON_SKILL_RULES.md`, Failure).

## Outputs to Record
Finding, evidence links, remediation owner/status, retest and residual limits.

Record evidence compactly (source, command, fact, interpretation, confidence, limit); redact secrets and personal data.

## Related Skills and Activation Triggers
vulnerability-assessment-authorized; secure-coding-and-code-review; documentation-and-handoff; threat-intelligence-and-risk-prioritization.

Load a related skill only when its trigger is observed and it changes the next action.

## Completion Checklist
- [ ] Trigger matches; scope and assumptions recorded.
- [ ] Smallest workflow run; claims tied to evidence.
- [ ] Checks run, or skipped ones labeled.
- [ ] Limits and next action recorded.

**Time-box advice:** Report highest-impact confirmed findings first; isolate speculation as hardening advice.
