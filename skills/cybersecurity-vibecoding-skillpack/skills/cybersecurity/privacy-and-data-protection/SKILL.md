---
name: privacy-and-data-protection
description: Minimize, secure, retain and redact sensitive data across input, logs, AI, exports and reports.
triggers:
  - Personal/case-sensitive data handled
  - Telemetry or AI/export paths may disclose sensitive fields
---

# Privacy and Data Protection

## Purpose
Minimize, secure, retain and redact sensitive data across input, logs, AI, exports and reports.

## Use When
- Personal/case-sensitive data handled
- Telemetry or AI/export paths may disclose sensitive fields

## Do Not Load When
- Only synthetic nonsensitive data with no privacy boundary.

## Required Context and Prerequisites
Task brief, project instructions and the code touched. Active testing needs written scope and stop conditions first. See `instructions/COMMON_SKILL_RULES.md`.

## First 5-Minute Actions
Data inventory, purpose, roles, storage, external processors, retention and local policy.

## Procedure
1. Map fields and decide which are necessary for the stated task.
2. Classify data (public, internal, personal, sensitive) and apply controls per class: encryption in transit and at rest, access roles, retention, deletion.
3. Keep personal data out of logs and errors by design (allowlisted fields, masked identifiers); use synthetic data for demos and tests.
4. Provide the user-facing basics where relevant: purpose notice, consent or lawful-basis note, export and deletion path.
5. Record data flows and third-party processors; flag where legal review is needed instead of asserting compliance.

## Decision Rules and Stop Conditions
- Define purpose, minimum collection, access roles, retention and deletion requirements.
- Redact secrets/identifiers from logs, screenshots, samples and reports unless explicitly needed.
- Check read/write/export boundaries and privileged access audit.
- Review external API/LLM transmission, backups and telemetry for unintended disclosure.
- Use synthetic fixtures for development and test deletion/retention safely.
- Record privacy risks and legal reviews still required.

## Tooling and Fallbacks
Use existing tooling and offline fixtures first. If something is unavailable, take the simplest credible fallback and say what it cannot verify (`instructions/COMMON_SKILL_RULES.md`).

## Implementation Patterns / Examples
Do not treat a checklist as legal compliance certification. Avoid placing real personal data in development/test tools unnecessarily. Use stable pseudonymous case identifiers and evidence references while redacting irrelevant personal details.

## Verification and Acceptance Criteria
Data movement/access are documented, unnecessary fields are removed and required deletion/retention is tested.

Label evidence as reviewed, generated, mocked or executed, and record exact commands and outcomes (`instructions/COMMON_SKILL_RULES.md`, Evidence).

## Failure Modes and Troubleshooting
Secrets in logs, overcollection, cross-tenant export, unreviewed model transmission, indefinite retention.

On failure keep the error and identify its layer; after two similar failures change method or stop (`instructions/COMMON_SKILL_RULES.md`, Failure).

## Outputs to Record
Data inventory, redaction/access rules, relevant tests and residual privacy concerns.

Record evidence compactly (source, command, fact, interpretation, confidence, limit); redact secrets and personal data.

## Related Skills and Activation Triggers
identity-session-and-access-control; ai-llm-and-agent-security; security-reporting-and-remediation; secrets-and-audit-logging.

Load a related skill only when its trigger is observed and it changes the next action.

## Completion Checklist
- [ ] Trigger matches; scope and assumptions recorded.
- [ ] Smallest workflow run; claims tied to evidence.
- [ ] Checks run, or skipped ones labeled.
- [ ] Limits and next action recorded.

**Time-box advice:** Resolve the highest-risk disclosure path first.
