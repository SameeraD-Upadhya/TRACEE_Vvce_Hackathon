---
name: secrets-and-audit-logging
description: Keep credentials out of code, logs and packages, and produce audit logs that are useful, free of sensitive values and tamper-evident where required.
triggers:
  - The product uses API keys, tokens, passwords or certificates, or a secret may have leaked
  - The product must record who did what (admin actions, data access, case or response changes) with evidence integrity
---

# Secrets and Audit Logging

## Purpose
Handle credentials and keys safely across code, configuration, CI and runtime, and produce audit logs that are useful, free of sensitive values and tamper-evident where required.

## Use When
- The product uses API keys, tokens, passwords, certificates or signing keys
- Admin, data-access, alert, case or response actions must be attributable
- Log shipping, retention or evidence integrity matters
- A secret may have been committed, printed or packaged

## Do Not Load When
- Static content with no credentials and no actions to audit

## Required Context and Prerequisites
The repository and its history, configuration and CI files, the runtime environment, and which actions need attribution. Use test credentials only.

## First 5-Minute Actions
List secrets by name and consumer (never values); scan the tree and package for exposed ones.

## Procedure
1. Inventory secrets and consumers (code, environment, CI, containers, third parties); search the tree and history with an available scanner or pattern check.
2. Remove secrets from source and images: read from environment or a secret store, commit `.env.example` with placeholders only, and exclude real env files from version control and archives.
3. If a secret was exposed, treat it as compromised: revoke and rotate first, then clean up; history rewriting alone is not a fix. Note the event without the value.
4. Define the audit event schema: UTC timestamp, actor, action, object, result, source (address or session) and correlation id. Never log passwords, tokens, keys or raw sensitive payloads.
5. Write audit events from server-side code at the point of decision, including denials and failures; give the application role append-only access.
6. Where tamper evidence is required, chain entries (each stores the hash of the previous) or ship to a separate write-only store; verify with a script and document that this detects, not prevents, modification by a privileged attacker.
7. Test: no secret in tree, logs or package; denials are logged; newline injection in logged input is neutralized; the chain check fails on an altered entry.

## Decision Rules and Stop Conditions
- Never commit real secrets, even for demos; never print them in terminal output or reports (mask all but at most the last four characters).
- Do not disable authentication or TLS, or place secrets in URLs, to make something work.
- The audit log is a security control: separate from debug logs, access-controlled, with bounded retention.
- Stop and ask the owner before rotating or revoking a credential on a production system.

## Tooling and Fallbacks
Use existing tooling and offline fixtures first. If something is unavailable, take the simplest credible fallback and say what it cannot verify (`instructions/COMMON_SKILL_RULES.md`).

## Implementation Patterns / Examples
Hash chain: `entry_hash = SHA-256(prev_hash + canonical_json(entry))`, with canonical JSON via sorted keys and compact separators; verification recomputes from the first entry and reports the first mismatch. Log shape: `{ts, actor, action, object, result, src, corr_id}`.

## Verification and Acceptance Criteria
Secret scan of tree and package is clean (or its exact limits are recorded); audit entries exist for success and denial; chain verification passes on an intact fixture and fails on a tampered one; no sensitive values appear in sampled logs.

## Failure Modes and Troubleshooting
Secrets in git history or container layers; tokens in logs or error pages; unbounded log growth; only successes logged; clock skew; log injection; a chain the application account can silently rewrite.

## Outputs to Record
Secret inventory (names only), rotation status, audit schema, verification commands and results, retention note.

## Related Skills and Activation Triggers
privacy-and-data-protection; identity-session-and-access-control; cloud-container-and-devsecops; deployment-and-environment; incident-response-and-dfir.

## Completion Checklist
- [ ] Trigger matches; scope and assumptions recorded.
- [ ] Smallest workflow run; claims tied to evidence.
- [ ] Checks run, or skipped ones labeled.
- [ ] Limits and next action recorded.

**Time-box advice:** Fix exposure first (rotate), then add the audit trail; do not log to prove diligence without testing the log.
