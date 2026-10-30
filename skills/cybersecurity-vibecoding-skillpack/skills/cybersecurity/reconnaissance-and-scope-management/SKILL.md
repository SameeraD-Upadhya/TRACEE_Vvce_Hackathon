---
name: reconnaissance-and-scope-management
description: Bound asset collection to written authorization and keep passive observations distinct from active probes.
triggers:
  - Assessment needs asset map or targets
  - Redirects, wildcard domains or third parties could expand scope
---

# Reconnaissance and Scope Management

## Purpose
Bound asset collection to written authorization and keep passive observations distinct from active probes.

## Use When
- Assessment needs asset map or targets
- Redirects, wildcard domains or third parties could expand scope

## Do Not Load When
- No external asset collection is in scope.

## Required Context and Prerequisites
Task brief, project instructions and the code touched. Active testing needs written scope and stop conditions first. See `instructions/COMMON_SKILL_RULES.md`.

## First 5-Minute Actions
Authorization, approved roots, exclusions, allowed sources, window and rate limits.

## Procedure
1. Write explicit allowlist/exclusions and label planned activities passive or active.
2. Obtain the scope statement from the asset owner in writing (targets, dates, methods, contacts) and keep it with the evidence.
3. Start passive (public records, DNS, certificate transparency); use active methods only when the scope explicitly permits.
4. Log every request target and timestamp; stop and ask when a discovered asset is not on the allowlist.
5. Deliver an inventory with provenance and a list of out-of-scope observations left untouched.

## Decision Rules and Stop Conditions
- Normalize hostnames/URLs and interpret wildcard scope conservatively.
- Record provenance and timestamps for passive observations.
- Check each active method against approved scope before use.
- Re-check allowlist after redirects; cap crawl depth, duration, payload size and request rate.
- Stop when ownership or scope is uncertain; public reachability is not permission.

## Tooling and Fallbacks
Use existing tooling and offline fixtures first. If something is unavailable, take the simplest credible fallback and say what it cannot verify (`instructions/COMMON_SKILL_RULES.md`).

## Implementation Patterns / Examples
Do not expand to linked vendors, employees, adjacent networks or new domains without written inclusion. A third-party link discovered on an in-scope page is a dependency lead, not permission to test that service.

## Verification and Acceptance Criteria
Each asset has a source, time, scope decision and allowed next action.

Label evidence as reviewed, generated, mocked or executed, and record exact commands and outcomes (`instructions/COMMON_SKILL_RULES.md`, Evidence).

## Failure Modes and Troubleshooting
DNS discovery treated as authorization, wildcard guessing, redirect leaks, endless crawling.

On failure keep the error and identify its layer; after two similar failures change method or stop (`instructions/COMMON_SKILL_RULES.md`, Failure).

## Outputs to Record
Allowlist/exclusions, asset inventory, provenance, permitted plan and stop triggers.

Record evidence compactly (source, command, fact, interpretation, confidence, limit); redact secrets and personal data.

## Related Skills and Activation Triggers
vulnerability-assessment-authorized; osint-and-evidence-correlation; web-and-api-security.

Load a related skill only when its trigger is observed and it changes the next action.

## Completion Checklist
- [ ] Trigger matches; scope and assumptions recorded.
- [ ] Smallest workflow run; claims tied to evidence.
- [ ] Checks run, or skipped ones labeled.
- [ ] Limits and next action recorded.

**Time-box advice:** Set scope first and collect only what is needed for the stated objective.
