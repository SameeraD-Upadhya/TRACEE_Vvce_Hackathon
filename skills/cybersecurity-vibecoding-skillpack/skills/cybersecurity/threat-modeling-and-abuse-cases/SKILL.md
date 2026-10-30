---
name: threat-modeling-and-abuse-cases
description: Identify assets, trust boundaries and abuse cases early, rank the top risks, and turn them into controls and tests.
triggers:
  - New product, feature or architecture handles sensitive data, privileged actions, external input or AI tool use
  - A security rationale or risk-ranked review is needed instead of a generic checklist
---

# Threat Modeling and Abuse Cases

## Purpose
Identify assets, trust boundaries and abuse cases early enough to change the design, rank the top risks, and turn them into controls and tests.

## Use When
- A new product, feature or architecture handles sensitive data, privileged actions, external input, file handling or AI tool use
- A hackathon or review needs a defensible security rationale, not a generic checklist
- Automated, bulk, administrative or response actions are being added

## Do Not Load When
- A narrow bug fix changes no trust boundary
- The task is analysis of supplied evidence only (forensics, CTF)

## Required Context and Prerequisites
A system description or repository, the actor list (users, admins, services, outsiders), data classes and the deployment context. Unknown facts are recorded as assumptions, not invented.

## First 5-Minute Actions
Draw a text or Mermaid data-flow sketch: actors, processes, stores, external services and trust boundaries.

## Procedure
1. Define scope and assets (data, privileges, availability, reputation) and actors, including malicious users, compromised insiders and automated abusers.
2. Sketch data flows; mark trust boundaries and every entry point.
3. Enumerate threats per element with STRIDE (Spoofing, Tampering, Repudiation, Information disclosure, Denial of service, Elevation of privilege) and write abuse cases as "actor abuses capability to cause impact".
4. Rank by impact, likelihood and exposure on a stated scale; keep the top 5 to 10.
5. Assign each top risk a control (prevent, detect, respond or accept), an owner and a verification; put testable abuse cases into the test plan.
6. Revisit the model when architecture, data or exposure changes; record accepted risks with a review trigger.

## Decision Rules and Stop Conditions
- Model the system as built or planned, not an idealized version.
- Prefer controls that remove capability over controls that only detect misuse.
- High-risk functionality (bulk export, admin actions, automated response, uploads, code execution, AI tool calls) needs an explicit abuse case and control.
- A threat without a control or an accept decision is unfinished.
- STRIDE categories are prompts, not a quota; stop after the time box.

## Tooling and Fallbacks
Use existing tooling and offline fixtures first. If something is unavailable, take the simplest credible fallback and say what it cannot verify (`instructions/COMMON_SKILL_RULES.md`).

## Implementation Patterns / Examples
File upload: abuse cases are oversized or compressed-bomb files, path tricks in filenames, spoofed content types and stored script execution via preview. Controls: size and count limits, content-based type allowlist, random server-side names outside the web root, safe content-disposition or a sandboxed origin, bounded scanning. Use `templates/threat-model.md` for the record.

## Verification and Acceptance Criteria
Every top risk has a control plus a verification (test, configuration check or accepted-risk entry); assumptions and boundaries are explicit; at least one abuse case became an executable test or a documented manual check.

## Failure Modes and Troubleshooting
A generic threat list copied from another project; only external attackers considered; threats without owners; a model never revisited; analysis paralysis (cap the MVP model at about 30 minutes).

## Outputs to Record
Data-flow sketch, asset list, ranked threats and abuse cases, controls, linked tests, accepted risks.

## Related Skills and Activation Triggers
architecture-and-mvp; web-and-api-security; security-testing-and-adversarial-validation; privacy-and-data-protection.

## Completion Checklist
- [ ] Trigger matches; scope and assumptions recorded.
- [ ] Smallest workflow run; claims tied to evidence.
- [ ] Checks run, or skipped ones labeled.
- [ ] Limits and next action recorded.

**Time-box advice:** Model the riskiest workflow first; a short accurate model beats a complete unfinished one.
