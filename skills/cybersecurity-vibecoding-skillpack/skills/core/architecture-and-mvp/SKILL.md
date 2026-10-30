---
name: architecture-and-mvp
description: Design minimal components, boundaries and data flow around testable requirements.
triggers:
  - New product or major feature
  - Multiple UI/API/storage/tools need to integrate
---

# Architecture and Minimum Viable Product

## Purpose
Design minimal components, boundaries and data flow around testable requirements.

## Use When
- New product or major feature
- Multiple UI/API/storage/tools need to integrate

## Do Not Load When
- Tiny localized bug with known cause and no architectural impact.

## Required Context and Prerequisites
Task brief, project instructions and the code touched. Active testing needs written scope and stop conditions first. See `instructions/COMMON_SKILL_RULES.md`.

## First 5-Minute Actions
Sketch one event/request from validation through logic and persistence to visible output.

## Procedure
1. Identify boundaries, data ownership, IDs, trust boundaries and failure paths.
2. Respect existing stack unless evidence supports a change.
3. Define one minimal API/data contract and vertical slice.
4. Address secrets, authorization, retention, timeouts, limits and unavailable dependencies.
5. Record consequential decisions only when useful; avoid future-proofing without need.
6. For any feature with sensitive data or a privileged action, run a time-boxed threat model (threat-modeling-and-abuse-cases) before locking the design.

## Decision Rules and Stop Conditions
Prefer a simple modular app and fixtures over microservices when they satisfy actual scale and team needs. AI is optional when deterministic behavior meets acceptance.

## Tooling and Fallbacks
Use existing tooling and offline fixtures first. If something is unavailable, take the simplest credible fallback and say what it cannot verify (`instructions/COMMON_SKILL_RULES.md`).

## Implementation Patterns / Examples
Ingest a JSON fixture, normalize/deduplicate, create a case and display its timeline before adding real telemetry connectors.

## Verification and Acceptance Criteria
Every component has a clear role, contracts match code and the slice has explicit acceptance checks.

Label evidence as reviewed, generated, mocked or executed, and record exact commands and outcomes (`instructions/COMMON_SKILL_RULES.md`, Evidence).

## Failure Modes and Troubleshooting
Premature distributed architecture, ambiguous shared state, assumptions about service availability, no failure model.

On failure keep the error and identify its layer; after two similar failures change method or stop (`instructions/COMMON_SKILL_RULES.md`, Failure).

## Outputs to Record
Component/data-flow diagram, contract, MVP boundary, risks and decisions.

Record evidence compactly (source, command, fact, interpretation, confidence, limit); redact secrets and personal data.

## Related Skills and Activation Triggers
requirements-and-acceptance; backend-api-and-data; frontend-ux-and-accessibility; threat-modeling-and-abuse-cases.

Load a related skill only when its trigger is observed and it changes the next action.

## Completion Checklist
- [ ] Trigger matches; scope and assumptions recorded.
- [ ] Smallest workflow run; claims tied to evidence.
- [ ] Checks run, or skipped ones labeled.
- [ ] Limits and next action recorded.

**Time-box advice:** Choose safe boundaries quickly; do not document every hypothetical future feature.
