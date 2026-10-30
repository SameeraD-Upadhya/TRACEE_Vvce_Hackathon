---
name: documentation-and-handoff
description: Make setup, behavior, limits and reproduction understandable to the next developer or reviewer.
triggers:
  - Need a README/report/handoff
  - Current docs differ from implementation
---

# Documentation and Handoff

## Purpose
Make setup, behavior, limits and reproduction understandable to the next developer or reviewer.

## Use When
- Need a README/report/handoff
- Current docs differ from implementation

## Do Not Load When
- Tiny experiment without handoff need, unless behavior changed.

## Required Context and Prerequisites
Task brief, project instructions and the code touched. Active testing needs written scope and stop conditions first. See `instructions/COMMON_SKILL_RULES.md`.

## First 5-Minute Actions
Inspect real source, actual commands, user flow, config and known limits before writing.

## Procedure
1. Explain purpose, scope, architecture and main data flow concisely.
2. Document prerequisites, setup/run/test commands and expected observable outputs.
3. Separate implemented, planned, mocked, unverified and unsupported behavior.
4. Record known errors, reset/cleanup behavior and safe config.
5. Check relative links and align every strong claim with source/test evidence.
6. Include an architecture or data-flow diagram (text or Mermaid), setup commands that were actually run, test evidence, and a limitations list separating real, synthetic and unimplemented parts.

## Decision Rules and Stop Conditions
Never document a plan as an implemented feature or an unrun check as passed. Favor reproducibility over promotional language.

## Tooling and Fallbacks
Use existing tooling and offline fixtures first. If something is unavailable, take the simplest credible fallback and say what it cannot verify (`instructions/COMMON_SKILL_RULES.md`).

## Implementation Patterns / Examples
Fixture-backed dashboard must be called fixture-backed, not live telemetry.

## Verification and Acceptance Criteria
A fresh developer can reproduce the main verified workflow from the docs.

Label evidence as reviewed, generated, mocked or executed, and record exact commands and outcomes (`instructions/COMMON_SKILL_RULES.md`, Evidence).

## Failure Modes and Troubleshooting
Generic instructions, undocumented manual steps, stale screenshots or false feature claims.

On failure keep the error and identify its layer; after two similar failures change method or stop (`instructions/COMMON_SKILL_RULES.md`, Failure).

## Outputs to Record
README/setup, architecture/data-flow, exact checks, limitations and handoff.

Record evidence compactly (source, command, fact, interpretation, confidence, limit); redact secrets and personal data.

## Related Skills and Activation Triggers
repository-audit; testing-and-verification; demo-and-judging.

Load a related skill only when its trigger is observed and it changes the next action.

## Completion Checklist
- [ ] Trigger matches; scope and assumptions recorded.
- [ ] Smallest workflow run; claims tied to evidence.
- [ ] Checks run, or skipped ones labeled.
- [ ] Limits and next action recorded.

**Time-box advice:** Document alongside integration, then do a factual accuracy pass after code freeze.
