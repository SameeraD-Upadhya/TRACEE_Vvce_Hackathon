---
name: hackathon-prioritization
description: Spend limited event time on rubric-critical, feasible work while protecting integration, verification and submission.
triggers:
  - Fixed event deadline or judging rubric
  - Many competing feature ideas
---

# Hackathon Prioritization

## Purpose
Spend limited event time on rubric-critical, feasible work while protecting integration, verification and submission.

## Use When
- Fixed event deadline or judging rubric
- Many competing feature ideas

## Do Not Load When
- No binding timebox and an already approved delivery plan.

## Required Context and Prerequisites
Task brief, project instructions and the code touched. Active testing needs written scope and stop conditions first. See `instructions/COMMON_SKILL_RULES.md`.

## First 5-Minute Actions
Identify the core outcome and cut scope to a slice that can be demoed and verified.

## Procedure
1. Rank features by rubric relevance, user impact, effort, risk, dependencies and demo reliability.
2. Define MVP must-haves, cut line and explicitly deferred ideas.
3. Prototype the riskiest dependency with a small early experiment.
4. Reserve checkpoints for merge/integration, tests, rehearsal and packaging.
5. Cut enhancements before sacrificing core verification or required deliverables.
6. Name the differentiator and the evidence behind it; if similar work exists, describe the actual difference instead of claiming novelty.

## Decision Rules and Stop Conditions
A sophisticated feature is not a must-have if it cannot be integrated and verified on time. Optimize odds; never promise to win.

## Tooling and Fallbacks
Use existing tooling and offline fixtures first. If something is unavailable, take the simplest credible fallback and say what it cannot verify (`instructions/COMMON_SKILL_RULES.md`).

## Implementation Patterns / Examples
Missing external AI credentials → deliver deterministic local logic and label AI as optional rather than blocking the core.

## Verification and Acceptance Criteria
A useful end-to-end path exists before decorative polish; verification and submission time remain protected.

Label evidence as reviewed, generated, mocked or executed, and record exact commands and outcomes (`instructions/COMMON_SKILL_RULES.md`, Evidence).

## Failure Modes and Troubleshooting
Feature creep, disconnected screens, late integration, neglected packaging.

On failure keep the error and identify its layer; after two similar failures change method or stop (`instructions/COMMON_SKILL_RULES.md`, Failure).

## Outputs to Record
Prioritized task board, cut line, checkpoints, risks and demo path.

Record evidence compactly (source, command, fact, interpretation, confidence, limit); redact secrets and personal data.

## Related Skills and Activation Triggers
challenge-intake; demo-and-judging; coding-and-integration.

Load a related skill only when its trigger is observed and it changes the next action.

## Completion Checklist
- [ ] Trigger matches; scope and assumptions recorded.
- [ ] Smallest workflow run; claims tied to evidence.
- [ ] Checks run, or skipped ones labeled.
- [ ] Limits and next action recorded.

**Time-box advice:** Use `HACKATHON_MODE.md` time-box patterns; stop feature work during the final lock.
