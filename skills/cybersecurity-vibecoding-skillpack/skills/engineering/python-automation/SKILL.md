---
name: python-automation
description: Build small repeatable utilities with safe paths, validation, clear CLI behavior and tests.
triggers:
  - Manual file/data workflow can be automated
  - A standard-library utility is enough
---

# Python Automation

## Purpose
Build small repeatable utilities with safe paths, validation, clear CLI behavior and tests.

## Use When
- Manual file/data workflow can be automated
- A standard-library utility is enough

## Do Not Load When
- Native command or established tool is simpler and safer.

## Required Context and Prerequisites
Task brief, project instructions and the code touched. Active testing needs written scope and stop conditions first. See `instructions/COMMON_SKILL_RULES.md`.

## First 5-Minute Actions
Inputs/outputs, Python version, path rules, scale, overwrite behavior and failure cases.

## Procedure
1. Create a tiny fixture and define exact success/failure outputs first.
2. Structure as an argparse CLI over pure functions with tests; keep side effects at the edges.
3. Call subprocesses with explicit argument lists (no shell=True) and timeouts.
4. Offer --dry-run for any action that modifies files or uses the network.
5. Document usage, exit codes and an example in --help.

## Decision Rules and Stop Conditions
- Validate CLI arguments and input schema; use pathlib and explicit encodings.
- Bound file size, iteration count and subprocess time where relevant.
- Make output deterministic and refuse overwrite unless explicitly requested.
- Handle expected errors with clear messages and nonzero exit codes.
- Test success, malformed input, missing file and existing-target safety.

## Tooling and Fallbacks
Use existing tooling and offline fixtures first. If something is unavailable, take the simplest credible fallback and say what it cannot verify (`instructions/COMMON_SKILL_RULES.md`).

## Implementation Patterns / Examples
Never execute input data as code or trust archive paths blindly. Prefer standard library unless a dependency materially helps. A context initializer should create a target from a template and refuse overwrite unless `--force` is provided.

## Verification and Acceptance Criteria
CLI behavior is predictable, paths are safe, outputs deterministic and failure cases tested.

Label evidence as reviewed, generated, mocked or executed, and record exact commands and outcomes (`instructions/COMMON_SKILL_RULES.md`, Evidence).

## Failure Modes and Troubleshooting
Swallowed errors, wrong working-directory assumptions, path traversal, destructive overwrite, resource exhaustion.

On failure keep the error and identify its layer; after two similar failures change method or stop (`instructions/COMMON_SKILL_RULES.md`, Failure).

## Outputs to Record
Script, usage examples, fixtures, tests and limitations.

Record evidence compactly (source, command, fact, interpretation, confidence, limit); redact secrets and personal data.

## Related Skills and Activation Triggers
testing-and-verification; release-and-packaging; data-analysis-and-visualization.

Load a related skill only when its trigger is observed and it changes the next action.

## Completion Checklist
- [ ] Trigger matches; scope and assumptions recorded.
- [ ] Smallest workflow run; claims tied to evidence.
- [ ] Checks run, or skipped ones labeled.
- [ ] Limits and next action recorded.

**Time-box advice:** Implement core path plus the likely invalid-input and existing-output paths first.
