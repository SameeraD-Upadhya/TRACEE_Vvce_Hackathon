---
name: release-and-packaging
description: Build reproducible clean artifacts and verify file inventory, integrity and top-level structure.
triggers:
  - ZIP/archive/installer/report bundle is required
  - Release must exclude secrets, caches and unrelated files
---

# Release and Packaging

## Purpose
Build reproducible clean artifacts and verify file inventory, integrity and top-level structure.

## Use When
- ZIP/archive/installer/report bundle is required
- Release must exclude secrets, caches and unrelated files

## Do Not Load When
- No artifact or reproducibility requirement exists.

## Required Context and Prerequisites
Task brief, project instructions and the code touched. Active testing needs written scope and stop conditions first. See `instructions/COMMON_SKILL_RULES.md`.

## First 5-Minute Actions
Exact output path/format, required content, exclusions, platform and signing requirements if any.

## Procedure
1. List required files and exclusions; confirm no existing user project will be overwritten.
2. Version the release and update changelog and manifest consistently.
3. Run the validator and tests on the source tree and again on the extracted archive.
4. Check that nothing outside the allowlist is included and no secrets are present.
5. Publish a checksum when recipients need to verify integrity.

## Decision Rules and Stop Conditions
- Build from a known source tree/allowlist and normalize relative paths/order.
- Exclude credentials, env files, private keys, caches, VCS metadata, test outputs and old archives.
- Use stable timestamps/permissions where practical and document remaining variability.
- Open/test the archive; check root layout, content, file size and relative paths.
- Use hashes/signatures only when a defined release process requires them.
- Record the actual command, output path and checks performed.

## Tooling and Fallbacks
Use existing tooling and offline fixtures first. If something is unavailable, take the simplest credible fallback and say what it cannot verify (`instructions/COMMON_SKILL_RULES.md`).

## Implementation Patterns / Examples
Never claim an artifact exists before verifying its exact path. Preserve source when both directory and archive are requested. The archive should contain one expected root folder, not loose files or a nested prior archive.

## Verification and Acceptance Criteria
Archive opens, required paths exist, no absolute/traversal paths and no known-forbidden files are packaged.

Label evidence as reviewed, generated, mocked or executed, and record exact commands and outcomes (`instructions/COMMON_SKILL_RULES.md`, Evidence).

## Failure Modes and Troubleshooting
Wrong root, stale artifacts, secret leakage, nested archive, platform-specific absolute path.

On failure keep the error and identify its layer; after two similar failures change method or stop (`instructions/COMMON_SKILL_RULES.md`, Failure).

## Outputs to Record
Artifact, included-file inventory, integrity check and reproducibility note.

Record evidence compactly (source, command, fact, interpretation, confidence, limit); redact secrets and personal data.

## Related Skills and Activation Triggers
python-automation; testing-and-verification; documentation-and-handoff.

Load a related skill only when its trigger is observed and it changes the next action.

## Completion Checklist
- [ ] Trigger matches; scope and assumptions recorded.
- [ ] Smallest workflow run; claims tied to evidence.
- [ ] Checks run, or skipped ones labeled.
- [ ] Limits and next action recorded.

**Time-box advice:** Freeze source, build, inspect, and rebuild only when a documented defect is fixed.
