---
name: reverse-engineering-and-binary-analysis
description: Safely characterize supplied binaries/software artifacts with static facts and bounded dynamic experiments.
triggers:
  - Challenge binary, executable, firmware or unknown file format
  - Behavior is unknown and source unavailable
---

# Reverse Engineering and Binary Analysis

## Purpose
Safely characterize supplied binaries/software artifacts with static facts and bounded dynamic experiments.

## Use When
- Challenge binary, executable, firmware or unknown file format
- Behavior is unknown and source unavailable

## Do Not Load When
- Request is to create/deploy harmful capability instead of analyze it.

## Required Context and Prerequisites
Task brief, project instructions and the code touched. Active testing needs written scope and stop conditions first. See `instructions/COMMON_SKILL_RULES.md`.

## First 5-Minute Actions
Artifact provenance, hash/type/size, safe environment, scope and locally available tools.

## Procedure
1. Identify architecture, format, imports and metadata without executing the artifact.
2. Use static tools (file, strings, symbol and import tables, disassembler or decompiler) to map entry points and functions of interest.
3. Annotate findings with addresses or offsets in a working copy and keep a log of hypotheses tested.
4. If dynamic analysis is justified, use a debugger inside an isolated snapshot-able environment with the network off.
5. Report behavior with evidence (addresses, traces); label inferred intent as inference; do not publish weaponized exploit code.

## Decision Rules and Stop Conditions
- Preserve originals and analyze working copies in an isolated least-privilege environment.
- Use metadata, strings, sections, imports and control-flow clues to form a testable hypothesis.
- Execute only when necessary, isolated, resource-bounded and network-restricted as appropriate.
- Record tool/version, input offsets and observations; distinguish observed from inferred behavior.
- Test analyzer/parser changes on benign fixtures and malformed inputs.

## Tooling and Fallbacks
Use existing tooling and offline fixtures first. If something is unavailable, take the simplest credible fallback and say what it cannot verify (`instructions/COMMON_SKILL_RULES.md`).

## Implementation Patterns / Examples
Never run unknown binaries with host privileges or access to sensitive networks/credentials. No malware deployment, evasion or persistence guidance. A URL string in a binary does not prove it connects at runtime; check reachable call paths or safe sandbox observations.

## Verification and Acceptance Criteria
Conclusions have evidence offsets/addresses, reproducible steps and an explicit confidence level.

Label evidence as reviewed, generated, mocked or executed, and record exact commands and outcomes (`instructions/COMMON_SKILL_RULES.md`, Evidence).

## Failure Modes and Troubleshooting
Execute first, extrapolate from strings, ignore architecture/endian details, fuzz without bounds.

On failure keep the error and identify its layer; after two similar failures change method or stop (`instructions/COMMON_SKILL_RULES.md`, Failure).

## Outputs to Record
Artifact metadata, analysis notebook, hypotheses and results, safe reproduction and limits.

Record evidence compactly (source, command, fact, interpretation, confidence, limit); redact secrets and personal data.

## Related Skills and Activation Triggers
ctf-and-wargame-analysis; malware-analysis-defensive; mobile-iot-and-embedded-security.

Load a related skill only when its trigger is observed and it changes the next action.

## Completion Checklist
- [ ] Trigger matches; scope and assumptions recorded.
- [ ] Smallest workflow run; claims tied to evidence.
- [ ] Checks run, or skipped ones labeled.
- [ ] Limits and next action recorded.

**Time-box advice:** Static inspection first; dynamic analysis only when it resolves a consequential question.
