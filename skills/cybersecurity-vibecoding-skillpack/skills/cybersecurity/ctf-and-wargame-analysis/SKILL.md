---
name: ctf-and-wargame-analysis
description: Triage supplied challenge artifacts with bounded hypotheses and reproducible proof.
triggers:
  - Authorized event or local challenge artifact
  - Challenge asks for a flag or proof
---

# CTF and Wargame Analysis

## Purpose
Triage supplied challenge artifacts with bounded hypotheses and reproducible proof.

## Use When
- Authorized event or local challenge artifact
- Challenge asks for a flag or proof

## Do Not Load When
- Unrelated real target without explicit authorization.

## Required Context and Prerequisites
Task brief, project instructions and the code touched. Active testing needs written scope and stop conditions first. See `instructions/COMMON_SKILL_RULES.md`.

## First 5-Minute Actions
Rules, artifact inventory, challenge scope, hints, limits and tools available.

## Procedure
1. Inventory files/types/sizes/hashes and choose one low-cost hypothesis-driven experiment.
2. Confirm the event rules first: allowed tools and targets, flag format, no attacks on event infrastructure.
3. Triage by artifact type: static inspection first; run unknown binaries only in isolation; run supplied services in a local container.
4. After each experiment note input, command, output and the eliminated hypothesis.
5. Stop at a flag verified against the artifact and write up the solving path.

## Decision Rules and Stop Conditions
- Classify by observed artifacts rather than title alone.
- Keep a notebook of input, command, output, hypothesis and eliminated paths.
- Use bounded parsing and isolate unknown binaries before execution.
- Avoid unbounded brute force/fuzzing; change strategy after two similar dead ends.
- Verify the claimed flag/proof against event submission rules.

## Tooling and Fallbacks
Use existing tooling and offline fixtures first. If something is unavailable, take the simplest credible fallback and say what it cannot verify (`instructions/COMMON_SKILL_RULES.md`).

## Implementation Patterns / Examples
Stay inside supplied challenge scope. Avoid privileged execution, destructive activity and pivots to unrelated systems. Inspect archive members/metadata before extraction and guard against traversal or oversized expansion.

## Verification and Acceptance Criteria
The result has a short reproducible chain from a supplied artifact; guesses are labeled as guesses.

Label evidence as reviewed, generated, mocked or executed, and record exact commands and outcomes (`instructions/COMMON_SKILL_RULES.md`, Evidence).

## Failure Modes and Troubleshooting
Blind brute force, unsafe execution, guessed flag formats, time lost on dead ends.

On failure keep the error and identify its layer; after two similar failures change method or stop (`instructions/COMMON_SKILL_RULES.md`, Failure).

## Outputs to Record
Artifact notes, provenance, hypothesis log, verified proof and uncertainty.

Record evidence compactly (source, command, fact, interpretation, confidence, limit); redact secrets and personal data.

## Related Skills and Activation Triggers
reverse-engineering-and-binary-analysis; cryptography-and-blockchain; digital-forensics-and-pcap.

Load a related skill only when its trigger is observed and it changes the next action.

## Completion Checklist
- [ ] Trigger matches; scope and assumptions recorded.
- [ ] Smallest workflow run; claims tied to evidence.
- [ ] Checks run, or skipped ones labeled.
- [ ] Limits and next action recorded.

**Time-box advice:** Time-box each hypothesis and switch based on evidence.
