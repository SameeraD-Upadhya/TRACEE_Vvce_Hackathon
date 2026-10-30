---
name: cryptography-and-blockchain
description: Review cryptographic assumptions, key handling, protocol use and contract invariants without overstating conclusions.
triggers:
  - Crypto primitive, signing, key exchange, hashes, wallets or smart contracts
  - Crypto CTF or controlled contract test
---

# Cryptography and Blockchain Analysis

## Purpose
Review cryptographic assumptions, key handling, protocol use and contract invariants without overstating conclusions.

## Use When
- Crypto primitive, signing, key exchange, hashes, wallets or smart contracts
- Crypto CTF or controlled contract test

## Do Not Load When
- Crypto is incidental and no crypto boundary is involved.

## Required Context and Prerequisites
Task brief, project instructions and the code touched. Active testing needs written scope and stop conditions first. See `instructions/COMMON_SKILL_RULES.md`.

## First 5-Minute Actions
Security goal, protocol/code, threat model, key lifecycle, test vectors and local/test-chain scope.

## Procedure
1. Identify the intended property, adversary capability, algorithm and exact parameters.
2. Use a vetted library API at recommended defaults; do not implement primitives, modes or protocols yourself.
3. Write test vectors and negative tests: tampered ciphertext, wrong key, nonce reuse, expired or replayed message.
4. For contracts, test invariants, access control and reentrancy on a local or test network; never use real funds or keys.
5. Record threat assumptions and what the construction does not protect (metadata, key storage, side channels).

## Decision Rules and Stop Conditions
- Check randomness, nonce/IV reuse, key derivation, authentication and primitive composition.
- Prefer standard, reviewed library APIs instead of custom cryptography.
- For contracts, inspect access control, state invariants, arithmetic, external calls and emitted events.
- Use known test vectors and negative tests on local/test networks.
- State assumptions and limits; do not infer a broken primitive from one odd output.

## Tooling and Fallbacks
Use existing tooling and offline fixtures first. If something is unavailable, take the simplest credible fallback and say what it cannot verify (`instructions/COMMON_SKILL_RULES.md`).

## Implementation Patterns / Examples
Never request or expose real private keys or seed phrases. Do not exploit live contracts or manipulate funds; test locally or on authorized test environments. Signature tests include valid message, altered message, wrong key and malformed signature.

## Verification and Acceptance Criteria
Critical invariants hold for normal/boundary cases and secrets do not appear in logs.

Label evidence as reviewed, generated, mocked or executed, and record exact commands and outcomes (`instructions/COMMON_SKILL_RULES.md`, Evidence).

## Failure Modes and Troubleshooting
Custom crypto, weak randomness, nonce reuse, unclear chain environment, claims beyond evidence.

On failure keep the error and identify its layer; after two similar failures change method or stop (`instructions/COMMON_SKILL_RULES.md`, Failure).

## Outputs to Record
Threat assumptions, API/primitive review, test vectors, invariant tests and caveats.

Record evidence compactly (source, command, fact, interpretation, confidence, limit); redact secrets and personal data.

## Related Skills and Activation Triggers
secure-coding-and-code-review; identity-session-and-access-control; testing-and-verification.

Load a related skill only when its trigger is observed and it changes the next action.

## Completion Checklist
- [ ] Trigger matches; scope and assumptions recorded.
- [ ] Smallest workflow run; claims tied to evidence.
- [ ] Checks run, or skipped ones labeled.
- [ ] Limits and next action recorded.

**Time-box advice:** Prioritize misuse of primitives and key custody before theory-heavy analysis unless required.
