---
name: ai-llm-and-rag-product-integration
description: Integrate grounded AI with controlled context, validated outputs, fallbacks and evaluation.
triggers:
  - Summarization, semantic retrieval or natural-language interpretation is required
  - LLM/RAG is an explicit product component
---

# AI, LLM and RAG Product Integration

## Purpose
Integrate grounded AI with controlled context, validated outputs, fallbacks and evaluation.

## Use When
- Summarization, semantic retrieval or natural-language interpretation is required
- LLM/RAG is an explicit product component

## Do Not Load When
- Deterministic rules meet acceptance or AI is merely speculative.

## Required Context and Prerequisites
Task brief, project instructions and the code touched. Active testing needs written scope and stop conditions first. See `instructions/COMMON_SKILL_RULES.md`.

## First 5-Minute Actions
Define the desired answer, authorized sources, credential availability, privacy and a non-AI fallback.

## Procedure
1. Separate retrieval, context assembly, generation and output validation.
2. Enforce per-user authorization before retrieval/context construction.
3. Treat retrieved documents as untrusted content; protect against injection and leakage.
4. Validate response schemas and bound token/size/time/cost; handle provider failure.
5. Ground claims in source references and provide an uncertainty/fallback state.
6. Test valid, unsupported, empty-context, adversarial and malformed-output cases.

## Decision Rules and Stop Conditions
AI output must not authorize consequential remediation by itself. A paid API must not become a hidden core dependency without explicit requirement.

## Tooling and Fallbacks
Use existing tooling and offline fixtures first. If something is unavailable, take the simplest credible fallback and say what it cannot verify (`instructions/COMMON_SKILL_RULES.md`).

## Implementation Patterns / Examples
Summarize authorized event excerpts and cross-check each generated claim against stored evidence.

## Verification and Acceptance Criteria
Unsupported/empty context is handled honestly, schemas validate, and AI/mock behavior is labeled.

Label evidence as reviewed, generated, mocked or executed, and record exact commands and outcomes (`instructions/COMMON_SKILL_RULES.md`, Evidence).

## Failure Modes and Troubleshooting
Fabricated citations, unbounded cost, secret exposure, unsafe retrieved instructions, silent timeout.

On failure keep the error and identify its layer; after two similar failures change method or stop (`instructions/COMMON_SKILL_RULES.md`, Failure).

## Outputs to Record
AI data-flow, prompt/config policy, fixtures/evaluation, fallback and limitations.

Record evidence compactly (source, command, fact, interpretation, confidence, limit); redact secrets and personal data.

## Related Skills and Activation Triggers
ai-llm-and-agent-security; privacy-and-data-protection; testing-and-verification.

Load a related skill only when its trigger is observed and it changes the next action.

## Completion Checklist
- [ ] Trigger matches; scope and assumptions recorded.
- [ ] Smallest workflow run; claims tied to evidence.
- [ ] Checks run, or skipped ones labeled.
- [ ] Limits and next action recorded.

**Time-box advice:** Set output contract and fallback before prompt tuning or complex retrieval engineering.
