---
name: performance-and-reliability
description: Locate measured bottlenecks and bound memory, queues, retries, event size and log growth.
triggers:
  - Slow responses, large volumes, memory growth or reliability failures reported
  - Long-running worker/ingest pipeline
---

# Performance and Reliability

## Purpose
Locate measured bottlenecks and bound memory, queues, retries, event size and log growth.

## Use When
- Slow responses, large volumes, memory growth or reliability failures reported
- Long-running worker/ingest pipeline

## Do Not Load When
- No performance symptom or reliability target exists.

## Required Context and Prerequisites
Task brief, project instructions and the code touched. Active testing needs written scope and stop conditions first. See `instructions/COMMON_SKILL_RULES.md`.

## First 5-Minute Actions
Representative workload, baseline, resource limits, latency/volume goals, logs and environment.

## Procedure
1. Reproduce one bottleneck with a bounded workload and capture a baseline.
2. Add structured logging, metrics (latency, errors, queue depth) and health checks to the measured path.
3. Define one target relevant to the product (for example p95 latency or ingest lag) and measure against it.
4. Handle partial failure: timeouts, fallback or circuit breaking, idempotent retries, graceful degradation.
5. Document the tested load envelope and the behavior beyond it.

## Decision Rules and Stop Conditions
- Use profiling or focused timing to identify the hot path before architectural change.
- Set payload, batch, queue, concurrency, timeout and retry limits.
- Make retries bounded/idempotent; apply back-pressure rather than unbounded buffering.
- Aggregate repeated incidents while preserving raw evidence and counts.
- Compare before/after using the same synthetic workload and environment.
- Test DB outage, slow consumer, partial failure and restart recovery.

## Tooling and Fallbacks
Use existing tooling and offline fixtures first. If something is unavailable, take the simplest credible fallback and say what it cannot verify (`instructions/COMMON_SKILL_RULES.md`).

## Implementation Patterns / Examples
Never claim improvements without comparable measurements. Do not trade evidence fidelity or safety for speed. For continuous simulated attacks, create bounded incident summaries with linked events instead of one gigantic log per event.

## Verification and Acceptance Criteria
Resource usage stays bounded; failures recover predictably; benchmark method and limits are documented.

Label evidence as reviewed, generated, mocked or executed, and record exact commands and outcomes (`instructions/COMMON_SKILL_RULES.md`, Evidence).

## Failure Modes and Troubleshooting
Infinite retries, unbounded logs/queues, misleading microbenchmark, optimization without profile.

On failure keep the error and identify its layer; after two similar failures change method or stop (`instructions/COMMON_SKILL_RULES.md`, Failure).

## Outputs to Record
Baseline, workload, measurements, limits and reliability regression checks.

Record evidence compactly (source, command, fact, interpretation, confidence, limit); redact secrets and personal data.

## Related Skills and Activation Triggers
soc-siem-and-threat-detection; backend-api-and-data; testing-and-verification.

Load a related skill only when its trigger is observed and it changes the next action.

## Completion Checklist
- [ ] Trigger matches; scope and assumptions recorded.
- [ ] Smallest workflow run; claims tied to evidence.
- [ ] Checks run, or skipped ones labeled.
- [ ] Limits and next action recorded.

**Time-box advice:** Measure first; fix one expensive path and remeasure the same workload.
