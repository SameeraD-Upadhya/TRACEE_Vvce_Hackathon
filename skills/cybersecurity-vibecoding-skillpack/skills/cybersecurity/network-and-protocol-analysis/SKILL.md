---
name: network-and-protocol-analysis
description: Interpret network and protocol behavior through bounded, authorized observation.
triggers:
  - PCAP, DNS/HTTP/TLS flows or protocol parser
  - Controlled lab protocol verification
---

# Network and Protocol Analysis

## Purpose
Interpret network and protocol behavior through bounded, authorized observation.

## Use When
- PCAP, DNS/HTTP/TLS flows or protocol parser
- Controlled lab protocol verification

## Do Not Load When
- No network artifact or protocol behavior is relevant.

## Required Context and Prerequisites
Task brief, project instructions and the code touched. Active testing needs written scope and stop conditions first. See `instructions/COMMON_SKILL_RULES.md`.

## First 5-Minute Actions
Capture provenance/time basis, lab scope, topology and locally available parsers.

## Procedure
1. Inventory capture, file size and time range; preserve original hash when appropriate.
2. Start from conversation-level statistics (endpoints, ports, protocols, volume) before packet detail.
3. Reassemble streams and decode application protocols with documented parsers; treat truncated or encrypted data as a stated limit.
4. Correlate DNS, TLS handshake metadata and flow timing to hypotheses; do not infer payload content from encrypted traffic.
5. Before sending any live lab traffic confirm allowlisted hosts, a rate cap and a stop rule.

## Decision Rules and Stop Conditions
- Check capture completeness, interface, collection point and timezone/clock caveats.
- Filter relevant conversations and reconstruct available request/response facts.
- Correlate DNS, connection setup and application events without over-reading encrypted payloads.
- Test parser assumptions on truncated, malformed or fragmented samples.
- For live lab traffic, enforce host allowlists, low rate, timeouts and stop rules.

## Tooling and Fallbacks
Use existing tooling and offline fixtures first. If something is unavailable, take the simplest credible fallback and say what it cannot verify (`instructions/COMMON_SKILL_RULES.md`).

## Implementation Patterns / Examples
An IP/domain association does not prove maliciousness. TLS limits visibility; state exactly what was and was not observable. DNS followed by TLS to a host is a temporal relation, not proof that a payload was downloaded or executed.

## Verification and Acceptance Criteria
Findings specify capture/filter/time basis, protocol evidence and limits.

Label evidence as reviewed, generated, mocked or executed, and record exact commands and outcomes (`instructions/COMMON_SKILL_RULES.md`, Evidence).

## Failure Modes and Troubleshooting
One packet treated as a full session, clock drift ignored, capture from unauthorized network.

On failure keep the error and identify its layer; after two similar failures change method or stop (`instructions/COMMON_SKILL_RULES.md`, Failure).

## Outputs to Record
Conversation timeline, filters, key observations, parser tests and caveats.

Record evidence compactly (source, command, fact, interpretation, confidence, limit); redact secrets and personal data.

## Related Skills and Activation Triggers
digital-forensics-and-pcap; osint-and-evidence-correlation; incident-response-and-dfir.

Load a related skill only when its trigger is observed and it changes the next action.

## Completion Checklist
- [ ] Trigger matches; scope and assumptions recorded.
- [ ] Smallest workflow run; claims tied to evidence.
- [ ] Checks run, or skipped ones labeled.
- [ ] Limits and next action recorded.

**Time-box advice:** Use the smallest relevant capture window; stop when more packets do not change the hypothesis.
