# Routing Examples

## New SOC dashboard for a short hackathon
Evidence: rubric-scored demo, no live telemetry credentials, local JSON fixtures. Start with `core/challenge-intake`, then route to `core/architecture-and-mvp`. Supports: SOC/detection, frontend UX and testing. MVP: fixture ingestion → normalize/deduplicate → incident list/detail → test. Label fixture data; defer live connectors and automated containment.

## “Scan a website”
- Owned staging app with written scope: authorized assessment + web/API security + reporting.
- Source code only, no live target permission: secure code review and local tests.
- Unknown ownership/scope: no active requests; establish scope and do passive/local analysis.

## “Malware analysis”
Supplied executable: defensive isolated analysis, possibly reverse engineering. PCAP plus host logs: forensics first. Request to deploy, persist or evade: out of scope; redirect to harmless simulation and detection.

## Half-built app where reset leaves stale counters
Audit first; trace UI action → API → database/cache/worker → rendered counter. Then use debugging and tests. Do not clear every store speculatively. Add a regression test that proves all relevant counters agree after reset.

## Research-gap report
Use Research and Paper Mode. Verify actual papers, metadata, method and limitations; compare like-for-like; label gaps as inference. Similar keywords do not prove novelty.

## Packaging under a deadline
Use release/packaging and verification skills. Freeze features, inventory files, exclude secrets/caches, inspect archive root and report all unchecked criteria.
## Unfamiliar hackathon problem statement
Start with `core/challenge-intake` (criteria table, problem/user/impact, glossary), then `core/hackathon-prioritization`. Add `cybersecurity/threat-modeling-and-abuse-cases` only if the product handles sensitive data or privileged actions. Keep a claims ledger from the first slice.

## Fixing an access-control bug
Primary `cybersecurity/identity-session-and-access-control`; supports `cybersecurity/security-testing-and-adversarial-validation` (denied-case regression test seen failing first) and `cybersecurity/security-reporting-and-remediation` if a report is required. Do not load SOC or forensics skills.

## Dashboard with a threat feed and 200 findings
Primary `cybersecurity/threat-intelligence-and-risk-prioritization` (dated sources, transparent ranking); supports `engineering/data-analysis-and-visualization`. Label the feed synthetic or live at the point of display.
