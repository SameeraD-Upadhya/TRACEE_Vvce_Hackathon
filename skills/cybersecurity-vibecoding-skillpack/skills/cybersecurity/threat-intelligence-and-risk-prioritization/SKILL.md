---
name: threat-intelligence-and-risk-prioritization
description: Rank vulnerabilities, alerts and indicators by exposure, exploitability and impact using cited sources, without overstating attribution.
triggers:
  - Many findings, CVEs or alerts must be put in a fix order
  - A report or detection needs threat context such as ATT&CK techniques, known-exploited status or indicators
---

# Threat Intelligence and Risk Prioritization

## Purpose
Turn vulnerabilities, alerts and external threat information into a ranked, evidence-based action order without overstating attribution or certainty.

## Use When
- Many findings, CVEs or alerts need a defensible fix order
- A report, dashboard or detection needs threat context (technique mapping, known-exploited status, indicators)
- A demo shows threat feeds and real versus synthetic data must be disclosed

## Do Not Load When
- One confirmed bug with an obvious fix
- No external context or ranking decision is needed

## Required Context and Prerequisites
A finding list with affected asset, exposure (internet, internal, local), data sensitivity and exploit conditions. Know whether online lookups are possible; if not, say so.

## First 5-Minute Actions
Collect findings into one table: id, asset, exposure, exploit condition, impact, source and date.

## Procedure
1. Normalize inputs (CVE IDs, scanner output, rule hits) into one deduplicated table with source and date.
2. Enrich from trusted, citable sources when available: vendor advisory, NVD severity (CVSS), CISA Known Exploited Vulnerabilities catalog, EPSS exploit-probability data, MITRE ATT&CK mapping. Offline: state it and rank on exposure and impact alone.
3. Rank by context: reachable and exposed, authentication required, asset criticality, data sensitivity and compensating controls. A CVSS base score alone is not the priority.
4. Treat indicators (IP, domain, hash) as perishable and low context: record first and last seen, source, confidence and expiry; do not block production traffic on one unvetted indicator.
5. Describe observed behavior and techniques; name an actor only when a source supports it, with a stated confidence level and basis.
6. Output an ordered action list (fix now, schedule, monitor, accept) with reason and review date, and feed techniques into the detection backlog.

## Decision Rules and Stop Conditions
- Every external fact carries a source and retrieval date; otherwise label it unverified.
- A known-exploited, exposed and reachable issue outranks a higher CVSS score that is unreachable.
- The asset owner decides risk acceptance; this skill recommends.
- Never fabricate CVE details, scores, actor links or feed data; label synthetic feeds in demos.

## Tooling and Fallbacks
Use existing tooling and offline fixtures first. If something is unavailable, take the simplest credible fallback and say what it cannot verify (`instructions/COMMON_SKILL_RULES.md`).

## Implementation Patterns / Examples
Transparent scoring: priority = exposure (1-3) x exploitability (1-3) x impact (1-3), with the reason written beside each factor so reviewers can disagree with a number instead of a black box. Three findings might yield: internet-facing, known-exploited library (fix now); internal admin panel with weak lockout (schedule); informational header (monitor).

## Verification and Acceptance Criteria
Each ranked item shows asset, evidence, dated sources and confidence; low-priority items state why; demo data is labeled synthetic or live; the formula reproduces the order.

## Failure Modes and Troubleshooting
CVSS-only ranking; stale feeds; attribution from a single indicator; treating an ATT&CK mapping as proof; alert storms from indicator lists; blocking legitimate shared infrastructure.

## Outputs to Record
Prioritized table, sources and dates, confidence levels, detection backlog items, accepted risks with review date.

## Related Skills and Activation Triggers
vulnerability-assessment-authorized; soc-siem-and-threat-detection; dependency-and-supply-chain; security-reporting-and-remediation; osint-and-evidence-correlation.

## Completion Checklist
- [ ] Trigger matches; scope and assumptions recorded.
- [ ] Smallest workflow run; claims tied to evidence.
- [ ] Checks run, or skipped ones labeled.
- [ ] Limits and next action recorded.

**Time-box advice:** A short ranked list with reasons is more useful than a long unranked one.
