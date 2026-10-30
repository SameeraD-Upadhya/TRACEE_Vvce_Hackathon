# Defensive SOC / DFIR Mode

Use for monitoring, detection, alert triage, evidence correlation, investigations, incident response and forensics.

1. Label telemetry as live, historical, uploaded, synthetic or simulated. Never style fixtures as live events.
2. Record source, event ID, event time, ingestion time, timezone, schema/version, parser confidence and hash/provenance where relevant. Preserve raw artifacts; analyze normalized copies.
3. Define explicit incident states and transitions with actor, timestamp and reason.
4. Validate schemas and sizes; bound queues, retries, timeouts, retention and logs; expose parse failures and ingestion lag.
5. Deduplicate with stable IDs or explicit time-window/entity keys. Prefer one incident-level summary with linked raw evidence over a log entry per repeated event; preserve raw event and suppressed-duplicate counts.
6. Make detection explainable: rule/version, reason, entities, evidence, timeline, confidence and next safe analyst action.
7. Preserve evidence and document clock/retention gaps. Missing evidence is not proof of absence. Containment requires authorization, preview, audit trail and rollback; simulation must be labeled.
8. Evaluate only against appropriately labeled data. Do not claim operational precision/recall from toy fixtures or screenshots.

Useful checks: duplicate delivery does not multiply cases unexpectedly; replay is idempotent or visible; malformed/missing timestamps are handled; events outside a time window do not merge; resets affect only intended lab state; burst workload stays bounded; case evidence survives refresh/restart. Report telemetry origin, correlation method, evidence, analyst decisions and limits.
Evidence integrity: hash artifacts on intake, analyze copies, keep an append-only action log (`cybersecurity/secrets-and-audit-logging`). Rank alerts, findings and indicators with dated sources and stated confidence (`cybersecurity/threat-intelligence-and-risk-prioritization`).
