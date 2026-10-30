# Skill Router — Choose the Smallest Useful Set

## Routing algorithm
1. Read the user request, brief, rules, rubric, time limit, deliverables and acceptance criteria. If no formal brief exists, write a compact task contract.
2. Inspect repository instructions (`AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, editor rules), README, manifests/lockfiles, environment samples, CI, tests, entry points and current worktree state.
3. Classify the immediate objective: understand, build, fix, test, research, triage evidence, assess security, deploy, or present. Do not route by keywords alone.
4. Choose one primary skill and normally no more than three supports. State each skill's trigger, output and prerequisite; include a scope skill if active testing may occur.
5. Pick the smallest valuable milestone, define acceptance checks and the feature cut-line, and defer speculative enhancements.
6. Execute, integrate and verify. Record exact commands and actual outcomes. Re-route only when new evidence changes the next action; say why.
7. If a tool/API/model/dataset/network is missing, use a local fixture, standard-library option, mock adapter or narrower credible outcome. After two materially similar failed attempts, change approach or stop and record the blocker.
8. For multi-session work, update `templates/project-context.md` or a short task log with chosen skills, assumptions, milestone, checks and next action.

## Decision table
| Signal in task/evidence | Primary candidate | Add only when triggered |
|---|---|---|
| Ambiguous brief, rubric or deliverable | `core/challenge-intake` | requirements, hackathon prioritization |
| Existing repo with unknown health | `core/repository-audit` | debugging, testing, deployment |
| Deadline and competing features | `core/hackathon-prioritization` | requirements, demo-and-judging |
| New product or major workflow | `core/architecture-and-mvp` | backend, frontend, testing |
| Authorized web/API assessment | `cybersecurity/web-and-api-security` | identity/access, authorized assessment, reporting |
| Supplied CTF file/target | `cybersecurity/ctf-and-wargame-analysis` | reverse engineering, crypto, forensics by artifact |
| Alerts, telemetry, SOC queue | `cybersecurity/soc-siem-and-threat-detection` | incident response, data analysis, reliability |
| PCAP, disk, logs, timeline | `cybersecurity/digital-forensics-and-pcap` | network analysis, correlation, reporting |
| Papers, novelty or research gaps | `instructions/RESEARCH_AND_PAPER_MODE.md` | intake, analysis, documentation |
| LLM with retrieval/tools/private data | `cybersecurity/ai-llm-and-agent-security` | AI integration, privacy, testing |
| Cloud, containers, CI, dependencies | `cybersecurity/cloud-container-and-devsecops` | supply chain, deployment, code review |
| New feature with sensitive data, privileged or automated actions, uploads or AI tool use | `cybersecurity/threat-modeling-and-abuse-cases` | architecture/MVP, security testing |
| Credentials, API keys, audit trail or evidence-integrity logging | `cybersecurity/secrets-and-audit-logging` | privacy, identity/access, deployment |
| Security fix, authorization/validation/detection claim to prove, adversarial inputs | `cybersecurity/security-testing-and-adversarial-validation` | testing-and-verification, the domain skill |
| Many findings, CVEs or alerts to rank; threat context needed | `cybersecurity/threat-intelligence-and-risk-prioritization` | vulnerability assessment, SOC, reporting |
| Broken UI/action/state | frontend or backend skill based on traced failure | debugging, testing |
| Clean archive or release | `engineering/release-and-packaging` | Python automation, testing, docs |

## Same words, different routes
- “Build a scanner”: local offline dataset → data analysis; owned app with written scope → authorized assessment; unknown public targets → no active testing until scope is confirmed.
- “Investigate malware”: supplied executable → defensive isolated analysis; PCAP/logs → forensics; request to deploy, persist or evade → refuse that harmful path and offer harmless simulation/detection.
- “AI threat detection”: deterministic alert rule → SOC/detection; AI as explanation layer → AI integration and grounding checks.
- “Production-ready”: unfamiliar existing repository → audit first; new product → architecture/MVP; deployment skill only when a real target/environment exists.

A skill name is not a plan. Pair it with an observable output, milestone and check. Do not load every skill by default.
## Context budget
- **Always:** `AGENTS.md` and this router; use `skills/INDEX.md` only when the table does not decide. **Per session:** one mode file.
- **Per milestone:** one primary skill, supports on trigger; read Use When, Procedure, Verification and Completion first. Open `instructions/COMMON_SKILL_RULES.md` sections only when a skill points to them or when building a product.
- Templates and examples only when producing that artifact; inspect targeted files, not directories or logs.
- Keep decisions, constraints, verified facts and failed approaches in `templates/project-context.md`; a retry needs new evidence.
