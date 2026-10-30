# Adaptive Master Workflow

Cycle: **Understand → Inspect → Classify → Select Skills → Plan → Build → Integrate → Test → Demo → Report**. Repeat only when new evidence changes the plan.

| Stage | Action | Exit condition |
|---|---|---|
| Understand | Read request, brief, rules, rubric, deadline and deliverables; restate success. | Observable task contract and exclusions exist. |
| Inspect | Check worktree, project instructions, manifests, entry points, data stores, APIs, tests and config. | Baseline is evidenced or unknowns are recorded. |
| Classify | Select immediate track and determine safety prerequisites. | One task track and applicable scope rules are clear. |
| Route | Use `SKILL_ROUTER.md`; choose one primary plus normally up to three supports. | Each skill has a trigger and output. |
| Plan | Rank by acceptance value, risk, effort, dependency and remaining time. | A thin slice and pass/fail checks are written. |
| Build | Make small targeted edits and resolve the riskiest assumption cheaply. | One meaningful workflow exists end-to-end. |
| Integrate | Connect UI/API/storage/tool boundaries and error paths. | Contract works or blocker is explicit. |
| Test | Run targeted then broader checks; inspect diffs and output. | Exact outcomes and skipped checks recorded. |
| Demo | Rehearse actual behavior and failure/fallback states. | Demonstration claims map to observable evidence. |
| Report | Summarize results, limitations, commands and next step. | Another person can reproduce and understand the state. |

**Evidence labels:** fact = directly observed; assumption = reversible choice made to proceed; hypothesis = plausible but unverified; finding = evidence-supported conclusion; verified outcome = acceptance check actually executed and passed. Do not promote a hypothesis to root cause without a distinguishing test.

**Research cut line:** start building once objective, authorization, key data flow, critical dependency risks and pass/fail behavior are clear enough for a safe first slice. Continue research only when an unknown can materially change scope, safety, architecture or acceptance.

**Re-route/stop:** explain new evidence before adding a skill. After two similar failed attempts, change diagnostic method or stop. Stop active testing on unclear scope, unexpected sensitive data, instability, rate-limit breach or third-party impact.
