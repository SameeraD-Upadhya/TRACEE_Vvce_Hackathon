# Start Here

This is a portable Markdown-first skill pack for cybersecurity projects, coding-agent workflows, and time-boxed challenges. It helps an agent select only the skills that fit the actual evidence and acceptance criteria.

## Use it
1. Copy this folder into a repository or keep it beside the repo and provide its files through your agent's context mechanism.
2. Open `AGENTS.md` and `SKILL_ROUTER.md` first; choose skills from `skills/INDEX.md` when the router table does not decide, and open `instructions/COMMON_SKILL_RULES.md` sections only when a skill points to them.
3. Give the agent the actual brief, rubric, rules, deadline, deliverables, authorized scope, and repository location.
4. Select one operating mode from `instructions/`, then ask the router to choose one primary skill and normally no more than three supporting skills.
5. Inspect before editing, build an end-to-end slice, run actual checks, and report results honestly.

## Kickoff prompt
> Read `AGENTS.md` and `SKILL_ROUTER.md`. Inspect the supplied task brief and repository before recommending changes. Classify the task, select one primary skill and at most three supporting skills for this pass, and explain each trigger. Separate facts, assumptions, hypotheses, unknowns, and verified outcomes. Implement the smallest useful end-to-end slice, preserve unrelated work, run feasible checks, and report exact commands/results. Do not invent tool availability, findings, test results, or live data. Stay inside authorized scope.

## Modes
- `instructions/HACKATHON_MODE.md` — deadline and judging rubric.
- `instructions/PROJECT_BUILD_MODE.md` — build a product or substantial feature.
- `instructions/PROJECT_AUDIT_MODE.md` — inspect an existing project before changing it.
- `instructions/CTF_AND_WARGAME_MODE.md` — supplied challenge artifacts or controlled lab.
- `instructions/DEFENSIVE_SOC_DFIR_MODE.md` — SOC, detection, incidents, evidence, forensics.
- `instructions/RESEARCH_AND_PAPER_MODE.md` — research and gap analysis.
- `instructions/FINAL_DEMO_AND_SUBMISSION.md` — rehearse, verify and package.

To create a resumable context record: `python scripts/init_project_context.py --target ../PROJECT_CONTEXT.md`. An existing target is preserved unless `--force` is explicitly supplied.
