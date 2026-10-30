# Portable Guide: Markdown-only or other agents

## Context to provide first
Manually open `START_HERE.md`, `AGENTS.md`, `SKILL_ROUTER.md`, the relevant mode and selected skills. Supply brief, scope, acceptance checks and time limit.

## Keep routing deterministic
This is the universal fallback. Do not assume frontmatter parsing, automatic discovery, hooks, network or filesystem access unless proven.

## Reusable prompt
> Read `AGENTS.md` and `SKILL_ROUTER.md`. Based on the task and repository that actually exist, choose one primary playbook and only necessary supporting files. Explain triggers, inspect before editing, preserve existing work, implement a narrow verified result, and report exact commands, outcomes, blockers and limits. If platform-specific automation is unavailable, use the Markdown workflow manually.
## Token-efficient routing
Route from `skills/INDEX.md`, read `instructions/COMMON_SKILL_RULES.md` once, and open only the skills chosen for the current milestone.
