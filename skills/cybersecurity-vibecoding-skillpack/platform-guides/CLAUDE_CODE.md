# Portable Guide: Claude Code

## Context to provide first
Provide `AGENTS.md`, `SKILL_ROUTER.md`, the task brief and one relevant mode first. Ask the agent to name the primary/supporting skill triggers before adding those files to context. If the installed version supports project instructions or skills directories, adapt this pack to its documented convention.

## Keep routing deterministic
Do not assume this folder is automatically discovered or its frontmatter parsed. Keep always-on context short; verify current behavior using local help/documentation.

## Reusable prompt
> Read `AGENTS.md` and `SKILL_ROUTER.md`. Based on the task and repository that actually exist, choose one primary playbook and only necessary supporting files. Explain triggers, inspect before editing, preserve existing work, implement a narrow verified result, and report exact commands, outcomes, blockers and limits. If platform-specific automation is unavailable, use the Markdown workflow manually.
## Token-efficient routing
Route from `skills/INDEX.md`, read `instructions/COMMON_SKILL_RULES.md` once, and open only the skills chosen for the current milestone.
