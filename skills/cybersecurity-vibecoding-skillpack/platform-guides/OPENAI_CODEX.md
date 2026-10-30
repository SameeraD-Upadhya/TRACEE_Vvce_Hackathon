# Portable Guide: OpenAI Codex

## Context to provide first
Provide universal rules through the repository/context mechanism supported by the current environment. Then attach the brief and only the selected mode/skill files. Ask for repo inspection, targeted changes and exact tests.

## Keep routing deterministic
Do not assume automatic discovery in all interfaces. Use direct Markdown context as fallback and preserve project-specific instructions.

## Reusable prompt
> Read `AGENTS.md` and `SKILL_ROUTER.md`. Based on the task and repository that actually exist, choose one primary playbook and only necessary supporting files. Explain triggers, inspect before editing, preserve existing work, implement a narrow verified result, and report exact commands, outcomes, blockers and limits. If platform-specific automation is unavailable, use the Markdown workflow manually.
## Token-efficient routing
Route from `skills/INDEX.md`, read `instructions/COMMON_SKILL_RULES.md` once, and open only the skills chosen for the current milestone.
