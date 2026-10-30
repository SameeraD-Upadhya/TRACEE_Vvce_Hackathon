# Portable Guide: Gemini-based coding tools

## Context to provide first
Open `START_HERE.md`, `AGENTS.md`, and the router; provide task contract, workspace and relevant skills. Check current file-access, terminal and context limits of the actual IDE/product.

## Keep routing deterministic
Do not depend on paid APIs, network or native skill loading. Keep offline fixtures and manual Markdown workflow available.

## Reusable prompt
> Read `AGENTS.md` and `SKILL_ROUTER.md`. Based on the task and repository that actually exist, choose one primary playbook and only necessary supporting files. Explain triggers, inspect before editing, preserve existing work, implement a narrow verified result, and report exact commands, outcomes, blockers and limits. If platform-specific automation is unavailable, use the Markdown workflow manually.
## Token-efficient routing
Route from `skills/INDEX.md`, read `instructions/COMMON_SKILL_RULES.md` once, and open only the skills chosen for the current milestone.
