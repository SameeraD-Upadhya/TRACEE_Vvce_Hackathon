# Cybersecurity Vibe-Coding Skill Pack

**Version:** 1.1.0 · **Updated:** 2026-10-25

A portable, Markdown-first set of task-routing instructions and focused playbooks for agents building, debugging, auditing, testing, researching and demonstrating cybersecurity projects. It deliberately balances broad coverage with selective loading.

## Contents
- `START_HERE.md`, `AGENTS.md`, and `SKILL_ROUTER.md` as the short entry points.
- Eight operating modes; seven portable guides for Claude Code, OpenAI Codex, Antigravity, Cursor, Gemini-based tools, GitHub Copilot, and Markdown-only agents.
- 43 differentiated skill playbooks across core engineering, cybersecurity domains, and supporting engineering, with `skills/INDEX.md` as a one-line-per-skill routing index.
- `instructions/COMMON_SKILL_RULES.md`: shared evidence, retry, token and product-integrity rules that skills reference instead of repeating (open sections on demand).
- Templates for project context, scope, requirements, tests, findings, evidence, decisions, demos and handoff.
- Routing examples and Python standard-library utilities for validation, context initialization, ZIP generation and tests.

## Install and use
Copy the folder into your repository (or keep it adjacent). Keep project-specific instructions in the project and use this pack as referenced playbooks. Open `AGENTS.md` and `SKILL_ROUTER.md`, provide the real task brief, then load one mode, one primary skill and only necessary supports. If an agent lacks native skills discovery, explicitly open or attach the Markdown files.

### Example prompts
**Hackathon:** “Read `AGENTS.md`, the router and `instructions/HACKATHON_MODE.md`. Inspect the actual brief/repo, choose the minimum useful skills, build a rubric-aligned vertical slice and preserve time for checks, rehearsal and submission.”

**Existing repo:** “Use `instructions/PROJECT_AUDIT_MODE.md` before editing. Classify each important feature as verified working, implemented but unverified, partial, disconnected, missing, broken or N/A. Trace the data flow, prioritize evidence-backed fixes and add regression tests.”

**CTF:** “Use `instructions/CTF_AND_WARGAME_MODE.md` only for the supplied challenge and authorized scope. Work in bounded hypotheses and verify any claimed proof against the real artifact.”

**SOC/DFIR:** “Use `instructions/DEFENSIVE_SOC_DFIR_MODE.md`. Distinguish synthetic from live telemetry, preserve provenance, deduplicate repeated events when suitable and verify alert-to-case-to-report flow.”

**Submission:** “Follow `instructions/FINAL_DEMO_AND_SUBMISSION.md`; map rubric items to actual evidence, run exact checks, disclose limits and validate the archive.”

## Safety
Active assessment requires explicit permission and bounded scope. Use local labs, synthetic data and test accounts where possible. When scope is unclear, stay passive/local. This pack excludes credential theft, stealth, persistence, destructive activity, malware deployment, exfiltration and unauthorized access. High-impact or irreversible actions require human approval.

## Validate / rebuild
Python 3.10+ intended; scripts use the standard library:
```bash
python scripts/validate_pack.py
python scripts/build_index.py --check
python scripts/check_preservation.py --original <old-pack-dir-or-zip>   # when upgrading
python -m unittest discover -s tests -v
python scripts/build_zip.py
```
Initialize resumable context safely:
```bash
python scripts/init_project_context.py --target ../PROJECT_CONTEXT.md
```
An existing target is not overwritten unless `--force` is explicit. The ZIP builder keeps one top-level folder and excludes caches, VCS metadata, environment files, generated archives and unrelated files.

## Limits and customization
Native skill discovery and agent-specific conventions vary by version. Platform guides therefore recommend a portable manual fallback instead of promising universal auto-loading. The pack supports engineering judgment; it does not guarantee correctness, security, research novelty or a competition win. Verify claims against the actual code, environment, data and source material.
