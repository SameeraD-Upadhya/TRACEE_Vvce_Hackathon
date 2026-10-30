# Project Audit Mode

**Do not edit first and investigate later.** Start with worktree status and read-only inventory.

## Feature status vocabulary
- **Verified working:** relevant behavior executed and passed a defined check.
- **Implemented but unverified:** code exists, execution not proved.
- **Partial:** some required paths/conditions work, others do not.
- **Disconnected:** implementation exists but is not wired into the real workflow.
- **Missing:** no implementation evidence found.
- **Broken:** reproducible failure evidence exists.
- **Not applicable:** requirement does not apply, with reason.

## Audit procedure
1. Record repository state/local changes. Read project instructions and docs.
2. Inventory runtime, entry points, manifests, APIs, persistence, workers, external integrations, tests, CI and startup/deployment steps.
3. Trace critical flows: input → validation → processing → persistence → API/state → UI/display → logging/error handling.
4. Compare docs to code. Separate confirmed defects, hypotheses, enhancements and missing requirements.
5. For each hypothesis, specify a distinguishing experiment. Rank issues by impact, likelihood, event relevance, effort and dependency.
6. Propose the smallest safe fix with a regression check. Avoid broad rewrites and destructive reset/cleanup without explicit need and approval.
7. Fix one priority at a time, run targeted verification and inspect the diff.

## Common traps to check
- Counters are maintained separately from records and drift.
- Reset clears visual state but not server, worker, database or cache state.
- UI reports success before durable write succeeds.
- Repeated events create unbounded duplicate incident logs.
- Graph/table/dashboard use stale or mismatched IDs.
- Exceptions are swallowed, or tests pass only because assertions were weakened.

Report a feature inventory, high-value data-flow map, prioritized issue table, exact command/results, hypotheses and regression plan. If tests cannot run, report static evidence only; do not claim execution.
