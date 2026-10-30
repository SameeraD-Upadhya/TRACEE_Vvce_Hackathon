# Project Build Mode

Use for a new product, major feature or intentional refactor. Respect the repository's current stack unless evidence justifies a change.

1. **Discover:** inspect instructions, worktree, runtimes, manifests/lockfiles, routes, data schema, services, tests, CI, config and secrets handling.
2. **Define:** turn the requested user outcome into observable checks and non-goals; identify authorization, sensitive data and failure modes.
3. **Design:** sketch components, data movement, trust boundaries, external dependencies and error paths. Avoid architecture that has no acceptance benefit.
4. **Slice:** choose one user action that traverses input validation → business logic → persistence/adapter → output/UI. Add a representative test.
5. **Implement:** targeted edits, typed/validated boundaries, explicit errors, environment-based configuration, bounded timeouts/resources, and least privilege.
6. **Integrate:** check contracts, identifiers, timestamp semantics, async behavior, persistence, migration needs and loading/empty/error states.
7. **Verify:** unit/integration/UI/security tests as relevant; capture exact commands and outcomes; review diffs and dependency changes.
8. **Hand off:** document setup, real versus mocked components, operational risks, rollback/cleanup, limits and next action.

Prefer the simplest architecture that satisfies demonstrated needs. Treat AI output as advisory and validate it before consequential actions. Keep response actions separate from detection, with approval and rollback safeguards. Done means written acceptance checks were exercised or blocked explicitly, failure paths are understood, unrelated work is preserved, and another person can reproduce the slice.
**Gates before calling a slice done:** a threat/abuse-case pass for sensitive or privileged functionality (`cybersecurity/threat-modeling-and-abuse-cases`); secrets outside the tree and audit events for consequential actions (`cybersecurity/secrets-and-audit-logging`); denied-case and malformed-input tests (`cybersecurity/security-testing-and-adversarial-validation`). Shared product-integrity rules: `instructions/COMMON_SKILL_RULES.md`.
