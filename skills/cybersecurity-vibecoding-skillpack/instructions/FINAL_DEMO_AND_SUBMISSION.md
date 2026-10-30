# Final Demo and Submission

1. Read format, time, naming and judging requirements.
2. Choose one real end-to-end walkthrough and map every rubric criterion to a screen, artifact, test or explanation.
3. Reproduce setup/startup from a documented environment; validate config placeholders, ports, fixture/reset behavior and cleanup.
4. Run targeted and available broader checks; save exact commands, exit status and output summary. Mark unavailable checks blocked/not run.
5. Rehearse normal, empty, invalid, service-failure and recovery states where relevant. Ensure controls and status indicators match actual behavior.
6. Inspect diffs and package contents for secrets, private data, unrelated files, fake status values, debug leaks and broken links.
7. Explain problem/user, architecture/data flow, trust boundaries, real versus mocked services, evidence, differentiator and known limits.
8. Prepare only permitted fallbacks; label recordings and simulated fixtures accurately.
9. Build the exact submission, verify required files, archive integrity, root paths, startup instructions and constraints.

Demo order: problem → workflow → observable evidence → differentiator → reliability check → limits → reproduction. After feature freeze, fix only release-blocking defects and rerun affected checks. Never pretend telemetry, tests or model responses are live or successful without evidence.
Before presenting, complete `templates/claims-ledger.md`: each claim is verified by an executed check, relabeled (partial, mocked, synthetic) or removed.
