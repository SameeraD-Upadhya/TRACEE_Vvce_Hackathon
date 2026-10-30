# Hackathon Mode

Optimize for rubric coverage and a reliable demo, not for maximum feature count. Inspect event rules, judging criteria, team capacity, available APIs, permitted tools and submission format. Never promise a win.

## Time plans
| Time remaining | Recommended split | Minimum finish |
|---|---|---|
| 5 min | Brief/scope → tiny core result → one check | Honest artifact/result and limitations. |
| 15 min | 2 min intake, 3 min inspect, 6 min slice, 2 min verify, 2 min explain | One narrow runnable/inspectable path. |
| 30 min | 4 min intake, 5 inspect, 12 build, 5 integrate/test, 4 demo/submit | End-to-end happy path and fallback. |
| 60 min | 8 intake, 8 inspect/plan, 25 build/integrate, 10 verify, 9 rehearse/package | Tested core and rubric mapping. |
| Multi-hour | 10–15% intake/baseline; 45–55% core; 15–20% integration/tests; final 15–20% demo/submission | Freeze features early enough to verify. |

Treat splits as heuristics; preserve the verification and submission block.

## Priority and cut line
Score candidate features against published rubric value, user impact, feasibility, dependencies, risk, demo reliability and verification cost. Build rubric-required behaviors, then one working differentiator. Defer anything that depends on missing credentials/data, cannot be integrated, or cannot be tested before deadline. A small end-to-end slice beats disconnected screens. Every visible control must work or be labeled mock/demo; never present fixture telemetry as live.

## Integration and final lock
Agree on API/data contracts and file ownership before parallel work. Integrate early, not at the deadline. Verify startup, normal/error/empty states, persistence if claimed, changed-file diff and secret hygiene. In the final lock window, stop feature additions; rehearse the actual flow, map rubric criteria to evidence, validate package structure and record exact command results. Fix only a release-blocking defect after freeze, then rerun affected checks.
## Unfamiliar problem statements and claims
Extract in one table the judging criteria, constraints, deadlines, permitted tools/data and required deliverables. State the problem, target user and measurable impact in one sentence each; do not invent impact figures. Separate must-have MVP behavior from optional enhancements, choose the most feasible defensible approach, and name the real differentiator only as far as evidence supports (if similar work exists, describe the actual difference). Use reproducible or clearly disclosed synthetic data. Keep a claims ledger (`templates/claims-ledger.md`), prepare architecture diagram, setup steps, test evidence and answers to likely judge questions (limits, trade-offs, security risks, future work), and present only verified claims.
