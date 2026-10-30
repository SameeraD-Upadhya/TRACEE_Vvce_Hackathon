# TRACEE Phase 1 (Demo-Critical) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the five demo-critical gaps the hackathon judges flagged — missing relationship graph, placeholder Findings & Reports, no visible tamper detection, no realistic end-to-end demo, and no visible gap/log-deletion reasoning — without breaking any of the 745 passing tests or the non-overclaiming invariants.

**Architecture:** Each workstream adds one or two new `src/tracee/*.py` modules that mirror the existing `reconstruction_service.py` storage pattern (symlink-safe directories, exclusive file locks, canonical-JSON content hashing, append-only where relevant), wires 1-6 new routes into the single `api.py` FastAPI closure behind the existing bearer-auth middleware, and replaces the two literal UI placeholders (`ui/index.html:180`, `:183-185`). Tasks are ordered by real dependency, not the master prompt's listed order: a demo-vault skeleton must exist before the tamper demo can use it, and relationships/reports/gaps must exist before the full end-to-end scenario can exercise them.

**Tech Stack:** Python 3.10+, FastAPI/uvicorn/python-multipart only (stdlib otherwise), vanilla HTML/CSS/JS (no build step, no CDN), pytest, Node's built-in test runner for `ui/*.test.js`.

**Spec:** `TRACEE_master_prompt.md` (originally `C:\projectt\TRACEE_master_prompt.md`), Sections 1, 2, 6 (W1/W2/W4/W6/W7), 8, 9.

## Global Constraints

- Same input -> same output, byte-for-byte, including IDs (Section 2.3). Every derived record carries source observation and evidence IDs.
- All 745 existing tests (1 skipped) must keep passing; the Node check (`node --check ui/app.js`) must keep passing.
- Core stays Python stdlib + `fastapi`/`uvicorn`/`python-multipart`; anything else (e.g. a graph library) is forbidden - write layout/graph code by hand.
- Server binds to loopback by default; never `0.0.0.0`. No secrets in logs, URLs, or browser storage.
- Forbidden wording anywhere user-visible (UI, reports, docs): "proves", "detects attacks", "attack-agnostic", "attack graph", "identifies the attacker", "tamper-proof", "court-admissible", "AI-powered", "real-time", "production-ready", "scalable to enterprise". Required wording: "candidate", "lead", "co-observed", "records show", "not independently corroborated".
- Edge/graph semantics are "co-observed in the same evidence record" only - never infer across records or from temporal proximity.
- Missing data alone must never produce a possible-removal/deletion claim (existing invariant in `coverage.py`; gap detectors must preserve it).
- New on-disk records get their own `schema_version` (start at `"1.0"`) and live in a new vault subdirectory; never mutate the existing chain/metadata/activity schemas.
- Do not import from `archive_future/` - its imports are stale and broken. Mine it for ideas only.
- Every new route sits inside `create_app()` in `src/tracee/api.py` and is covered by the existing `require_api_bearer` middleware (already gates all of `/api/v1/*`); no new auth mechanism in this phase (that's W5, Phase 2).

## Review Focus

- **Backward compatibility of `VerificationResult`:** adding `failed_layer`/`layer_details` fields must not break existing keyword-argument construction or `state`/`evidence_id`/`message` consumers. Pinned by Task 2's explicit regression test plus the full-suite run after every task.
- **Symlink/path-traversal safety of new vault subdirectories:** `relationships/`, `reports/`, `reviews/`, `alerts.jsonl` must reuse the same symlink checks as `reconstruction_service.py` (`is_symlink()` guards before every mkdir/open). Pinned by a dedicated symlink-rejection test in Tasks 8, 11, and 12.
- **HTML report injection:** a log line containing `<script>` or other HTML must never render unescaped in `render_report_html`. Pinned by Task 10's hostile-content test.
- **Concurrent build-or-get races:** two near-simultaneous calls to build the same relationship graph or report must not corrupt storage or double-charge an ID. Pinned by a concurrency test in Tasks 8 and 11 mirroring `reconstruction_service.py`'s lock pattern.
- **Non-overclaiming wording regressions:** new UI copy, report copy, and gap explanations must avoid the Section 8 forbidden-word list. Pinned by a small grep-based assertion in Tasks 9, 10, 13, and 14 (a full repo-wide `tools/check_claims.py` is Phase 4/W12 scope, not duplicated here).

---

### Task 1: Demo vault marker and CLI skeleton (prerequisite for Task 6 and Task 17)

**Files:**
- Create: `src/tracee/demo.py`
- Modify: `src/tracee/cli.py` (`build_parser` ~l50, `run_command` ~l376)
- Test: `tests/test_demo.py`

**Interfaces:**
- Consumes: whatever vault-bootstrap helper `tests/conftest.py` already uses to build a `FilesystemVaultStore`-backed temp vault (read that fixture first and reuse it - do not re-implement vault bootstrap).
- Produces: `DEMO_MARKER_FILENAME: str`, `create_demo_marker(vault_dir: Path) -> None`, `is_demo_vault(vault_dir: Path) -> bool`, `create_demo_vault(base_dir: Path | None = None) -> Path`. Later tasks (6, 17) depend on exactly these four names.

- [ ] **Step 1: Write the failing test**

```python
def test_create_demo_vault_sets_marker(tmp_path):
    vault_dir = create_demo_vault(base_dir=tmp_path)
    assert is_demo_vault(vault_dir) is True

def test_is_demo_vault_false_for_ordinary_vault(tmp_path):
    assert is_demo_vault(tmp_path) is False
```

- [ ] **Step 2: Run** `pytest tests/test_demo.py -v` - expect FAIL (`demo` module not found).
- [ ] **Step 3: Implement** `create_demo_vault`/`is_demo_vault`/`create_demo_marker` in `src/tracee/demo.py`. Marker is a small JSON file (`{"marker": "tracee-demo-v1", "created_at": "<iso>"}`) written atomically (tempfile + `os.replace`, 0o600) at the vault root, following the same atomic-write style used elsewhere in the codebase (e.g. `reconstruction_service.py`'s `_persist`).
- [ ] **Step 4: Run** `pytest tests/test_demo.py -v` - expect PASS.
- [ ] **Step 5: Add the CLI skeleton.** In `cli.py`, add a `demo` subparser with an optional `tamper` sub-action and `--vault PATH` / `--reset` flags; wire `run_command` to call into `demo.py` (full behavior lands in Tasks 6 and 17 - for now `tracee demo` with no scenario wiring should still create the marked vault and print its path).
- [ ] **Step 6: Write test:** `test_cli_demo_subcommand_registered` in `tests/test_demo.py`, matching the existing argparse-smoke-test style already used in `tests/test_cli.py`.
- [ ] **Step 7: Run** full suite: `python -m pytest -q`. Expect 745+new passed, 1 skipped.
- [ ] **Step 8: Commit**

```bash
git add src/tracee/demo.py src/tracee/cli.py tests/test_demo.py
git commit -m "feat(demo): add demo vault marker and CLI skeleton"
```

---

### Task 2: Per-layer tamper detail in `VerificationEngine`

**Files:**
- Modify: `src/tracee/verify.py` (`VerificationResult` dataclass l44-55, `VerificationTamperError` l58-59, `_verify_evidence` l255, `_verify_metadata_binding` l300, `_verify_complete_chain` l318, `verify()` l90-152)
- Test: `tests/test_verify.py` (existing)

**Interfaces:**
- Produces: `VerificationResult.failed_layer: str | None = None` (one of `"evidence_hash"`, `"metadata_binding"`, `"chain_sequence"`, `"chain_link"`), `VerificationResult.layer_details: Mapping[str, str] = field(default_factory=dict)` (truncated 12-hex-char `expected_sha256_prefix`/`actual_sha256_prefix` keys where a hash comparison is available). `VerificationTamperError(message: str, *, layer: str, details: Mapping[str, str] | None = None)` - positional `message` stays compatible with any existing `str(exc)` call site.
- Task 3 consumes `VerificationResult.failed_layer`/`layer_details` directly.

- [ ] **Step 1: Write the failing tests** in `tests/test_verify.py`:

```python
def test_verify_tampered_evidence_reports_evidence_hash_layer(...):
    # flip a byte in the evidence file copy, then verify
    result = verify_evidence(...)
    assert result.state is VerificationState.TAMPERED
    assert result.failed_layer == "evidence_hash"
    assert "expected_sha256_prefix" in result.layer_details

def test_verify_tampered_metadata_binding_reports_layer(...): ...
def test_verify_bad_chain_sequence_reports_chain_sequence_layer(...): ...
def test_verify_bad_chain_link_reports_chain_link_layer(...): ...
def test_verification_result_accepts_omitted_layer_fields():
    # existing-style construction with only state/evidence_id/message still works
    result = VerificationResult(VerificationState.VALID, "x", "ok")
    assert result.failed_layer is None and result.layer_details == {}
```

- [ ] **Step 2: Run** `pytest tests/test_verify.py -v` - expect FAIL.
- [ ] **Step 3: Implement.** Add `layer`/`details` attributes to `VerificationTamperError.__init__`, storing them on the instance. Update the four raise sites to pass `layer=...` (and `details={"expected_sha256_prefix": ..., "actual_sha256_prefix": ...}` where both hashes are known - the size-mismatch branch in `_verify_evidence` has no hash to show, so `details={}` there is correct). Update `verify()`'s `except VerificationTamperError as exc` branch to read `exc.layer`/`exc.details` into the returned `VerificationResult`.
- [ ] **Step 4: Run** `pytest tests/test_verify.py -v` - expect PASS.
- [ ] **Step 5: Run full suite** `python -m pytest -q` - confirm no regression (existing tests that only check `state`/`evidence_id`/`message` are unaffected by new optional fields with defaults).
- [ ] **Step 6: Commit**

```bash
git add src/tracee/verify.py tests/test_verify.py
git commit -m "feat(verify): report which integrity layer failed with truncated hash details"
```

---

### Task 3: Bulk verify-all API route

**Files:**
- Modify: `src/tracee/api.py` (add route near the existing `GET /api/v1/evidence/{id}/verify`)
- Test: `tests/test_api.py` (existing)

**Interfaces:**
- Consumes: Task 2's `VerificationResult.failed_layer`/`layer_details`; the existing evidence-listing call already used by `GET /api/v1/evidence` (read that handler first and reuse its listing/pagination logic rather than re-deriving it).
- Produces: `POST /api/v1/verify-all` -> `{"results": [{"evidence_id", "state", "failed_layer", "layer_details", "message"}], "summary": {"total", "valid", "tampered", "missing", "invalid", "never_verified"}}`. Task 4 consumes this route's per-result shape to decide when to raise an alert.

- [ ] **Step 1: Write the failing test**

```python
def test_verify_all_returns_summary_counts(client, seeded_vault_with_one_tampered_evidence):
    response = client.post("/api/v1/verify-all", headers=auth_headers)
    body = response.json()
    assert body["summary"]["tampered"] == 1
    assert any(r["failed_layer"] for r in body["results"] if r["state"] == "TAMPERED")
```

- [ ] **Step 2: Run** `pytest tests/test_api.py -v -k verify_all` - expect FAIL (404).
- [ ] **Step 3: Implement** the route: list all evidence via the existing listing call, run `verify_evidence()` per item, aggregate counts, and write one `activity.append(event_type="verify_all", actor="local_api_token", outcome="success")` entry (actor string matches the existing single-shared-credential model; a named-principal actor is W5/Phase 2 scope).
- [ ] **Step 4: Run** `pytest tests/test_api.py -v -k verify_all` - expect PASS.
- [ ] **Step 5: Run full suite.**
- [ ] **Step 6: Commit**

```bash
git add src/tracee/api.py tests/test_api.py
git commit -m "feat(api): add bulk verify-all endpoint with dashboard summary counts"
```

---

### Task 4: Alerts for TAMPERED/MISSING results, with acknowledgement

**Files:**
- Create: `src/tracee/alerts.py`
- Modify: `src/tracee/api.py` (`GET /api/v1/alerts`, `POST /api/v1/alerts/{alert_id}/acknowledge`; call from the verify-all route when a result is TAMPERED/MISSING)
- Test: `tests/test_alerts.py`, additions to `tests/test_api.py`

**Interfaces:**
- Consumes: `locking.exclusive_file_lock`/`set_private_permissions` (same functions `activity.py` and `reconstruction_service.py` already import), Task 3's verify-all result shape.
- Produces: `AlertStore(vault_dir: Path)` with `.raise_alert(evidence_id: str, state: str, failed_layer: str | None) -> dict`, `.list_alerts(*, include_acknowledged: bool = False) -> list[dict]`, `.acknowledge(alert_id: str, *, actor: str) -> dict`. Alert IDs follow the existing `TRACE-<TAG>-<32hex>` convention (e.g. `TRACE-AL-<hex>`), matching `is_valid_reconstruction_id`'s style in `reconstruction_service.py`.

- [ ] **Step 1: Write the failing tests**

```python
def test_raise_alert_persists_unacknowledged(tmp_path): ...
def test_acknowledge_marks_alert_and_logs_activity(tmp_path): ...
def test_list_alerts_excludes_acknowledged_by_default(tmp_path): ...
def test_alert_store_rejects_symlinked_alerts_file(tmp_path): ...
```

- [ ] **Step 2: Run** `pytest tests/test_alerts.py -v` - expect FAIL.
- [ ] **Step 3: Implement** `alerts.py` as an append-only `alerts.jsonl` at the vault root, mirroring `activity.py`'s lock-file pattern (`_open_lock_file`/`exclusive_file_lock`) rather than inventing a new one. Acknowledging an alert both updates its record and calls `ActivityLog.append(event_type="alert_acknowledge", actor=actor, outcome="success", evidence_id=...)`.
- [ ] **Step 4: Wire into the verify-all route** from Task 3: for each result with `state in ("TAMPERED", "MISSING")`, call `alerts.raise_alert(...)`.
- [ ] **Step 5: Run** `pytest tests/test_alerts.py tests/test_api.py -v` - expect PASS.
- [ ] **Step 6: Run full suite.**
- [ ] **Step 7: Commit**

```bash
git add src/tracee/alerts.py src/tracee/api.py tests/test_alerts.py tests/test_api.py
git commit -m "feat(alerts): persist and acknowledge integrity alerts for tampered or missing evidence"
```

---

### Task 5: `tracee demo tamper` - safe tamper demonstration

**Files:**
- Modify: `src/tracee/demo.py` (add `tamper_demo_vault(vault_dir: Path) -> dict`)
- Modify: `src/tracee/cli.py` (wire `tracee demo tamper --vault PATH`)
- Test: additions to `tests/test_demo.py`

**Interfaces:**
- Consumes: Task 1's `is_demo_vault`.
- Produces: `tamper_demo_vault(vault_dir: Path) -> dict` - refuses (raises a dedicated `DemoError`) unless `is_demo_vault(vault_dir)` is true; on a marked demo vault, flips one byte in one evidence file (-> TAMPERED/`evidence_hash`), deletes a second evidence file (-> MISSING), and mutates one field of a third evidence's `chain.jsonl` record (-> TAMPERED/`chain_link`); returns `{"evidence_hash": evidence_id_a, "missing": evidence_id_b, "chain_link": evidence_id_c}`.

- [ ] **Step 1: Write the failing tests**

```python
def test_tamper_demo_vault_refuses_non_demo_vault(tmp_path):
    with pytest.raises(DemoError):
        tamper_demo_vault(tmp_path)

def test_tamper_demo_vault_produces_three_failure_modes(demo_vault_with_three_evidence):
    result = tamper_demo_vault(demo_vault_with_three_evidence)
    assert verify_evidence(...).state is VerificationState.TAMPERED  # evidence_hash target
    assert verify_evidence(...).state is VerificationState.MISSING   # missing target
    assert verify_evidence(...).failed_layer == "chain_link"          # chain target
```

- [ ] **Step 2: Run** `pytest tests/test_demo.py -v` - expect FAIL.
- [ ] **Step 3: Implement** `tamper_demo_vault` and wire the CLI subcommand.
- [ ] **Step 4: Run** `pytest tests/test_demo.py -v` - expect PASS.
- [ ] **Step 5: Run full suite.**
- [ ] **Step 6: Commit**

```bash
git add src/tracee/demo.py src/tracee/cli.py tests/test_demo.py
git commit -m "feat(demo): add safe tamper demonstration restricted to marked demo vaults"
```

---

### Task 6: Dashboard summary cards, chain visualizer, and alert banner (UI)

**Files:**
- Modify: `ui/index.html` (dashboard summary-card markup; verification view gets a chain-visualizer container)
- Modify: `ui/app.js` (`renderDashboard` ~l342: real counts from `POST /api/v1/verify-all`; `renderVerification` ~l487: per-layer failure display with a copy-truncated-hash button and a horizontal chain visualizer; new alert banner + acknowledge wiring)
- Modify: `ui/styles.css`
- Test: manual verification via the running demo (no Python change in this task)

**Interfaces:**
- Consumes: Task 3's `/api/v1/verify-all` response shape, Task 4's `/api/v1/alerts` and acknowledge route.

- [ ] **Step 1: Implement** the dashboard cards (total/verified/tampered/missing/invalid/never-verified) backed by `verify-all`, replacing any hard-coded placeholder counts.
- [ ] **Step 2: Implement** the verification-view per-layer display: show `failed_layer` and truncated `layer_details` hashes with a copy button; render the chain as a horizontal sequence list with sequence number, hash prefix, and link-status marker, highlighting exactly where a break occurs.
- [ ] **Step 3: Implement** the alert banner: a persistent, visible banner on the Dashboard for any unacknowledged alert, with an "Acknowledge" button calling `POST /api/v1/alerts/{id}/acknowledge`.
- [ ] **Step 4: Run** `node --check ui/app.js` - expect no syntax errors. Run `python -m pytest -q` - expect no regression.
- [ ] **Step 5: Manually verify.** Start the server against a `tracee demo` vault (Task 1/5), run `tracee demo tamper --vault <path>`, reload the dashboard, confirm the alert banner and per-layer verification detail appear. Capture a real screenshot via the `chrome-devtools` MCP tool to `docs/screenshots/tamper-detected.png` - never fabricate this screenshot.
- [ ] **Step 6: Commit**

```bash
git add ui/index.html ui/app.js ui/styles.css docs/screenshots/tamper-detected.png
git commit -m "feat(ui): show real dashboard summary cards, chain visualizer, and alert banner"
```

---

### Task 7: Deterministic entity/edge extraction (`src/tracee/relationships.py`)

**Files:**
- Create: `src/tracee/relationships.py`
- Test: `tests/test_relationships.py`

**Interfaces:**
- Consumes: `events.SourceObservation` exactly as defined (attributes keys observed in parsers: `user`, `ip`, `source_ip`, `hostname`/`host`, `process`, `pid`, `file`, per the parser inventory already confirmed in this repo).
- Produces: `Entity(entity_id: str, entity_type: str, normalized_key: str, schema_version: str = "1.0")`, `Edge(edge_id: str, edge_type: str, source_entity_id: str, target_entity_id: str, first_seen_utc: str | None, last_seen_utc: str | None, count: int, supporting_observation_ids: tuple[str, ...], evidence_ids: tuple[str, ...], ambiguous: bool = False, schema_version: str = "1.0")`, `RelationshipGraph(graph_id: str, evidence_id: str, analysis_id: str, source_sha256: str, entities: tuple[Entity, ...], edges: tuple[Edge, ...], truncated: bool, schema_version: str = "1.0")` with `.to_dict()`. `build_relationships(observations: tuple[SourceObservation, ...], *, evidence_id: str, analysis_id: str, source_sha256: str, max_entities: int = 2000, max_edges: int = 5000) -> RelationshipGraph`. Task 8 consumes `build_relationships` and `RelationshipGraph.to_dict()` directly.
- Edge types: `logged_in_on` (user->host), `connected_from` (user or host<->ip), `ran_on` (process->host), `executed_by` (process->user, only when the observation attributes explicitly state it), `accessed` (process or user->file), `connected_to` (process or host->ip). Entity IDs: `"TRACE-EN-" + hashlib.sha256(f"{entity_type}:{normalized_key}".encode()).hexdigest()[:32]`. Normalization: IPs via `ipaddress.ip_address(value).compressed`; user/host/process values lowercased and stripped; never merge two entities unless normalized keys match exactly.

- [ ] **Step 1: Write the failing tests**

```python
def test_build_relationships_is_byte_deterministic(sample_observations):
    a = build_relationships(sample_observations, evidence_id=..., analysis_id=..., source_sha256=...)
    b = build_relationships(sample_observations, evidence_id=..., analysis_id=..., source_sha256=...)
    assert canonical_json(a.to_dict()) == canonical_json(b.to_dict())

def test_logged_in_on_edge_from_user_and_host_attributes(...): ...
def test_connected_to_edge_normalizes_ip_representations(...):
    # "192.168.1.1" and "192.168.001.001" must resolve to the same entity_id
def test_ambiguous_edge_when_one_observation_has_conflicting_attribute_values(...): ...
def test_edge_without_supporting_observations_is_rejected():
    with pytest.raises(ModelValidationError):
        Edge(..., supporting_observation_ids=())
def test_truncation_flag_set_when_entity_count_exceeds_max(...): ...
def test_no_edge_inferred_across_separate_observation_records(...):
    # two observations that would "connect" only via shared timing must not produce an edge
```

- [ ] **Step 2: Run** `pytest tests/test_relationships.py -v` - expect FAIL.
- [ ] **Step 3: Implement** `relationships.py`. Iterate observations in `observation_id`-sorted order for determinism; derive every entity/edge from a single observation's own attributes only (never across observations); raise/validate in `__post_init__` the same way the rest of the codebase's frozen dataclasses do.
- [ ] **Step 4: Run** `pytest tests/test_relationships.py -v` - expect PASS.
- [ ] **Step 5: Run full suite.**
- [ ] **Step 6: Commit**

```bash
git add src/tracee/relationships.py tests/test_relationships.py
git commit -m "feat(relationships): add deterministic entity and edge extraction from analyses"
```

---

### Task 8: Relationship storage and API routes

**Files:**
- Create: `src/tracee/relationship_service.py` (mirror `reconstruction_service.py`'s storage pattern: `vault_dir/"relationships"/<evidence_id>/<graph_id>.json`, lock file, `content_sha256`, create-or-return-existing)
- Modify: `src/tracee/api.py` - `POST /api/v1/evidence/{id}/analyses/{analysis_id}/relationships`, `GET .../relationships`, `GET .../relationships/{rel_id}` with query filters `entity_type`, `since`/`until`, `entity_id`+`depth`
- Test: `tests/test_relationship_service.py`, additions to `tests/test_api.py`

**Interfaces:**
- Consumes: Task 7's `build_relationships`/`RelationshipGraph`; `ReconstructionService`'s exact method shapes as the template (`reconstruct`, `_read`, `list_reconstructions`, `get_reconstruction`, including their symlink/lock/content-hash checks) - substitute "relationship"/"graph" vocabulary, do not invent a different storage discipline.
- Produces: `RelationshipService(service: TraceeService)` with `.build_or_get(evidence_id: str, analysis_id: str) -> dict`, `.get(evidence_id: str, graph_id: str, *, entity_type: str | None = None, since: str | None = None, until: str | None = None, entity_id: str | None = None, depth: int | None = None, offset: int, limit: int) -> dict`, `.list(evidence_id: str, *, offset: int, limit: int) -> tuple[list[dict], int]`. Task 10 (reporting) and Task 9 (UI) consume these.

- [ ] **Step 1: Write the failing tests**

```python
def test_build_or_get_is_idempotent_returns_same_graph_id(...): ...
def test_relationships_route_requires_currently_verified_source(...):
    # stale/tampered source -> 409, mirrors ReconstructionService._verify_current_source
def test_relationships_filter_by_entity_type(...): ...
def test_relationships_neighborhood_depth_limit(...): ...
def test_relationship_service_rejects_symlinked_storage_directory(tmp_path): ...
def test_concurrent_build_or_get_does_not_duplicate_graph(...):
    # two threads/processes calling build_or_get at once produce one stored graph
```

- [ ] **Step 2: Run** `pytest tests/test_relationship_service.py -v` - expect FAIL.
- [ ] **Step 3: Implement** `relationship_service.py` and the three API routes; call `activity.append(event_type="relationship_build", actor="local_api_token", outcome="success", evidence_id=evidence_id)` on a successful build.
- [ ] **Step 4: Run** `pytest tests/test_relationship_service.py tests/test_api.py -v` - expect PASS.
- [ ] **Step 5: Run full suite.**
- [ ] **Step 6: Commit**

```bash
git add src/tracee/relationship_service.py src/tracee/api.py tests/test_relationship_service.py tests/test_api.py
git commit -m "feat(api): persist and expose relationship graphs per analysis"
```

---

### Task 9: Timeline & Relationships graph UI

**Files:**
- Modify: `ui/index.html` (remove the `.relationships-notice` block at l180; add a Timeline/Graph toggle, SVG container, legend, entity-type filters, time-range slider, search, side panel, keyboard-nav affordances, and a text/table alternative view, plus the fixed banner: "Edges mean co-observed in the same evidence record. They do not indicate causation or an attack path.")
- Modify: `ui/app.js` (`renderTimeline` ~l1160, `loadTimeline` ~l1206; add a pure, testable `computeGraphLayout(entities, edges, {width, height}) -> Map<entityId, {x, y}>`)
- Modify: `ui/styles.css` (remove `.relationships-notice` styles if now unused elsewhere; add legend/graph styles meeting WCAG AA contrast in both themes; non-color status cues)
- Create: `tests/test_relationship_layout.test.js` (same Node test-runner pattern as `tests/test_reconstruction_presentation.test.js` - check that file's own run command first and reuse it)

**Interfaces:**
- Consumes: Task 8's relationship API response shape.
- Produces: `computeGraphLayout` and the filter/search pure-logic helpers, exported the same UMD way `reconstruction-presentation.js` already does, so Task 9's own JS tests and any future reuse can import them without a DOM.

- [ ] **Step 1: Write the failing JS tests**

```js
test("computeGraphLayout is deterministic for the same input", () => { ... });
test("computeGraphLayout assigns every entity a finite x and y", () => { ... });
test("filterEntitiesByType only returns matching nodes", () => { ... });
```

- [ ] **Step 2: Run** the existing Node test command (same one used for `test_reconstruction_presentation.test.js`) - expect FAIL.
- [ ] **Step 3: Implement** `computeGraphLayout` and the filter/search helpers in `app.js` (check its current line count first - if it has already grown past what one file should hold, split the new graph logic into `ui/graph.js` loaded by `index.html`; otherwise follow the codebase's existing single-file convention).
- [ ] **Step 4: Wire into `renderTimeline`:** toggle switches between the existing timeline list and the new inline-SVG graph; render legend (shape + color + text label, not color alone), node/edge counts, the banner text above, click-to-open side panel showing supporting observations/source locators/parser/raw timestamps, keyboard navigation between nodes (tabindex + arrow keys), and a text/table fallback view of the same data. Remove the old "Relationships are not available" notice entirely; keep a clear, honest empty state when an analysis has zero entities.
- [ ] **Step 5: Run** the JS tests - expect PASS. Run `node --check ui/app.js`. Run `python -m pytest -q` - confirm no regression.
- [ ] **Step 6: Grep the new UI copy** against the Section 8 forbidden-word list; fix any match.
- [ ] **Step 7: Manually verify** via a `tracee demo` vault; capture a real screenshot via `chrome-devtools` to `docs/screenshots/relationship-graph.png`.
- [ ] **Step 8: Commit**

```bash
git add ui/index.html ui/app.js ui/styles.css tests/test_relationship_layout.test.js docs/screenshots/relationship-graph.png
git commit -m "feat(ui): render relationship graph with legend, filters, and accessible fallback"
```

---

### Task 10: Report builder core (`src/tracee/reporting.py`)

**Files:**
- Create: `src/tracee/reporting.py`
- Test: `tests/test_reporting.py`

**Interfaces:**
- Consumes: `EvidenceAnalysisService`/`ReconstructionService`/`RelationshipService` (Task 8) outputs; Task 14's gap detectors (built before this task - see ordering note below); `coverage.py`; `ActivityLog.recent()`.
- Produces: `REPORT_SCHEMA_VERSION = "1.0"`; `build_report(service: TraceeService, *, evidence_ids: tuple[str, ...], generated_by: str) -> dict` returning `{"generation": {"report_id", "generated_at", "generated_by"}, "content": {...everything else...}}` - only `"content"` is hashed, documented in the docstring, so the report stays deterministic apart from its own generation metadata. `render_report_html(report: dict) -> str` - self-contained, no external assets, every evidence-derived string passed through `html.escape`. Task 11 consumes both functions directly.
- **Ordering note:** this task depends on Task 14 (gap detectors) for the coverage/gap summary section. If Task 14 has not landed yet when this task starts, stub the gap section as `{"gaps": [], "note": "gap detectors not yet available"}` and file a follow-up - do not block the whole report on it, but do not fabricate gap data either.

- [ ] **Step 1: Write the failing tests**

```python
def test_build_report_content_is_deterministic_excluding_generation_metadata(...):
    a, b = build_report(...), build_report(...)
    assert a["content"] == b["content"]
    assert a["generation"]["report_id"] != b["generation"]["report_id"]

def test_build_report_shows_tampered_evidence_prominently(seeded_tampered_evidence):
    report = build_report(...)
    assert "TAMPERED" in json.dumps(report["content"])

def test_render_report_html_escapes_hostile_log_content(...):
    report = build_report(...)  # one observation attribute contains "<script>alert(1)</script>"
    html_out = render_report_html(report)
    assert "<script>alert(1)</script>" not in html_out
    assert "&lt;script&gt;" in html_out

def test_build_report_never_uses_forbidden_wording(...):
    text = json.dumps(report["content"])
    for forbidden in ("proves", "attack-agnostic", "identifies the attacker", "tamper-proof"):
        assert forbidden not in text.lower()
```

- [ ] **Step 2: Run** `pytest tests/test_reporting.py -v` - expect FAIL.
- [ ] **Step 3: Implement** `reporting.py`, reusing the services already built rather than re-querying the filesystem directly; compute `content_sha256` using the same canonical-JSON + SHA-256 pattern as `reconstruction_service.py`'s `_canonical`.
- [ ] **Step 4: Run** `pytest tests/test_reporting.py -v` - expect PASS.
- [ ] **Step 5: Run full suite.**
- [ ] **Step 6: Commit**

```bash
git add src/tracee/reporting.py tests/test_reporting.py
git commit -m "feat(reporting): build deterministic, escaped case reports from existing evidence state"
```

---

### Task 11: Report storage, export, manifest, and API

**Files:**
- Create: `src/tracee/report_service.py` (mirror `reconstruction_service.py` storage pattern: `vault_dir/"reports"/<report_id>.json` + rendered `.html`, a manifest listing every exported file's SHA-256, immutable once written)
- Modify: `src/tracee/api.py` - `POST /api/v1/reports` (body: `evidence_ids`), `GET /api/v1/reports`, `GET /api/v1/reports/{report_id}`, `GET /api/v1/reports/{report_id}/html`, `GET /api/v1/reports/{report_id}/manifest`, `POST /api/v1/reports/{report_id}/verify`
- Test: `tests/test_report_service.py`, additions to `tests/test_api.py`

**Interfaces:**
- Consumes: Task 10's `build_report`/`render_report_html`.
- Produces: `ReportService(service: TraceeService)` with `.generate(evidence_ids: tuple[str, ...], generated_by: str) -> dict`, `.get(report_id: str) -> dict`, `.get_html(report_id: str) -> str`, `.get_manifest(report_id: str) -> dict`, `.verify(report_id: str) -> dict` (`{"valid": bool, "mismatches": [str, ...]}`), `.list(*, offset: int, limit: int) -> tuple[list[dict], int]`.

- [ ] **Step 1: Write the failing tests**

```python
def test_generate_report_is_immutable_and_hash_stable(...): ...
def test_report_manifest_lists_every_exported_file_with_sha256(...): ...
def test_verify_report_detects_manifest_tampering(...):
    # flip a byte in the stored html file, assert valid is False and the path is named in mismatches
def test_report_storage_rejects_symlinked_reports_directory(tmp_path): ...
def test_concurrent_generate_does_not_corrupt_storage(...): ...
```

- [ ] **Step 2: Run** `pytest tests/test_report_service.py -v` - expect FAIL.
- [ ] **Step 3: Implement** `report_service.py` and the five API routes; call `activity.append(event_type="report_generate", actor="local_api_token", outcome="success")` on generation, recording the report's own content hash.
- [ ] **Step 4: Run** `pytest tests/test_report_service.py tests/test_api.py -v` - expect PASS.
- [ ] **Step 5: Run full suite.**
- [ ] **Step 6: Commit**

```bash
git add src/tracee/report_service.py src/tracee/api.py tests/test_report_service.py tests/test_api.py
git commit -m "feat(api): persist, export, and verify case reports with a file manifest"
```

---

### Task 12: Review workflow for reconstruction candidates

**Files:**
- Create: `src/tracee/review.py` (append-only review records, `vault_dir/"reviews"/<evidence_id>.jsonl`, reusing `activity.py`'s lock+append pattern)
- Modify: `src/tracee/api.py` - `POST /api/v1/evidence/{id}/reconstructions/{reconstruction_id}/hypotheses/{hypothesis_id}/review`
- Test: `tests/test_review.py`

**Interfaces:**
- Consumes: `hypotheses.ReviewStatus` enum values (`ACCEPTED`, `REJECTED`, `NEEDS_MORE_EVIDENCE`) as the internal storage mapping for the master prompt's external decision strings.
- Produces: `ReviewStore(vault_dir: Path)` with `.record(*, hypothesis_id: str, decision: str, note: str, principal: str) -> dict` where `decision` is one of `"reviewed-accepted-as-lead"`, `"reviewed-rejected"`, `"needs-more-evidence"`, and `.history(hypothesis_id: str) -> list[dict]`.

- [ ] **Step 1: Write the failing tests**

```python
def test_record_review_is_append_only(...):
    # two records for the same hypothesis_id both persist, in order
def test_record_review_rejects_unknown_decision(...):
    with pytest.raises(ValueError):
        store.record(hypothesis_id=..., decision="not-a-real-decision", note="", principal="local_api_token")
def test_review_storage_rejects_symlinked_reviews_directory(tmp_path): ...
```

- [ ] **Step 2: Run** `pytest tests/test_review.py -v` - expect FAIL.
- [ ] **Step 3: Implement** `review.py` and the API route.
- [ ] **Step 4: Run** `pytest tests/test_review.py -v` - expect PASS.
- [ ] **Step 5: Run full suite.**
- [ ] **Step 6: Commit**

```bash
git add src/tracee/review.py src/tracee/api.py tests/test_review.py
git commit -m "feat(review): add append-only investigator review decisions for reconstruction candidates"
```

---

### Task 13: Findings & Reports UI

**Files:**
- Modify: `ui/index.html` (replace the l183-185 placeholder with a reports list, a "Generate report" dialog with an evidence-multiselect scope and preview, download buttons, hash display, and a "verify this report" action)
- Modify: `ui/app.js` (new `renderReports` function wired into the existing `views` map / `showView`)
- Modify: `ui/styles.css`

**Interfaces:**
- Consumes: Task 11's report API routes and Task 12's review route.

- [ ] **Step 1: Implement** the reports list view, generate dialog, and review-decision controls per candidate (wired to Task 12's route).
- [ ] **Step 2: Run** `node --check ui/app.js`; add a JS test for any extracted pure helper (e.g. report-summary formatting) following the existing test file's pattern.
- [ ] **Step 3: Run** `python -m pytest -q` - confirm no regression.
- [ ] **Step 4: Grep new UI copy** against the Section 8 forbidden-word list.
- [ ] **Step 5: Manually verify** via `tracee demo`: generate a report, screenshot the Findings & Reports view and the exported HTML report to `docs/screenshots/` via `chrome-devtools`.
- [ ] **Step 6: Commit**

```bash
git add ui/index.html ui/app.js ui/styles.css docs/screenshots/
git commit -m "feat(ui): replace Findings & Reports placeholder with real report generation and review"
```

---

### Task 14: Gap and log-deletion detectors (`src/tracee/gaps.py`)

**Files:**
- Create: `src/tracee/gaps.py`
- Test: `tests/test_gaps.py`

**Interfaces:**
- Consumes: `coverage.SourceCoverage`, `coverage.assess_observation_availability`, `hypotheses.InterpretationState` (reuse `CHALLENGED`/`UNDERDETERMINED`/`INSUFFICIENT_INPUT` only - never introduce a "deleted" state).
- Produces: `GapAssessment(gap_id: str, gap_type: str, interpretation: InterpretationState, supporting_observation_ids: tuple[str, ...], assumptions: tuple[str, ...], limitations: tuple[str, ...], explanation: str, schema_version: str = "1.0")` where `gap_type` is one of `"sequence_gap"`, `"silence_interval"`, `"log_clear_indicator"`, `"cross_source_expectation"`, `"timestamp_discontinuity"`; five detector functions, each `(observations: tuple[SourceObservation, ...], coverage: SourceCoverage, **config) -> tuple[GapAssessment, ...]`, pure and deterministic. `SILENCE_THRESHOLD_SECONDS` default constant, overridable via `config`. Tasks 10 and 15 consume these detector functions and `GapAssessment.to_dict()` directly.

- [ ] **Step 1: Write the failing tests**

```python
def test_sequence_gap_detects_skipped_record_number(...): ...
def test_silence_interval_detects_regular_source_going_quiet(...): ...
def test_silence_interval_does_not_fire_for_naturally_quiet_host(...):
    # benign look-alike: must return an empty tuple
def test_log_clear_indicator_is_recorded_as_observed_event_not_tampering(...):
    assessment = detect_log_clear_indicator(...)[0]
    assert assessment.interpretation is not InterpretationState.CORROBORATED
    assert "deleted" not in assessment.explanation.lower()
def test_cross_source_expectation_requires_declared_coverage_of_source_b(...): ...
def test_timestamp_discontinuity_reported_as_clock_uncertainty(...): ...
def test_missing_data_alone_never_produces_possible_removal(...):
    # regression test mirroring coverage.py's own guarantee
```

- [ ] **Step 2: Run** `pytest tests/test_gaps.py -v` - expect FAIL.
- [ ] **Step 3: Implement** `gaps.py`.
- [ ] **Step 4: Run** `pytest tests/test_gaps.py -v` - expect PASS.
- [ ] **Step 5: Run full suite.**
- [ ] **Step 6: Commit**

```bash
git add src/tracee/gaps.py tests/test_gaps.py
git commit -m "feat(gaps): add versioned gap detectors with conservative, non-overclaiming interpretations"
```

---

### Task 15: Gap API and Coverage & Gaps UI panel

**Files:**
- Modify: `src/tracee/api.py` - `GET /api/v1/gap-rules` (registry of the 5 detectors with versions and false-positive-cause descriptions, same pattern as the existing `GET /api/v1/reconstruction/rules`), `POST /api/v1/evidence/{id}/analyses/{analysis_id}/gaps`, `GET .../gaps`
- Modify: `ui/index.html` (new "Coverage & Gaps" panel inside the Event Analysis & Reconstruction view)
- Modify: `ui/app.js`
- Test: additions to `tests/test_api.py`

**Interfaces:**
- Consumes: Task 14's detector functions.

- [ ] **Step 1: Write the failing test** `test_gaps_route_returns_detector_results_for_seeded_observations`.
- [ ] **Step 2: Run** `pytest tests/test_api.py -v -k gaps` - expect FAIL.
- [ ] **Step 3: Implement** the three routes.
- [ ] **Step 4: Implement** the UI panel: per-source coverage strip (covered/declared-uncovered/unknown), gap markers aligned to the timeline, and per-gap cards with interpretation state, "what we observed", "what we expected and why", "alternative explanations", and "what evidence would settle it".
- [ ] **Step 5: Run** `pytest tests/test_api.py -v`; `node --check ui/app.js`; full suite.
- [ ] **Step 6: Grep new UI copy** against the Section 8 forbidden-word list.
- [ ] **Step 7: Manually verify** via `tracee demo`; screenshot to `docs/screenshots/coverage-and-gaps.png`.
- [ ] **Step 8: Commit**

```bash
git add src/tracee/api.py ui/index.html ui/app.js docs/screenshots/coverage-and-gaps.png
git commit -m "feat(gaps): expose gap detectors via API and the Coverage and Gaps UI panel"
```

---

### Task 16: Scenario fixtures and frozen `EXPECTED_RESULTS.md`

**Files:**
- Create: `scenarios/intrusion-and-log-tamper/{auth.log, journal.jsonl, events.json, windows_events.json, README.md}`
- Create: `scenarios/intrusion-and-log-tamper/EXPECTED_RESULTS.md`
- Create: `scenarios/negative-control/{...same shape, benign admin activity}`

**Interfaces:**
- Consumes: Task 7's edge-type vocabulary and Task 14's gap-type vocabulary, so the fixtures' hand-traced expectations use exactly the same names the code will produce.

- [ ] **Step 1: Author the fixtures by hand**, matching the master prompt's content spec: many failed SSH logins from one IP then a success (`auth.log`); sudo and a new process (`journal.jsonl`); file reads and an outbound connection to a second IP (`events.json`); a Windows logon and a log-cleared event (`windows_events.json`); one deliberate timestamp-conflict record; one timezone-unknown record; one declared logging-disabled interval (a gap).
- [ ] **Step 2: Author** `EXPECTED_RESULTS.md` by tracing the fixtures against Task 7/14's documented rules - do not run TRACEE on the data yet.
- [ ] **Step 3: Author the negative-control fixtures** (benign admin activity) that must not produce a CORROBORATED attack-like hypothesis.
- [ ] **Step 4: Commit** fixtures and `EXPECTED_RESULTS.md` together, in their own commit, before any later task runs TRACEE against them:

```bash
git add scenarios/
git commit -m "test(scenario): add intrusion-and-log-tamper fixtures and frozen expected results"
```

---

### Task 17: Full `tracee demo` wiring and end-to-end acceptance test

**Files:**
- Modify: `src/tracee/demo.py` (`run_demo(vault_dir: Path | None = None, *, reset: bool = False) -> dict`: ingest the scenario, run analysis per parser, build relationships, run gap detectors, run reconstruction, generate a report, start uvicorn on loopback, print a numbered walkthrough)
- Create: `tests/test_demo_scenario_end_to_end.py`
- Create: `tests/test_demo_negative_control.py`

**Interfaces:**
- Consumes: Task 1's demo-vault helpers, Task 16's fixtures/`EXPECTED_RESULTS.md`, and every service built in Tasks 7-15.

- [ ] **Step 1: Write the failing end-to-end test**, hand-mirroring `EXPECTED_RESULTS.md`'s declared entities/edges/gaps/interpretation states as Python constants (do not parse the Markdown file in the test).
- [ ] **Step 2: Write the negative-control test** asserting no CORROBORATED attack-like hypothesis is produced.
- [ ] **Step 3: Run** `pytest tests/test_demo_scenario_end_to_end.py tests/test_demo_negative_control.py -v` - expect FAIL.
- [ ] **Step 4: Implement** the full `run_demo` wiring, reusing - never re-implementing - the services from Tasks 7-15. Note: this is where Task 10's "stub the gap section" fallback (if used) gets replaced with the real Task 14 output.
- [ ] **Step 5: Run** the two new tests - expect PASS. Run the full suite (745+new, 1 skipped) and `node --check ui/app.js`.
- [ ] **Step 6: Commit**

```bash
git add src/tracee/demo.py tests/test_demo_scenario_end_to_end.py tests/test_demo_negative_control.py
git commit -m "feat(demo): wire full scenario ingest-to-report pipeline and add end-to-end acceptance test"
```

---

### Task 18: Measured manual-baseline-vs-TRACEE timing comparison

**Files:**
- Create: `tools/baseline_grep_timing.py` (scripted, timed `grep`/`sort`-equivalent baseline over the Task 16 scenario files)
- Create: `docs/research/MANUAL_BASELINE.md`

- [ ] **Step 1: Implement** the timing script, counting manual steps and wall-clock time.
- [ ] **Step 2: Run it 5 times**, record the median.
- [ ] **Step 3: Write** `MANUAL_BASELINE.md` with only measured numbers, the method, and an explicit "not extrapolated to real-world savings" caveat.
- [ ] **Step 4: Commit**

```bash
git add tools/baseline_grep_timing.py docs/research/MANUAL_BASELINE.md
git commit -m "docs(demo): record measured manual-baseline-vs-TRACEE timing comparison"
```

---

## Phase 1 exit criteria

- `python -m pytest -q` passes (745 pre-existing + all new tests), 1 skip unchanged.
- `node --check ui/app.js` and all `tests/*.test.js` pass.
- `tracee demo` runs from a clean checkout, and `tracee demo tamper --vault <path>` demonstrates all three failure modes live.
- The Timeline & Relationships and Findings & Reports views show real data with no placeholder text.
- The end-to-end scenario test matches `EXPECTED_RESULTS.md`; the negative control produces no false positive.
- `docs/screenshots/` contains real screenshots of: the dashboard with an active alert, the chain visualizer mid-break, the relationship graph, the Coverage & Gaps panel, and a generated report.
