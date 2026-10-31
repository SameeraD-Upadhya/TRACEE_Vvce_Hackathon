"use strict";

const PREVIEW_LIMIT = 8;
const reconstructionPresentation = window.TraceeReconstructionPresentation;
const state = {
  evidence: [],
  inventoryStatus: "loading",
  inventoryErrorCode: null,
  selectedId: null,
  currentView: "dashboard",
  activityStatus: "idle",
  activity: [],
  analysis: { evidenceId: null, analyses: [], analysisOffset: 0, analysisTotal: 0, analysisId: null, detail: null, detailOffset: 0, runs: [], runsOffset: 0, runsTotal: 0, reconstructionId: null, reconstruction: null, hypothesisOffset: 0, skippedOffset: 0, generation: 0 },
  timeline: { evidenceId: null, analysisId: null, analyses: [], result: null, offset: 0, selectedEventId: null, generation: 0 },
};
let uploadFile = null;
let uploadController = null;
let uploadedEvidenceId = null;
let apiAccessToken = null;

const byId = (id) => document.getElementById(id);
const views = {
  dashboard: "Dashboard",
  evidence: "Evidence Explorer",
  verification: "Integrity & Recovery",
  mtls: "Adaptive mTLS Lab",
  replay: "Dataset Replay",
  activity: "Investigation Activity",
  analysis: "Event Analysis & Reconstruction",
  timeline: "Timeline & Correlation",
  reports: "Findings & Reports",
};

function element(tag, className = "", text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function safeFilename(value) {
  if (typeof value !== "string" || !value.trim()) return "Unnamed evidence file";
  return value.replaceAll("\\", "/").split("/").filter(Boolean).pop() || "Unnamed evidence file";
}

function formatDate(value) {
  if (typeof value !== "string") return "Unknown timestamp";
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return "Unknown timestamp";
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(parsed);
}

function formatSize(value) {
  if (!Number.isFinite(value) || value < 0) return "Unknown";
  if (value < 1024) return `${value} bytes`;
  const units = ["KB", "MB", "GB", "TB"];
  let amount = value;
  let unit = -1;
  do {
    amount /= 1024;
    unit += 1;
  } while (amount >= 1024 && unit < units.length - 1);
  return `${amount.toFixed(amount >= 10 ? 1 : 2)} ${units[unit]}`;
}

function setAlert(id, message) {
  const alert = byId(id);
  alert.textContent = message;
  alert.classList.toggle("hidden", !message);
}

function apiErrorMessage(payload, status) {
  const code = payload?.error?.code;
  const messages = {
    vault_not_configured: "No vault is configured. Set TRACEE_API_VAULT_DIR and restart the local API.",
    vault_unavailable: "The configured vault is unavailable. Check its location, metadata directory, and local access permissions.",
    api_auth_not_configured: "The server has no API credential configured. Contact the local API operator.",
    api_auth_misconfigured: "The server API credential configuration is too weak. Contact the local API operator.",
    api_auth_required: "Authorize this page with the shared API credential to load evidence and investigation data.",
    invalid_evidence_id: "The evidence ID is invalid. Select a record returned by the inventory.",
    evidence_not_found: "The evidence metadata record was not found in the configured vault.",
    malformed_metadata: "A metadata record is malformed. The inventory cannot be displayed safely.",
    unreadable_metadata: "A metadata record could not be read. Check local file access and the API server logs.",
    internal_error: "The API encountered an unexpected internal error. Check the local server logs.",
    upload_disabled: "Upload is disabled by server configuration. Ask the local API operator to configure upload access.",
    upload_token_misconfigured: "Upload is unavailable because the server upload-token configuration is invalid. Contact the API operator.",
    unauthorized: "The API bearer credential was not accepted. Check it with the local API operator and retry.",
    invalid_origin: "The API rejected this upload origin. Open TRACEE from the local API address and retry.",
    upload_too_large: "The selected file exceeds the server's upload limit.",
    upload_configuration_invalid: "Upload is unavailable because the server upload-size configuration is invalid. Contact the API operator.",
    invalid_content_length: "The API could not accept the upload request size. Check the selected file and retry.",
    unsupported_media_type: "The API did not receive a supported file upload. Select a file and retry.",
    invalid_multipart: "The upload request could not be read. Select the file again and retry.",
    unexpected_form_field: "The upload request contained unsupported form data. Select one file and retry.",
    duplicate_evidence: "This evidence content is already present in the vault.",
    invalid_filename: "The selected file name is not accepted by the API.",
    empty_file: "The selected file is empty and cannot be uploaded.",
    ingestion_failed: "The API could not ingest this evidence. Check the local server logs before retrying.",
    storage_failure: "The API could not store this evidence. Check the vault and server logs before retrying.",
    activity_log_invalid: "The activity log failed integrity validation. Check the local API server logs.",
    activity_audit_failed: "The API could not record the acquisition activity. Refresh the inventory before retrying.",
    missing_file: "Select a file before uploading.",
    invalid_upload: "The upload request was not accepted. Select one file and retry.",
    activity_log_unavailable: "The activity log is unavailable. Check the local API server logs.",
    analysis_not_found: "The stored analysis was not found or is no longer valid for this evidence.",
    analysis_invalid: "The stored analysis is malformed or has invalid provenance. Check the API server logs.",
    analysis_unavailable: "Stored analysis data is unavailable. Check local vault access and the API server logs.",
    analysis_storage_failed: "The API could not safely store the analysis. Check vault capacity and server logs.",
    analysis_limit_exceeded: "The analysis limit for this evidence has been reached.",
    analysis_configuration_invalid: "The server's analysis configuration is invalid. Contact the local API operator.",
    analysis_id_conflict: "The API could not reserve a unique analysis identifier. Retry after checking the server logs.",
    source_changed: "Evidence changed while analysis was running. Refresh the inventory and review the evidence state.",
    evidence_unavailable: "The verified evidence object is unavailable. Check the vault and API server logs.",
    invalid_record: "A source record could not be normalized. Review parser diagnostics and the source file.",
    unsupported_parser: "This parser is not supported for the selected evidence.",
    parser_mismatch: "The selected parser does not match the stored analysis.",
    invalid_analysis_id: "The analysis identifier is invalid.",
    reconstruction_not_found: "The stored reconstruction was not found or is no longer valid for this evidence.",
    reconstruction_invalid: "The stored reconstruction is malformed or has invalid provenance. Check the API server logs.",
    reconstruction_unavailable: "Stored reconstruction data is unavailable. Check vault access and the API server logs.",
    reconstruction_storage_unavailable: "Reconstruction storage is unavailable. Check local vault access and server logs.",
    reconstruction_storage_failed: "The API could not safely store the reconstruction. Check vault capacity and server logs.",
    reconstruction_id_conflict: "The API could not reserve a unique reconstruction identifier. Retry after checking the server logs.",
    unsupported_source_type: "No built-in reconstruction rule supports this analysis parser.",
    reconstruction_limit_exceeded: "The reconstruction limit for this evidence has been reached.",
    reconstruction_configuration_invalid: "The candidate window is outside the supported range.",
    stale_analysis: "The evidence or analysis changed. Refresh stored results before continuing.",
    stale_reconstruction: "The evidence or reconstruction changed. Refresh stored results before continuing.",
    invalid_pagination: "The requested result page is invalid. Refresh stored results.",
    invalid_request: "The API rejected the request format.",
  };
  if (messages[code]) return messages[code];
  if (status === 404) return "The requested API resource is unavailable.";
  if (status >= 500) return "The local API could not complete the request. Check the server status and logs.";
  if (status >= 400) return "The API rejected the request.";
  return "The API returned an unexpected response.";
}

function apiAuthorizationHeader() {
  if (!apiAccessToken) {
    const error = new Error(apiErrorMessage({ error: { code: "api_auth_required" } }, 401));
    error.code = "api_auth_required";
    error.status = 401;
    throw error;
  }
  return { Authorization: `Bearer ${apiAccessToken}` };
}

async function apiHealth() {
  let response;
  try {
    response = await fetch("/health", {
      method: "GET",
      headers: { Accept: "application/json" },
      cache: "no-store",
    });
  } catch {
    throw new Error("Cannot reach the local TRACEE API. Confirm it is running on this computer and try again.");
  }
  let payload;
  try { payload = await response.json(); }
  catch { throw new Error("The API returned a response that was not valid JSON."); }
  if (!response.ok) throw new Error("The local API health check failed.");
  return payload;
}

async function apiGet(path) {
  let response;
  try {
    response = await fetch(path, {
      method: "GET",
      headers: { Accept: "application/json", ...apiAuthorizationHeader() },
      cache: "no-store",
    });
  } catch {
    throw new Error("Cannot reach the local TRACEE API. Confirm it is running on this computer and try again.");
  }

  let payload;
  try {
    payload = await response.json();
  } catch {
    throw new Error("The API returned a response that was not valid JSON.");
  }

  if (!response.ok) {
    const error = new Error(apiErrorMessage(payload, response.status));
    error.code = payload?.error?.code || "http_error";
    error.status = response.status;
    error.payload = payload;
    throw error;
  }
  return payload;
}

async function apiPostUpload(file, signal) {
  let response;
  const data = new FormData();
  data.append("file", file, file.name);
  try {
    response = await fetch("/api/v1/evidence", {
      method: "POST",
      headers: { Accept: "application/json", ...apiAuthorizationHeader() },
      body: data,
      cache: "no-store",
      signal,
    });
  } catch (error) {
    if (error.name === "AbortError") throw error;
    throw new Error("Cannot reach the local TRACEE API. The upload outcome is unknown; refresh the inventory before retrying.");
  }
  let payload;
  try { payload = await response.json(); } catch {
    throw new Error("The API returned a response that was not valid JSON. Refresh the inventory before retrying.");
  }
  if (!response.ok) {
    const error = new Error(apiErrorMessage(payload, response.status));
    error.code = payload?.error?.code || "http_error";
    error.status = response.status;
    error.payload = payload;
    throw error;
  }
  return payload;
}

async function apiPostJson(path, body) {
  let response;
  try {
    response = await fetch(path, { method: "POST", headers: { Accept: "application/json", "Content-Type": "application/json", ...apiAuthorizationHeader() }, body: JSON.stringify(body), cache: "no-store" });
  } catch {
    throw new Error("Cannot reach the local TRACEE API. Confirm it is running and refresh stored results before retrying.");
  }
  let payload;
  try { payload = await response.json(); } catch { throw new Error("The API returned a response that was not valid JSON."); }
  if (!response.ok) {
    const error = new Error(apiErrorMessage(payload, response.status));
    error.code = payload?.error?.code || "http_error";
    error.status = response.status;
    error.payload = payload;
    throw error;
  }
  return payload;
}

function updateConnection(connected) {
  const dot = byId("header-dot");
  dot.className = `status-dot ${connected ? "online" : "offline"}`;
  byId("header-status").textContent = connected ? "API connected" : "API unavailable";
}

function updateApiSessionButton() {
  const button = byId("api-session-button");
  const authorized = Boolean(apiAccessToken);
  button.textContent = authorized ? "Lock API session" : "Authorize API";
  button.setAttribute("aria-label", authorized ? "Lock and clear the API session" : "Authorize this page to access the API");
}

function openApiAuthDialog() {
  byId("api-auth-alert").textContent = "";
  byId("api-auth-alert").classList.add("hidden");
  byId("api-token").value = "";
  if (!byId("api-auth-dialog").open) byId("api-auth-dialog").showModal();
  byId("api-token").focus();
}

async function authorizeApiSession(event) {
  event.preventDefault();
  const input = byId("api-token");
  const candidate = input.value;
  input.value = "";
  if (!candidate) {
    setAlert("api-auth-alert", "Enter the credential supplied by the local API operator.");
    return;
  }
  apiAccessToken = candidate;
  const submit = byId("api-auth-submit");
  submit.disabled = true;
  setAlert("api-auth-alert", "");
  try {
    await apiGet("/api/v1/reconstruction/rules");
    updateApiSessionButton();
    byId("api-auth-dialog").close();
    await refreshData();
  } catch (error) {
    apiAccessToken = null;
    updateApiSessionButton();
    setAlert("api-auth-alert", error.message || "The API credential was not accepted.");
  } finally {
    input.value = "";
    submit.disabled = false;
  }
}

function clearApiSession() {
  apiAccessToken = null;
  byId("api-token").value = "";
  window.location.reload();
}

function showView(name) {
  if (!views[name]) return;
  state.currentView = name;

  document.querySelectorAll(".view").forEach((view) => {
    const active = view.id === `view-${name}`;
    view.classList.toggle("active", active);
    view.hidden = !active;
  });

  document.querySelectorAll(".nav-item").forEach((button) => {
    const active = button.dataset.view === name;
    button.classList.toggle("active", active);
    if (active) button.setAttribute("aria-current", "page");
    else button.removeAttribute("aria-current");
  });

  byId("current-section").textContent = views[name];
  history.replaceState(null, "", `#${name}`);
  if (name === "activity" && state.activityStatus === "idle") refreshActivity();
  if (name === "analysis") prepareAnalysisView();
  if (name === "timeline") {
    prepareTimelineView();
    loadInvestigationRisk();
    loadCorrelationGraph();
  }
  if (name === "verification") loadRecoveryStatus();
  if (name === "mtls") initMtlsView();
  if (name === "replay") loadDatasetInfo();
}

function makeEvidenceRow(record, selected = false) {
  const row = element("tr", selected ? "selected" : "");
  row.tabIndex = 0;
  row.setAttribute("aria-label", `Open evidence ${record.evidence_id}`);
  const id = element("td", "evidence-id-cell", record.evidence_id);
  const file = element("td", "filename-cell", safeFilename(record.original_filename));
  file.title = safeFilename(record.original_filename);
  const ingested = element("td", "timestamp-cell", formatDate(record.ingested_at));
  row.append(id, file, ingested);
  const select = () => openEvidence(record.evidence_id);
  row.addEventListener("click", select);
  row.addEventListener("keydown", (event) => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      select();
    }
  });
  return row;
}

function renderDashboard() {
  const loading = byId("dashboard-loading");
  const empty = byId("dashboard-empty");
  const unavailable = byId("dashboard-unavailable");
  const table = byId("dashboard-table-wrap");
  const footer = byId("dashboard-foot");
  const rows = byId("dashboard-rows");
  const count = byId("evidence-count");
  const range = byId("dashboard-range");

  loading.hidden = state.inventoryStatus !== "loading";
  empty.hidden = true;
  unavailable.hidden = true;
  table.hidden = true;
  footer.hidden = true;
  rows.replaceChildren();

  if (state.inventoryStatus === "loading") {
    count.textContent = "—";
    range.textContent = "Loading persisted records";
    return;
  }

  if (state.inventoryStatus === "error") {
    count.textContent = "—";
    range.textContent = "Inventory could not be retrieved";
    unavailable.hidden = false;
    return;
  }

  count.textContent = String(state.evidence.length);
  if (state.evidence.length === 0) {
    range.textContent = "No records in this vault";
    empty.hidden = false;
    return;
  }

  const preview = state.evidence.slice(0, PREVIEW_LIMIT);
  range.textContent = `Showing ${preview.length} of ${state.evidence.length} vault records`;
  preview.forEach((record) => rows.append(makeEvidenceRow(record)));
  table.hidden = false;
  if (state.evidence.length > PREVIEW_LIMIT) {
    byId("dashboard-subset").textContent = `Showing 1–${preview.length} of ${state.evidence.length} records`;
    footer.hidden = false;
  }
}

function renderExplorer() {
  const host = byId("evidence-rows");
  const query = byId("evidence-search").value.trim().toLocaleLowerCase();
  host.replaceChildren();

  if (state.inventoryStatus !== "loaded") {
    byId("record-count").textContent = state.inventoryStatus === "loading" ? "Loading records" : "Inventory unavailable";
    const row = element("tr");
    const cell = element("td", "empty-cell", state.inventoryStatus === "loading"
      ? "Loading inventory from the API"
      : "Resolve the API or vault error above, then refresh the inventory.");
    cell.colSpan = 3;
    row.append(cell);
    host.append(row);
    return;
  }

  const records = state.evidence.filter((record) => [
    record.evidence_id,
    safeFilename(record.original_filename),
    record.media_type,
  ].some((value) => String(value || "").toLocaleLowerCase().includes(query)));

  byId("record-count").textContent = `${records.length} ${records.length === 1 ? "record" : "records"}`;
  if (records.length === 0) {
    const row = element("tr");
    const message = state.evidence.length > 0
      ? "No records match this search."
      : "No evidence metadata records were found in the configured vault.";
    const cell = element("td", "empty-cell", message);
    cell.colSpan = 3;
    row.append(cell);
    host.append(row);
    return;
  }

  records.forEach((record) => host.append(makeEvidenceRow(record, record.evidence_id === state.selectedId)));
}

function metadataField(list, label, value, valueClass = "") {
  const field = element("div", "metadata-field");
  field.append(element("dt", "", label));
  field.append(element("dd", valueClass, value || "Not provided"));
  list.append(field);
}

function renderMetadata(metadata) {
  const panel = byId("metadata-detail");
  panel.replaceChildren();

  const heading = element("div", "detail-heading");
  heading.append(element("div", "eyebrow", "PERSISTED METADATA"));
  heading.append(element("h2", "", metadata.evidence_id));
  heading.append(element("p", "", safeFilename(metadata.original_filename)));

  const list = element("dl", "metadata-list");
  metadataField(list, "Original filename", safeFilename(metadata.original_filename));
  metadataField(list, "File size", formatSize(metadata.size_bytes));
  metadataField(list, "Media type", metadata.media_type);
  metadataField(list, "Ingested", formatDate(metadata.ingested_at));
  metadataField(list, "SHA-256", metadata.sha256, "digest");
  metadataField(list, "Schema version", metadata.schema_version);

  const verify = element("button", "button button-primary detail-verify", "Verify integrity");
  verify.type = "button";
  verify.addEventListener("click", () => {
    showView("verification");
    byId("verify-evidence-select").value = metadata.evidence_id;
    byId("verify-button").disabled = false;
  });

  const analyze = element("button", "button button-secondary detail-verify", "Open event analysis");
  analyze.type = "button";
  analyze.addEventListener("click", () => { state.selectedId = metadata.evidence_id; showView("analysis"); });

  panel.append(heading, list, verify, analyze);
}

async function openEvidence(evidenceId, navigate = true) {
  state.selectedId = evidenceId;
  if (navigate) showView("evidence");
  byId("explorer-layout").classList.add("has-selection");
  const panel = byId("metadata-detail");
  panel.hidden = false;
  panel.replaceChildren(element("div", "detail-loading", "Loading metadata from the API"));
  renderExplorer();

  try {
    const metadata = await apiGet(`/api/v1/evidence/${encodeURIComponent(evidenceId)}`);
    if (state.selectedId !== evidenceId) return;
    renderMetadata(metadata);
  } catch (error) {
    if (state.selectedId !== evidenceId) return;
    panel.replaceChildren();
    panel.append(element("div", "detail-error", error.message));
  }
}

function renderVerification(result, host = byId("verification-result")) {
  host.replaceChildren();
  const stateName = typeof result.state === "string" ? result.state.toUpperCase() : "";
  const known = ["VALID", "TAMPERED", "MISSING", "INVALID"].includes(stateName);
  const resultState = known ? stateName : "UNRECOGNIZED";
  const heading = element("div", "result-heading");
  heading.append(element("span", "result-id", result.evidence_id || "Unknown evidence"));
  heading.append(element("span", `state-pill ${known ? stateName.toLowerCase() : "unknown"}`, resultState));
  const messages = {
    VALID: "Evidence, metadata, and chain verification successful.",
    TAMPERED: "Integrity verification detected a mismatch.",
    MISSING: "A required evidence or vault file is missing.",
    INVALID: "The evidence metadata or integrity data is invalid.",
    UNRECOGNIZED: "The API returned an unrecognized state. No verification conclusion can be displayed.",
  };
  const responseMessage = known && typeof result.message === "string" && result.message.trim()
    ? result.message
    : messages.UNRECOGNIZED;
  host.append(heading, element("p", "result-message", responseMessage));

  if (result.diagnostics) {
    host.append(element("div", "result-diagnostics", `Details: ${result.diagnostics}`));
  }

  // Surfacing restore action for tampered or missing evidence
  if (resultState === "TAMPERED" || resultState === "MISSING") {
    const restoreBtn = element("button", "button button-primary", "Restore Original from Recovery Vault");
    restoreBtn.type = "button";
    restoreBtn.style.marginTop = "14px";
    restoreBtn.addEventListener("click", async () => {
      restoreBtn.disabled = true;
      restoreBtn.textContent = "Restoring from recovery copy…";
      try {
        const restResult = await apiPostJson(`/api/v1/recovery/${encodeURIComponent(result.evidence_id)}/restore`, {});
        alert(`Evidence ${result.evidence_id} successfully restored from SHA-256 recovery store!
Status: ${restResult.status}
Re-verifying integrity…`);
        await loadRecoveryStatus();
        await runVerification();
      } catch (err) {
        alert(`Restoration failed: ${err.message}`);
        restoreBtn.disabled = false;
        restoreBtn.textContent = "Restore Original from Recovery Vault";
      }
    });
    host.append(restoreBtn);
  }
}

async function runVerification() {
  const evidenceId = byId("verify-evidence-select").value;
  if (!evidenceId) return;

  const button = byId("verify-button");
  const result = byId("verification-result");
  button.disabled = true;
  button.querySelector("span").textContent = "Verifying…";
  result.replaceChildren(element("div", "detail-loading", "Verifying evidence, metadata, and chain"));
  setAlert("verification-error", "");

  try {
    const verification = await apiGet(`/api/v1/evidence/${encodeURIComponent(evidenceId)}/verify`);
    renderVerification(verification);
  } catch (error) {
    result.replaceChildren(element("div", "detail-error", error.message));
  } finally {
    button.disabled = !byId("verify-evidence-select").value;
    button.querySelector("span").textContent = "Run verification";
  }
}

function populateVerificationSelect() {
  const select = byId("verify-evidence-select");
  const previous = select.value;
  select.replaceChildren();
  const placeholder = element("option", "", state.evidence.length ? "Select an evidence record" : "No evidence records available");
  placeholder.value = "";
  select.append(placeholder);
  state.evidence.forEach((record) => {
    const option = element("option", "", `${record.evidence_id} · ${safeFilename(record.original_filename)}`);
    option.value = record.evidence_id;
    select.append(option);
  });
  if (state.evidence.some((record) => record.evidence_id === previous)) select.value = previous;
  const hasVal = Boolean(select.value);
  byId("verify-button").disabled = !hasVal;
  if (byId("simulate-tamper-btn")) byId("simulate-tamper-btn").disabled = !hasVal;
  if (byId("simulate-missing-btn")) byId("simulate-missing-btn").disabled = !hasVal;
}

async function refreshData() {
  const refresh = byId("refresh-button");
  refresh.disabled = true;
  refresh.setAttribute("aria-busy", "true");
  state.inventoryStatus = "loading";
  state.inventoryErrorCode = null;
  byId("vault-status").textContent = "Checking vault";
  byId("vault-status").className = "vault-status pending";
  setAlert("global-alert", "");
  setAlert("evidence-error", "");
  setAlert("verification-error", "");
  renderDashboard();
  renderExplorer();

  const health = await Promise.allSettled([apiHealth()]).then((result) => result[0]);

  const connected = health.status === "fulfilled"
    && health.value.service === "TRACEE"
    && health.value.status === "ok";
  updateConnection(connected);

  if (!apiAccessToken) {
    state.evidence = [];
    state.inventoryStatus = "error";
    state.inventoryErrorCode = "api_auth_required";
    byId("vault-status").textContent = "Authorization required";
    byId("vault-status").className = "vault-status pending";
    const message = apiErrorMessage({ error: { code: "api_auth_required" } }, 401);
    setAlert("global-alert", message);
    setAlert("evidence-error", message);
    setAlert("verification-error", message);
    renderDashboard();
    renderExplorer();
    populateVerificationSelect();
    refresh.disabled = false;
    refresh.removeAttribute("aria-busy");
    return;
  }

  const inventory = await Promise.allSettled([apiGet("/api/v1/evidence")]).then((result) => result[0]);

  let inventoryError = "";
  if (inventory.status === "fulfilled" && Array.isArray(inventory.value.evidence)) {
    state.evidence = inventory.value.evidence.filter((record) => record && typeof record.evidence_id === "string");
    state.inventoryStatus = "loaded";
  } else {
    state.evidence = [];
    state.inventoryStatus = "error";
    state.inventoryErrorCode = inventory.status === "rejected" ? inventory.reason.code : "invalid_response";
    inventoryError = inventory.status === "rejected"
      ? inventory.reason.message
      : "The API returned an invalid evidence inventory.";
  }

  if (!connected && !inventoryError) {
    inventoryError = health.status === "rejected"
      ? health.reason.message
      : "The health endpoint returned an unexpected response.";
  }

  if (inventoryError) {
    setAlert("global-alert", inventoryError);
    setAlert("evidence-error", inventoryError);
    setAlert("verification-error", inventoryError);
  }

  const vaultStatus = byId("vault-status");
  if (state.inventoryStatus === "loaded") {
    vaultStatus.textContent = "Vault available";
    vaultStatus.className = "vault-status online";
  } else if (state.inventoryErrorCode === "vault_not_configured") {
    vaultStatus.textContent = "Vault not configured";
    vaultStatus.className = "vault-status offline";
  } else if (state.inventoryErrorCode === "vault_unavailable") {
    vaultStatus.textContent = "Vault unavailable";
    vaultStatus.className = "vault-status offline";
  } else {
    vaultStatus.textContent = "Vault status unknown";
    vaultStatus.className = "vault-status pending";
  }

  renderDashboard();
  renderExplorer();
  populateVerificationSelect();

  if (state.selectedId && state.evidence.some((record) => record.evidence_id === state.selectedId)) {
    await openEvidence(state.selectedId, false);
  } else if (state.selectedId) {
    state.selectedId = null;
    byId("explorer-layout").classList.remove("has-selection");
    byId("metadata-detail").hidden = true;
  }

  if (state.currentView === "timeline") prepareTimelineView();

  refresh.disabled = false;
  refresh.removeAttribute("aria-busy");
}

function readableEventType(value) {
  const names = {
    evidence_viewed: "Evidence record viewed",
    integrity_verification: "Integrity verification",
    evidence_acquisition_started: "Evidence acquisition started",
    evidence_acquired: "Evidence acquired",
    evidence_acquisition_failed: "Evidence acquisition failed",
  };
  return names[value] || (typeof value === "string" ? value.replaceAll("_", " ") : "Recorded event");
}

function renderActivity() {
  const loading = byId("activity-loading");
  const empty = byId("activity-empty");
  const list = byId("activity-list");
  loading.hidden = state.activityStatus !== "loading";
  empty.hidden = true;
  list.hidden = true;
  list.replaceChildren();
  if (state.activityStatus !== "loaded") return;
  if (!state.activity.length) { empty.hidden = false; return; }
  state.activity.forEach((event) => {
    const item = element("li", "activity-item");
    const heading = element("div", "activity-event-heading");
    heading.append(element("h2", "", readableEventType(event.event_type)));
    heading.append(formatActivityTime(event.timestamp));
    const details = element("dl", "activity-details");
    const actorNames = { unauthenticated_local_client: "Legacy local client", local_api_token: "Shared API credential", local_upload_token: "Shared API credential" };
    activityField(details, "Actor category", actorNames[event.actor] || "Not provided");
    activityField(details, "Outcome", event.outcome || "Not provided");
    if (event.evidence_id) activityField(details, "Evidence ID", event.evidence_id, "technical-value");
    if (event.filename) activityField(details, "File", safeFilename(event.filename));
    if (event.size_bytes !== null && event.size_bytes !== undefined) activityField(details, "File size", formatSize(event.size_bytes));
    if (event.event_type === "integrity_verification" && ["VALID", "TAMPERED", "MISSING", "INVALID"].includes(event.outcome)) {
      const statePill = element("span", `state-pill ${event.outcome.toLowerCase()}`, event.outcome);
      heading.append(statePill);
    }
    item.append(heading, details);
    list.append(item);
  });
  list.hidden = false;
}

function formatActivityTime(value) {
  if (typeof value !== "string" || !value.trim()) return element("span", "activity-time", "Timestamp unavailable");
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return element("span", "activity-time", "Timestamp unavailable");
  const time = element("time", "activity-time", formatDate(value));
  time.dateTime = value;
  return time;
}

function activityField(list, label, value, className = "") {
  const wrapper = element("div", "activity-detail");
  wrapper.append(element("dt", "", label), element("dd", className, String(value)));
  list.append(wrapper);
}

async function refreshActivity() {
  const button = byId("activity-refresh-button");
  button.disabled = true;
  state.activityStatus = "loading";
  setAlert("activity-error", "");
  renderActivity();
  try {
    const payload = await apiGet("/api/v1/activity?limit=200");
    if (!Array.isArray(payload.activity)) throw new Error("The API returned an invalid activity response.");
    state.activity = payload.activity;
    state.activityStatus = "loaded";
  } catch (error) {
    state.activity = [];
    state.activityStatus = "error";
    setAlert("activity-error", error.message);
  } finally {
    renderActivity();
    button.disabled = false;
  }
}

function resetUploadDialog() {
  uploadFile = null;
  uploadedEvidenceId = null;
  byId("upload-form").reset();
  byId("upload-selection").textContent = "Choose a file from this device. A server-side path cannot be submitted.";
  byId("upload-status").textContent = "";
  byId("upload-result").replaceChildren();
  byId("upload-result").hidden = true;
  byId("upload-verification-result").replaceChildren();
  byId("upload-verify-button").hidden = true;
  setAlert("upload-alert", "");
  byId("upload-submit-button").disabled = false;
  byId("upload-submit-button").textContent = "Upload evidence";
  byId("upload-cancel-button").textContent = "Cancel";
}

function showStoredUpload(payload, auditWarning = false) {
  const metadata = payload.metadata || {};
  uploadedEvidenceId = payload.evidence_id;
  const result = byId("upload-result");
  result.replaceChildren();
  const heading = element("h3", "", auditWarning ? "Evidence stored; activity audit incomplete" : "Evidence acquired");
  const list = element("dl", "metadata-list upload-metadata");
  metadataField(list, "Evidence ID", payload.evidence_id, "digest");
  metadataField(list, "Filename", safeFilename(metadata.original_filename));
  metadataField(list, "File size", formatSize(metadata.size_bytes));
  metadataField(list, "SHA-256", metadata.sha256, "digest");
  if (Number.isInteger(payload.chain_sequence)) metadataField(list, "Chain sequence", String(payload.chain_sequence));
  result.append(heading, list);
  if (auditWarning) result.append(element("p", "upload-warning", "Evidence is stored, but the API could not confirm its activity record. Inventory was refreshed; do not retry this file until you have reviewed the vault."));
  result.hidden = false;
  byId("upload-verify-button").hidden = false;
  byId("upload-status").textContent = "Upload completed. Integrity verification has not been run.";
  state.selectedId = payload.evidence_id;
  refreshData();
}

async function submitUpload(event) {
  event.preventDefault();
  const fileInput = byId("upload-file");
  uploadFile = fileInput.files?.[0] || uploadFile;
  if (!uploadFile) { setAlert("upload-alert", "Choose a file to upload."); return; }
  if (!apiAccessToken) { setAlert("upload-alert", "Authorize the API session before uploading evidence."); return; }
  setAlert("upload-alert", "");
  byId("upload-status").textContent = "Uploading and recording acquisition…";
  byId("upload-submit-button").disabled = true;
  byId("upload-submit-button").textContent = "Processing…";
  uploadController = new AbortController();
  try {
    const payload = await apiPostUpload(uploadFile, uploadController.signal);
    if (typeof payload.evidence_id !== "string" || !payload.metadata) throw new Error("The API returned an incomplete upload result. Refresh the inventory before retrying.");
    showStoredUpload(payload);
  } catch (error) {
    const payload = error.payload;
    if (payload?.operation?.evidence_stored === true && typeof payload.operation.evidence_id === "string") {
      showStoredUpload({ evidence_id: payload.operation.evidence_id, metadata: {}, chain_sequence: null }, true);
    } else if (error.name === "AbortError") {
      byId("upload-status").textContent = "Upload request cancelled. Refresh inventory to confirm whether the server received it before retrying.";
    } else {
      setAlert("upload-alert", error.message);
      byId("upload-status").textContent = "Upload did not complete. If the connection was interrupted, refresh inventory before retrying.";
    }
  } finally {
    uploadController = null;
    byId("upload-submit-button").disabled = false;
    byId("upload-submit-button").textContent = "Retry upload";
  }
}

async function verifyUploadedEvidence() {
  if (!uploadedEvidenceId) return;
  const host = byId("upload-verification-result");
  byId("upload-verify-button").disabled = true;
  host.replaceChildren(element("div", "detail-loading", "Verifying evidence, metadata, and chain"));
  try {
    const result = await apiGet(`/api/v1/evidence/${encodeURIComponent(uploadedEvidenceId)}/verify`);
    renderVerification(result, host);
  } catch (error) {
    host.replaceChildren(element("div", "detail-error", error.message));
  } finally {
    byId("upload-verify-button").disabled = false;
  }
}

function openUploadDialog() {
  resetUploadDialog();
  byId("upload-dialog").showModal();
  byId("upload-file").focus();
}

const ANALYSIS_PAGE_SIZE = 25;
function analysisAlert(error) {
  const host = byId("analysis-error");
  host.replaceChildren();
  const code = error.code ? `${error.code}: ` : "";
  host.textContent = `${code}${error.message || "The request failed."}`;
  host.classList.remove("hidden");
}
function clearAnalysisError() { setAlert("analysis-error", ""); }
function clearAnalysisResults() {
  const a = state.analysis;
  a.analyses = []; a.analysisOffset = 0; a.analysisTotal = 0; a.analysisId = null; a.detail = null; a.detailOffset = 0;
  a.runs = []; a.runsOffset = 0; a.runsTotal = 0; a.reconstructionId = null; a.reconstruction = null;
  a.hypothesisOffset = 0; a.skippedOffset = 0;
  byId("analysis-run-select").replaceChildren(new Option("No stored analyses", ""));
  byId("reconstruction-run-select").replaceChildren(new Option("No stored reconstructions", ""));
  byId("analysis-summary").replaceChildren(element("p", "form-help", "No analysis run selected."));
  byId("analysis-detail").replaceChildren();
  byId("reconstruction-summary").replaceChildren(element("p", "form-help", "No reconstruction run selected."));
  byId("reconstruction-detail").replaceChildren();
}
function prepareAnalysisView() {
  const select = byId("analysis-evidence-select");
  const chosen = state.selectedId && state.evidence.some((item) => item.evidence_id === state.selectedId) ? state.selectedId : "";
  const previous = select.value;
  select.replaceChildren(new Option(state.evidence.length ? "Select an evidence record" : "No evidence records available", ""));
  state.evidence.forEach((record) => select.add(new Option(`${record.evidence_id} · ${safeFilename(record.original_filename)}`, record.evidence_id)));
  select.value = chosen || (state.evidence.some((item) => item.evidence_id === previous) ? previous : "");
  selectAnalysisEvidence(select.value);
  if (!select.value) loadRules();
}
function selectAnalysisEvidence(evidenceId) {
  const a = state.analysis;
  if (a.evidenceId === evidenceId) return;
  a.evidenceId = evidenceId || null;
  a.generation += 1;
  clearAnalysisResults(); clearAnalysisError();
  state.selectedId = evidenceId || null;
  byId("analysis-evidence-status").textContent = evidenceId ? "Loading stored analyses and reconstructions…" : "Select evidence to browse stored results.";
  const hasEvidence = Boolean(evidenceId);
  byId("run-analysis-button").disabled = !hasEvidence;
  byId("load-analysis-button").disabled = true;
  byId("run-reconstruction-button").disabled = true;
  byId("load-reconstruction-button").disabled = true;
  byId("analyses-prev").disabled = true; byId("analyses-next").disabled = true;
  byId("reconstructions-prev").disabled = true; byId("reconstructions-next").disabled = true;
  if (evidenceId) refreshAnalysisLists();
}
async function refreshAnalysisLists() {
  const a = state.analysis, evidenceId = a.evidenceId, generation = a.generation;
  if (!evidenceId) return;
  clearAnalysisError();
  byId("analysis-evidence-status").textContent = "Loading stored results…";
  try {
    const [analyses, reconstructions, rules] = await Promise.all([
      apiGet(`/api/v1/evidence/${encodeURIComponent(evidenceId)}/analyses?offset=${a.analysisOffset}&limit=${ANALYSIS_PAGE_SIZE}`),
      apiGet(`/api/v1/evidence/${encodeURIComponent(evidenceId)}/reconstructions?offset=${a.runsOffset}&limit=${ANALYSIS_PAGE_SIZE}`),
      apiGet("/api/v1/reconstruction/rules"),
    ]);
    if (a.evidenceId !== evidenceId || a.generation !== generation) return;
    a.analyses = Array.isArray(analyses.analyses) ? analyses.analyses : [];
    a.analysisTotal = analyses.pagination?.total_analyses || 0;
    a.runs = Array.isArray(reconstructions.reconstructions) ? reconstructions.reconstructions : [];
    a.runsTotal = reconstructions.pagination?.total_reconstructions || 0;
    renderAnalysisLists(); renderRules(rules.rules || []);
    byId("analysis-evidence-status").textContent = `Stored results for ${evidenceId}`;
  } catch (error) {
    if (a.evidenceId !== evidenceId || a.generation !== generation) return;
    byId("analysis-evidence-status").textContent = "Stored results could not be loaded.";
    analysisAlert(error);
  }
}
async function loadRules() {
  try { const response = await apiGet("/api/v1/reconstruction/rules"); renderRules(Array.isArray(response.rules) ? response.rules : []); }
  catch (error) { renderRules([]); analysisAlert(error); }
}
function renderAnalysisLists() {
  const a = state.analysis;
  const analysisSelect = byId("analysis-run-select");
  analysisSelect.replaceChildren(new Option(a.analyses.length ? "Select a stored analysis" : "No stored analyses", ""));
  a.analyses.forEach((item) => analysisSelect.add(new Option(`${item.analysis_id} · ${item.parser} · ${item.event_count} events · ${formatDate(item.created_at)}`, item.analysis_id)));
  if (a.analysisId && a.analyses.some((item) => item.analysis_id === a.analysisId)) analysisSelect.value = a.analysisId;
  const runSelect = byId("reconstruction-run-select");
  runSelect.replaceChildren(new Option(a.runs.length ? "Select a stored reconstruction" : "No stored reconstructions", ""));
  a.runs.forEach((item) => runSelect.add(new Option(`${item.reconstruction_id} · ${item.result_status} · ${item.hypothesis_count} hypotheses · ${formatDate(item.created_at)}`, item.reconstruction_id)));
  if (a.reconstructionId && a.runs.some((item) => item.reconstruction_id === a.reconstructionId)) runSelect.value = a.reconstructionId;
  byId("analyses-prev").disabled = a.analysisOffset <= 0;
  byId("analyses-next").disabled = a.analysisOffset + ANALYSIS_PAGE_SIZE >= a.analysisTotal;
  byId("reconstructions-prev").disabled = a.runsOffset <= 0;
  byId("reconstructions-next").disabled = a.runsOffset + ANALYSIS_PAGE_SIZE >= a.runsTotal;
  byId("load-analysis-button").disabled = !analysisSelect.value;
  byId("load-reconstruction-button").disabled = !runSelect.value;
  byId("run-reconstruction-button").disabled = !a.detail || !a.analysisId;
}
function renderRules(rules) {
  const host = byId("reconstruction-rules"); host.replaceChildren();
  if (!rules.length) { host.append(element("p", "form-help", "No reconstruction rules were returned by the API.")); return; }
  host.append(element("h3", "subsection-title", "Available rule registry"));
  rules.forEach((rule) => {
    const card = element("article", "rule-card"); card.append(element("h4", "", `${rule.rule_id} · v${rule.version}`), element("p", "", rule.description));
    if (Array.isArray(rule.supported_source_types)) card.append(element("p", "form-help", `Supported sources: ${rule.supported_source_types.join(", ") || "none listed"}`));
    if (Array.isArray(rule.required_attributes)) card.append(element("p", "form-help", `Required attributes: ${rule.required_attributes.join(", ") || "none listed"}`));
    if (Array.isArray(rule.assumptions) && rule.assumptions.length) card.append(element("p", "form-help", `Assumptions: ${rule.assumptions.join("; ")}`));
    card.append(element("p", "form-help", `Minimum supporting observations: ${rule.minimum_supporting_observations ?? "Not specified"}`));
    if (Array.isArray(rule.limitations) && rule.limitations.length) card.append(element("p", "rule-limitation", `Limitations: ${rule.limitations.join("; ")}`));
    host.append(card);
  });
}
function appendValue(parent, label, value) {
  const row = element("div", "analysis-field"); row.append(element("dt", "", label));
  let display = value;
  if (Array.isArray(value)) display = value.length ? value.join(", ") : "None";
  else if (value && typeof value === "object") display = JSON.stringify(value);
  row.append(element("dd", "", display === null || display === undefined || display === "" ? "Not provided" : String(display)));
  parent.append(row);
}
function renderSummary(host, summary, kind) {
  host.replaceChildren();
  if (!summary) { host.append(element("p", "form-help", `No ${kind} run selected.`)); return; }
  const box = element("div", "run-summary");
  const fields = kind === "analysis" ? [
    ["Analysis ID", summary.analysis_id], ["Parser", `${summary.parser} ${summary.parser_version || ""}`], ["Created", formatDate(summary.created_at)], ["Events", summary.event_count], ["Source SHA-256", summary.source_sha256],
  ] : [
    ["Reconstruction ID", summary.reconstruction_id], ["Evidence ID", summary.evidence_id], ["Analysis ID", summary.analysis_id], ["Source SHA-256", summary.source_sha256], ["Parser", `${summary.parser || "Unknown"} ${summary.parser_version || ""}`], ["Result status", summary.result_status], ["Created", formatDate(summary.created_at)], ["Candidate window", `${summary.config?.candidate_window_seconds ?? "Unknown"} seconds`], ["Hypotheses", summary.hypothesis_count], ["Skipped inputs", summary.skipped_input_count], ["Rule versions", (summary.rule_versions || []).map((rule) => `${rule.rule_id} ${rule.version}`).join(", ") || "None returned"],
  ];
  const list = element("dl", "analysis-fields"); fields.forEach(([label, value]) => appendValue(list, label, value));
  box.append(list);
  if (summary.diagnostics) {
    const d = summary.diagnostics; const diagnostics = element("p", "form-help", `Diagnostics: ${d.parsed_records ?? 0} parsed, ${d.partial_records ?? 0} partial, ${d.malformed_lines ?? 0} malformed of ${d.lines_total ?? 0} lines.`); box.append(diagnostics);
    if (Array.isArray(d.issues) && d.issues.length) box.append(element("p", "rule-limitation", `Parser issues: ${d.issues.map((issue) => `line ${issue.line_number}: ${issue.code}`).join("; ")}`));
  }
  host.append(box);
}
async function runAnalysis() {
  const a = state.analysis, evidenceId = a.evidenceId; if (!evidenceId) return;
  const button = byId("run-analysis-button"); button.disabled = true; button.textContent = "Analyzing…"; clearAnalysisError();
  try {
    const result = await apiPostJson(`/api/v1/evidence/${encodeURIComponent(evidenceId)}/analyze`, { parser: byId("analysis-parser").value });
    if (a.evidenceId !== evidenceId) return;
    a.analysisId = result.analysis_id; a.analysisOffset = 0; a.detail = null;
    renderSummary(byId("analysis-summary"), result, "analysis");
    await refreshAnalysisLists();
    if (a.evidenceId === evidenceId) { byId("analysis-run-select").value = result.analysis_id; byId("load-analysis-button").disabled = false; }
  } catch (error) {
    const operation = error.payload?.operation;
    if (operation?.completed === true && operation.type === "evidence_analysis" && a.evidenceId === evidenceId) {
      a.analysisId = operation.analysis_id; renderSummary(byId("analysis-summary"), operation, "analysis");
      await refreshAnalysisLists();
      if (a.evidenceId === evidenceId && a.analysisId) { byId("analysis-run-select").value = a.analysisId; byId("load-analysis-button").disabled = false; }
      analysisAlert({ code: error.code || "activity_log_unavailable", message: "The analysis was stored, but its activity record could not be written. Review the stored result before deciding whether to run analysis again." });
    } else analysisAlert(error);
  }
  finally { button.textContent = "Run analysis"; button.disabled = !a.evidenceId; }
}
async function loadAnalysis() {
  const a = state.analysis, evidenceId = a.evidenceId, analysisId = byId("analysis-run-select").value; if (!evidenceId || !analysisId) return;
  a.analysisId = analysisId; a.detailOffset = 0; a.detail = null; a.reconstruction = null; a.reconstructionId = null;
  clearAnalysisError(); byId("analysis-detail").replaceChildren(element("p", "detail-loading", "Loading analysis events and source observations…"));
  const generation = a.generation;
  try { const result = await apiGet(`/api/v1/evidence/${encodeURIComponent(evidenceId)}/analyses/${encodeURIComponent(analysisId)}?offset=0&limit=${ANALYSIS_PAGE_SIZE}`);
    if (a.evidenceId !== evidenceId || a.generation !== generation || a.analysisId !== analysisId) return;
    a.detail = result; renderSummary(byId("analysis-summary"), result, "analysis"); renderAnalysisDetail(); renderAnalysisLists();
  } catch (error) { if (a.evidenceId === evidenceId && a.generation === generation) analysisAlert(error); }
}
function renderAnalysisDetail() {
  const a = state.analysis, host = byId("analysis-detail"); host.replaceChildren();
  if (!a.detail) return;
  const events = Array.isArray(a.detail.events) ? a.detail.events : [];
  host.append(element("h3", "subsection-title", `Normalized events (${a.detail.pagination?.total_events ?? events.length} total)`));
  if (!events.length) host.append(element("p", "form-help", "This stored analysis contains no normalized events."));
  events.forEach((event) => {
    const card = element("article", "event-card"); card.append(element("h4", "", event.event_type || "Unspecified event type"));
    appendValue(card, "Event ID", event.event_id); appendValue(card, "Time extent", `${event.temporal_extent?.earliest_utc || "Unknown"} — ${event.temporal_extent?.latest_utc || "Unknown"}`);
    appendValue(card, "Source observation IDs", event.source_observation_ids || []); appendValue(card, "Attributes", event.attributes || {});
    host.append(card);
  });
  const observations = Array.isArray(a.detail.observations) ? a.detail.observations : [];
  host.append(element("h3", "subsection-title", `Source observations (${observations.length} returned with this event page)`));
  observations.forEach((obs) => {
    const card = element("article", "source-observation event-card"); card.append(element("h4", "", `Observation · ${obs.parse_status || "status unavailable"}`));
    appendValue(card, "Observation ID", obs.observation_id); appendValue(card, "Evidence ID", obs.evidence_id); appendValue(card, "Source locator", obs.source_locator); appendValue(card, "Parser", `${obs.parser_name || "Unknown"} ${obs.parser_version || ""}`); appendValue(card, "Source type", obs.source_type); appendValue(card, "Timestamp raw value", obs.timestamp?.raw_value); appendValue(card, "Timestamp format", obs.timestamp?.raw_format); appendValue(card, "Timezone status", obs.timestamp?.timezone_status); appendValue(card, "Parse errors", obs.parse_errors || []); appendValue(card, "Attributes", obs.attributes || {});
    host.append(card);
  });
  if (!observations.length) host.append(element("p", "form-help", "The API returned no source observations for this event page."));
  const pagination = a.detail.pagination || {}; const controls = element("div", "analysis-actions");
  const previous = element("button", "button button-secondary", "Previous events"); previous.type = "button"; previous.disabled = a.detailOffset <= 0; previous.addEventListener("click", () => pageAnalysis(a.detailOffset - ANALYSIS_PAGE_SIZE));
  const next = element("button", "button button-secondary", "Next events"); next.type = "button"; next.disabled = a.detailOffset + (pagination.limit || ANALYSIS_PAGE_SIZE) >= (pagination.total_events || 0); next.addEventListener("click", () => pageAnalysis(a.detailOffset + ANALYSIS_PAGE_SIZE));
  controls.append(previous, next); host.append(controls);
}
async function pageAnalysis(offset) {
  const a = state.analysis, evidenceId = a.evidenceId, analysisId = a.analysisId, generation = a.generation;
  try { const result = await apiGet(`/api/v1/evidence/${encodeURIComponent(evidenceId)}/analyses/${encodeURIComponent(analysisId)}?offset=${offset}&limit=${ANALYSIS_PAGE_SIZE}`); if (a.evidenceId !== evidenceId || a.analysisId !== analysisId || a.generation !== generation) return; a.detailOffset = offset; a.detail = result; renderAnalysisDetail(); }
  catch (error) { analysisAlert(error); }
}
async function runReconstruction() {
  const a = state.analysis, evidenceId = a.evidenceId, analysisId = a.analysisId; if (!evidenceId || !analysisId) return;
  const rawWindow = byId("candidate-window").value;
  const windowSeconds = Number(rawWindow);
  if (!rawWindow.trim() || !Number.isInteger(windowSeconds) || windowSeconds < 0 || windowSeconds > 86400) { analysisAlert(new Error("Candidate window must be a whole number from 0 through 86400 seconds.")); return; }
  a.reconstruction = null; a.reconstructionId = null; a.hypothesisOffset = 0; a.skippedOffset = 0;
  byId("reconstruction-run-select").value = "";
  byId("reconstruction-summary").replaceChildren(element("p", "form-help", "Reconstruction is running…"));
  byId("reconstruction-detail").replaceChildren(element("p", "detail-loading", "Generating and persisting a candidate run…"));
  const button = byId("run-reconstruction-button"); button.disabled = true; button.textContent = "Reconstructing…"; clearAnalysisError();
  try { const result = await apiPostJson(`/api/v1/evidence/${encodeURIComponent(evidenceId)}/analyses/${encodeURIComponent(analysisId)}/reconstruct`, { candidate_window_seconds: windowSeconds });
    if (a.evidenceId !== evidenceId || a.analysisId !== analysisId) return;
    a.reconstructionId = result.reconstruction_id; a.runsOffset = 0; renderSummary(byId("reconstruction-summary"), result, "reconstruction"); await refreshAnalysisLists();
    if (a.evidenceId === evidenceId) { byId("reconstruction-run-select").value = result.reconstruction_id; await loadReconstruction(); }
  } catch (error) {
    const operation = error.payload?.operation;
    if (operation?.completed === true && operation.type === "evidence_reconstruction" && a.evidenceId === evidenceId && a.analysisId === analysisId) {
      a.reconstructionId = operation.reconstruction_id; renderSummary(byId("reconstruction-summary"), operation, "reconstruction");
      await refreshAnalysisLists();
      if (a.evidenceId === evidenceId && a.reconstructionId) { byId("reconstruction-run-select").value = a.reconstructionId; await loadReconstruction(); }
      analysisAlert({ code: error.code || "activity_log_unavailable", message: "The reconstruction was stored, but its activity record could not be written. Review the stored result before deciding whether to run reconstruction again." });
    } else analysisAlert(error);
  }
  finally { button.textContent = "Run reconstruction for selected analysis"; button.disabled = !a.detail || !a.analysisId; }
}
async function loadReconstruction() {
  const a = state.analysis, evidenceId = a.evidenceId, reconstructionId = byId("reconstruction-run-select").value; if (!evidenceId || !reconstructionId) return;
  a.reconstructionId = reconstructionId; a.hypothesisOffset = 0; a.skippedOffset = 0;
  a.reconstruction = null;
  byId("reconstruction-summary").replaceChildren(element("p", "form-help", "Loading stored reconstruction summary…"));
  clearAnalysisError(); byId("reconstruction-detail").replaceChildren(element("p", "detail-loading", "Loading stored hypotheses and skipped inputs…"));
  const generation = a.generation;
  try { const result = await apiGet(`/api/v1/evidence/${encodeURIComponent(evidenceId)}/reconstructions/${encodeURIComponent(reconstructionId)}?hypothesis_offset=${a.hypothesisOffset}&hypothesis_limit=${ANALYSIS_PAGE_SIZE}&skipped_offset=${a.skippedOffset}&skipped_limit=${ANALYSIS_PAGE_SIZE}`);
    if (a.evidenceId !== evidenceId || a.generation !== generation || a.reconstructionId !== reconstructionId) return;
    a.reconstruction = result; renderSummary(byId("reconstruction-summary"), result, "reconstruction"); renderReconstructionDetail();
  } catch (error) {
    if (a.evidenceId === evidenceId && a.generation === generation) {
      a.reconstruction = null;
      byId("reconstruction-summary").replaceChildren(element("p", "form-help", "Reconstruction details are unavailable."));
      byId("reconstruction-detail").replaceChildren();
      analysisAlert(error);
    }
  }
}
function renderReconstructionDetail() {
  const a = state.analysis, host = byId("reconstruction-detail"); host.replaceChildren(); if (!a.reconstruction) return;
  const data = a.reconstruction;
  const hypotheses = Array.isArray(data.hypotheses) ? data.hypotheses : [];
  const hypothesisTotal = reconstructionPresentation.pageTotal(data, "hypotheses");
  host.append(element("h3", "subsection-title", `Hypotheses (${hypothesisTotal} total)`));
  hypotheses.forEach((hypothesis) => {
    const card = element("article", "hypothesis-card"); card.append(element("h4", "", hypothesis.event_type || "Candidate hypothesis"));
    const presentation = reconstructionPresentation.hypothesisPresentation(hypothesis, data.evidence_id);
    const distinction = element("div", "interpretation-note", "");
    appendValue(card, "Backend interpretation", presentation.interpretation);
    appendValue(card, "Supporting observations", presentation.supportingObservationCount === null ? "Unavailable in API response" : String(presentation.supportingObservationCount));
    appendValue(card, "Distinct evidence sources (records)", presentation.distinctEvidenceRecordCount === null ? "Unavailable in API response" : `${presentation.distinctEvidenceRecordCount} · ${presentation.evidenceId}`);
    distinction.textContent = presentation.interpretationExplanation;
    card.append(distinction);
    appendValue(card, "Independent corroboration", presentation.independentCorroboration === "not_established" ? "Not established by this single-evidence workflow" : "Unavailable");
    appendValue(card, "Causality or incident conclusion", presentation.causalityOrIncidentConclusion);
    appendValue(card, "Inference rule", `${hypothesis.inference_rule_id || "Unknown"} ${hypothesis.inference_rule_version || ""}`);
    appendValue(card, "Input observation IDs", hypothesis.input_observation_ids || []); appendValue(card, "Supporting observation IDs", hypothesis.supporting_observation_ids || []); appendValue(card, "Correlated observation IDs", hypothesis.correlated_observation_ids || []); appendValue(card, "Contradicting observation IDs", hypothesis.contradicting_observation_ids || []); appendValue(card, "Time extent", `${hypothesis.temporal_extent?.earliest_utc || "Unknown"} — ${hypothesis.temporal_extent?.latest_utc || "Unknown"}`); appendValue(card, "Attributes", hypothesis.attributes || {}); appendValue(card, "Assumptions", hypothesis.assumptions || []); appendValue(card, "Unresolved conditions", hypothesis.unresolved_conditions || []); appendValue(card, "Limitations", hypothesis.limitations || []); host.append(card);
  });
  if (!hypotheses.length) host.append(element("p", "form-help", "No hypotheses were returned for this page."));
  const skipped = Array.isArray(data.skipped_inputs) ? data.skipped_inputs : [];
  const skippedTotal = reconstructionPresentation.pageTotal(data, "skipped_inputs");
  host.append(element("h3", "subsection-title", `Skipped inputs (${skippedTotal} total)`));
  skipped.forEach((item) => { const row = element("p", "skipped-item", `${item.rule_id} · ${item.observation_id}: ${item.reason}`); host.append(row); });
  if (!skipped.length) host.append(element("p", "form-help", "No skipped inputs were returned for this page."));
  const page = data.pagination || {};
  const controls = element("div", "analysis-actions");
  const prevH = element("button", "button button-secondary", "Previous hypotheses"); prevH.type = "button"; prevH.disabled = a.hypothesisOffset <= 0; prevH.addEventListener("click", () => pageReconstruction(a.hypothesisOffset - ANALYSIS_PAGE_SIZE, a.skippedOffset));
  const nextH = element("button", "button button-secondary", "Next hypotheses"); nextH.type = "button"; nextH.disabled = a.hypothesisOffset + (page.hypotheses?.limit || ANALYSIS_PAGE_SIZE) >= (page.hypotheses?.total || 0); nextH.addEventListener("click", () => pageReconstruction(a.hypothesisOffset + ANALYSIS_PAGE_SIZE, a.skippedOffset));
  const prevS = element("button", "button button-secondary", "Previous skipped inputs"); prevS.type = "button"; prevS.disabled = a.skippedOffset <= 0; prevS.addEventListener("click", () => pageReconstruction(a.hypothesisOffset, a.skippedOffset - ANALYSIS_PAGE_SIZE));
  const nextS = element("button", "button button-secondary", "Next skipped inputs"); nextS.type = "button"; nextS.disabled = a.skippedOffset + (page.skipped_inputs?.limit || ANALYSIS_PAGE_SIZE) >= (page.skipped_inputs?.total || 0); nextS.addEventListener("click", () => pageReconstruction(a.hypothesisOffset, a.skippedOffset + ANALYSIS_PAGE_SIZE));
  controls.append(prevH, nextH, prevS, nextS); host.append(controls);
}
async function pageReconstruction(hypothesisOffset, skippedOffset) {
  const a = state.analysis, evidenceId = a.evidenceId, reconstructionId = a.reconstructionId, generation = a.generation;
  try { const result = await apiGet(`/api/v1/evidence/${encodeURIComponent(evidenceId)}/reconstructions/${encodeURIComponent(reconstructionId)}?hypothesis_offset=${hypothesisOffset}&hypothesis_limit=${ANALYSIS_PAGE_SIZE}&skipped_offset=${skippedOffset}&skipped_limit=${ANALYSIS_PAGE_SIZE}`); if (a.evidenceId !== evidenceId || a.reconstructionId !== reconstructionId || a.generation !== generation) return; a.hypothesisOffset = hypothesisOffset; a.skippedOffset = skippedOffset; a.reconstruction = result; renderReconstructionDetail(); }
  catch (error) { analysisAlert(error); }
}

function clearTimelineResult() {
  const t = state.timeline;
  t.result = null; t.offset = 0; t.selectedEventId = null;
  byId("timeline-summary").replaceChildren(); byId("timeline-summary").hidden = true;
  byId("timeline-known-list").replaceChildren(); byId("timeline-unresolved-list").replaceChildren();
  byId("timeline-detail").replaceChildren(); byId("timeline-detail").hidden = true;
  byId("timeline-page-status").textContent = "";
  byId("timeline-prev").disabled = true; byId("timeline-next").disabled = true;
  setAlert("timeline-error", "");
}
function prepareTimelineView() {
  const select = byId("timeline-evidence-select");
  const previous = select.value;
  const chosen = state.selectedId && state.evidence.some((item) => item.evidence_id === state.selectedId) ? state.selectedId : "";
  select.replaceChildren(new Option(state.evidence.length ? "Select an evidence record" : "No evidence records available", ""));
  state.evidence.forEach((record) => select.add(new Option(`${record.evidence_id} · ${safeFilename(record.original_filename)}`, record.evidence_id)));
  const evidenceId = chosen || (state.evidence.some((item) => item.evidence_id === previous) ? previous : "");
  select.value = evidenceId;
  if (state.timeline.evidenceId !== (evidenceId || null)) selectTimelineEvidence(evidenceId);
  else if (evidenceId && !state.timeline.analyses.length && !state.timeline.result) refreshTimelineAnalyses();
}
function selectTimelineEvidence(evidenceId) {
  const t = state.timeline;
  t.evidenceId = evidenceId || null; t.analysisId = null; t.analyses = []; t.generation += 1;
  state.selectedId = evidenceId || null;
  clearTimelineResult();
  setAlert("timeline-error", "");
  byId("timeline-no-analysis").hidden = true;
  byId("timeline-analysis-select").replaceChildren(new Option(evidenceId ? "Loading stored analyses…" : "Select evidence first", ""));
  byId("timeline-analysis-select").disabled = !evidenceId;
  byId("timeline-load-button").disabled = true;
  byId("timeline-status").textContent = evidenceId ? "Loading stored analyses…" : "Select evidence and a stored analysis, then load the timeline.";
  if (evidenceId) refreshTimelineAnalyses();
}
async function refreshTimelineAnalyses() {
  const t = state.timeline, evidenceId = t.evidenceId, generation = t.generation;
  if (!evidenceId) return;
  clearTimelineResult();
  byId("timeline-status").textContent = "Loading stored analyses…";
  byId("timeline-analysis-select").disabled = true;
  byId("timeline-load-button").disabled = true;
  try {
    const first = await apiGet(`/api/v1/evidence/${encodeURIComponent(evidenceId)}/analyses?offset=0&limit=100`);
    if (t.evidenceId !== evidenceId || t.generation !== generation) return;
    const total = first.pagination?.total_analyses;
    if (!Number.isInteger(total) || total < 0) throw new Error("The API returned invalid analysis pagination data.");
    t.analyses = Array.isArray(first.analyses) ? first.analyses : [];
    // Analysis list pages are capped at 100; fetch later pages only when needed.
    for (let offset = 100; offset < total; offset += 100) {
      const page = await apiGet(`/api/v1/evidence/${encodeURIComponent(evidenceId)}/analyses?offset=${offset}&limit=100`);
      if (t.evidenceId !== evidenceId || t.generation !== generation) return;
      t.analyses.push(...(Array.isArray(page.analyses) ? page.analyses : []));
    }
    const select = byId("timeline-analysis-select");
    select.replaceChildren(new Option(t.analyses.length ? "Select a stored analysis" : "No stored analyses", ""));
    t.analyses.forEach((item) => select.add(new Option(`${item.analysis_id} · ${item.parser} · ${item.event_count} events · ${formatDate(item.created_at)}`, item.analysis_id)));
    select.disabled = !t.analyses.length;
    byId("timeline-no-analysis").hidden = t.analyses.length > 0;
    byId("timeline-status").textContent = t.analyses.length ? `${t.analyses.length} stored ${t.analyses.length === 1 ? "analysis" : "analyses"} available. Choose one and load its timeline.` : "No stored analysis is available for this evidence.";
  } catch (error) {
    if (t.evidenceId !== evidenceId || t.generation !== generation) return;
    t.analyses = [];
    byId("timeline-analysis-select").replaceChildren(new Option("Analyses unavailable", ""));
    byId("timeline-analysis-select").disabled = true;
    byId("timeline-status").textContent = "Stored analyses could not be loaded.";
    setAlert("timeline-error", `${error.code ? `${error.code}: ` : ""}${error.message || "The request failed."}`);
  }
}
function renderTimeline() {
  const t = state.timeline, payload = t.result;
  if (!payload) return;
  const summary = byId("timeline-summary"); summary.hidden = false; summary.replaceChildren();
  summary.append(element("span", "timeline-count", `${payload.counts.known_time} events with bounded UTC times`));
  summary.append(element("span", "timeline-count", `${payload.counts.unresolved_time} events without a fully bounded UTC extent (${payload.counts.partially_bounded} partially bounded)`));
  const known = byId("timeline-known-list"), unresolved = byId("timeline-unresolved-list");
  known.replaceChildren(); unresolved.replaceChildren();
  const entries = Array.isArray(payload.entries) ? payload.entries : [];
  entries.forEach((entry) => {
    const item = element("li", "timeline-item");
    const button = element("button", `timeline-event${entry.event_id === t.selectedEventId ? " selected" : ""}`);
    button.type = "button"; button.setAttribute("aria-pressed", String(entry.event_id === t.selectedEventId));
    button.append(element("strong", "timeline-event-type", entry.event_type), element("span", "timeline-event-id", entry.event_id));
    const extent = entry.temporal_extent || {};
    button.append(element("span", "timeline-event-time", entry.time_status === "bounded_utc" ? `${extent.earliest_utc} — ${extent.latest_utc} (UTC)` : entry.time_status === "partially_bounded" ? `Partial UTC extent · ${extent.earliest_utc || extent.latest_utc} (UTC)` : "No justified UTC extent"));
    button.addEventListener("click", () => { t.selectedEventId = entry.event_id; renderTimeline(); renderTimelineDetail(entry); });
    item.append(button); (entry.time_status === "bounded_utc" ? known : unresolved).append(item);
  });
  if (!payload.counts.known_time) known.append(element("li", "timeline-empty", "No events have a fully bounded normalized UTC extent."));
  if (!payload.counts.partially_bounded && !payload.counts.unresolved_time) unresolved.append(element("li", "timeline-empty", "No events have unresolved time."));
  const page = payload.pagination;
  byId("timeline-page-status").textContent = `Showing ${page.total ? page.offset + 1 : 0}–${Math.min(page.offset + entries.length, page.total)} of ${page.total}`;
  byId("timeline-prev").disabled = page.offset <= 0;
  byId("timeline-next").disabled = page.offset + page.limit >= page.total;
}
function renderTimelineDetail(entry) {
  const host = byId("timeline-detail"); host.hidden = false; host.replaceChildren();
  host.append(element("h2", "subsection-title", `Source detail · ${entry.event_type}`));
  appendValue(host, "Event ID", entry.event_id); appendValue(host, "Time status", entry.time_status);
  appendValue(host, "Normalized UTC extent", `${entry.temporal_extent?.earliest_utc || "Unknown"} — ${entry.temporal_extent?.latest_utc || "Unknown"}`);
  (entry.source_observations || []).forEach((observation, index) => {
    const section = element("section", "source-observation");
    section.append(element("h3", "event-card-title", `Source observation ${index + 1}`));
    appendValue(section, "Observation ID", observation.observation_id);
    appendValue(section, "Evidence ID", observation.evidence_id);
    appendValue(section, "Source locator", observation.source_locator);
    appendValue(section, "Parser", `${observation.parser_name} ${observation.parser_version}`);
    appendValue(section, "Parse status", observation.parse_status);
    appendValue(section, "Raw timestamp", observation.timestamp?.raw_value || "Not present");
    appendValue(section, "Raw timestamp format", observation.timestamp?.raw_format || "Not known");
    appendValue(section, "Timezone certainty", observation.timestamp?.timezone_status || "Unknown");
    appendValue(section, "Timestamp precision", observation.timestamp?.precision || "Unknown");
    host.append(section);
  });
}
async function loadTimeline(offset = 0) {
  const t = state.timeline, evidenceId = t.evidenceId, analysisId = byId("timeline-analysis-select").value, generation = t.generation;
  if (!evidenceId || !analysisId) return;
  t.analysisId = analysisId; t.offset = offset; t.result = null; t.selectedEventId = null;
  byId("timeline-detail").hidden = true; byId("timeline-summary").hidden = true;
  byId("timeline-known-list").replaceChildren(element("li", "timeline-empty", "Loading timeline…"));
  byId("timeline-unresolved-list").replaceChildren();
  byId("timeline-load-button").disabled = true; byId("timeline-status").textContent = "Loading validated analysis events…";
  setAlert("timeline-error", "");
  try {
    const result = await apiGet(`/api/v1/evidence/${encodeURIComponent(evidenceId)}/analyses/${encodeURIComponent(analysisId)}/timeline?offset=${offset}&limit=${ANALYSIS_PAGE_SIZE}`);
    if (t.evidenceId !== evidenceId || t.analysisId !== analysisId || t.generation !== generation) return;
    t.result = result; t.offset = offset;
    byId("timeline-status").textContent = result.entries.length ? "Timeline loaded from the selected stored analysis." : "The selected analysis contains no normalized events.";
    renderTimeline();
  } catch (error) {
    if (t.evidenceId !== evidenceId || t.analysisId !== analysisId || t.generation !== generation) return;
    t.result = null;
    byId("timeline-known-list").replaceChildren(); byId("timeline-unresolved-list").replaceChildren();
    byId("timeline-page-status").textContent = "";
    byId("timeline-status").textContent = "Timeline could not be loaded.";
    setAlert("timeline-error", `${error.code ? `${error.code}: ` : ""}${error.message || "The request failed."}`);
  } finally {
    if (t.evidenceId === evidenceId && t.generation === generation) byId("timeline-load-button").disabled = !byId("timeline-analysis-select").value;
  }
}

function closeUploadDialog() {
  if (uploadController) {
    uploadController.abort();
    return;
  }
  byId("upload-dialog").close();
}

document.querySelectorAll("[data-view]").forEach((button) => {
  button.addEventListener("click", () => showView(button.dataset.view));
});
document.querySelectorAll("[data-go]").forEach((button) => {
  button.addEventListener("click", () => showView(button.dataset.go));
});
byId("refresh-button").addEventListener("click", refreshData);
byId("api-session-button").addEventListener("click", () => {
  if (apiAccessToken) clearApiSession();
  else openApiAuthDialog();
});
byId("api-auth-form").addEventListener("submit", authorizeApiSession);
byId("api-auth-cancel").addEventListener("click", () => {
  byId("api-token").value = "";
  byId("api-auth-dialog").close();
});
byId("api-auth-dialog").addEventListener("cancel", () => { byId("api-token").value = ""; });
byId("api-auth-dialog").addEventListener("close", () => { byId("api-token").value = ""; });
byId("evidence-search").addEventListener("input", renderExplorer);
byId("verify-evidence-select").addEventListener("change", (event) => {
  const hasVal = Boolean(event.target.value);
  byId("verify-button").disabled = !hasVal;
  if (byId("simulate-tamper-btn")) byId("simulate-tamper-btn").disabled = !hasVal;
  if (byId("simulate-missing-btn")) byId("simulate-missing-btn").disabled = !hasVal;
  if (hasVal) {
    runVerification();
  } else {
    byId("verification-result").replaceChildren(
      element("div", "verification-prompt", "Select an evidence record and run an integrity check.")
    );
  }
});
byId("verify-button").addEventListener("click", runVerification);

if (byId("simulate-tamper-btn")) {
  byId("simulate-tamper-btn").addEventListener("click", async () => {
    const eid = byId("verify-evidence-select").value;
    if (!eid) return;
    const btn = byId("simulate-tamper-btn");
    btn.disabled = true;
    btn.querySelector("span").textContent = "Tampering…";
    try {
      await apiPostJson(`/api/v1/recovery/${encodeURIComponent(eid)}/simulate-tamper`, {});
      await runVerification();
    } catch (err) {
      alert(`Simulation failed: ${err.message}`);
    } finally {
      btn.disabled = !byId("verify-evidence-select").value;
      btn.querySelector("span").textContent = "⚡ Corrupt / Tamper";
    }
  });
}

if (byId("simulate-missing-btn")) {
  byId("simulate-missing-btn").addEventListener("click", async () => {
    const eid = byId("verify-evidence-select").value;
    if (!eid) return;
    const btn = byId("simulate-missing-btn");
    btn.disabled = true;
    btn.querySelector("span").textContent = "Deleting…";
    try {
      await apiPostJson(`/api/v1/recovery/${encodeURIComponent(eid)}/simulate-missing`, {});
      await runVerification();
    } catch (err) {
      alert(`Simulation failed: ${err.message}`);
    } finally {
      btn.disabled = !byId("verify-evidence-select").value;
      btn.querySelector("span").textContent = "⚡ Delete / Missing";
    }
  });
}
byId("add-evidence-button").addEventListener("click", openUploadDialog);
byId("upload-file").addEventListener("change", (event) => {
  uploadFile = event.target.files?.[0] || null;
  byId("upload-selection").textContent = uploadFile
    ? `${uploadFile.name} · ${formatSize(uploadFile.size)}`
    : "Choose a file from this device. A server-side path cannot be submitted.";
});
byId("upload-form").addEventListener("submit", submitUpload);
byId("upload-cancel-button").addEventListener("click", closeUploadDialog);
byId("upload-dialog").addEventListener("cancel", () => {
  if (uploadController) uploadController.abort();
});
byId("upload-verify-button").addEventListener("click", verifyUploadedEvidence);
byId("activity-refresh-button").addEventListener("click", refreshActivity);
byId("analysis-evidence-select").addEventListener("change", (event) => selectAnalysisEvidence(event.target.value));
byId("analysis-refresh-button").addEventListener("click", () => state.analysis.evidenceId ? refreshAnalysisLists() : loadRules());
byId("timeline-evidence-select").addEventListener("change", (event) => selectTimelineEvidence(event.target.value));
byId("timeline-analysis-select").addEventListener("change", (event) => {
  state.timeline.analysisId = event.target.value || null;
  clearTimelineResult();
  byId("timeline-load-button").disabled = !event.target.value;
  byId("timeline-status").textContent = event.target.value ? "Load the selected stored analysis to view its timeline." : "Select a stored analysis.";
});
byId("timeline-refresh-button").addEventListener("click", refreshTimelineAnalyses);
byId("timeline-load-button").addEventListener("click", () => loadTimeline(0));
byId("timeline-prev").addEventListener("click", () => loadTimeline(Math.max(0, state.timeline.offset - ANALYSIS_PAGE_SIZE)));
byId("timeline-next").addEventListener("click", () => loadTimeline(state.timeline.offset + ANALYSIS_PAGE_SIZE));
byId("run-analysis-button").addEventListener("click", runAnalysis);
byId("analysis-run-select").addEventListener("change", (event) => {
  state.analysis.analysisId = event.target.value || null;
  state.analysis.detail = null; state.analysis.reconstruction = null; state.analysis.reconstructionId = null;
  byId("analysis-detail").replaceChildren(); byId("reconstruction-detail").replaceChildren();
  byId("reconstruction-summary").replaceChildren(element("p", "form-help", "Load a stored reconstruction after loading its analysis."));
  byId("run-reconstruction-button").disabled = true; byId("load-analysis-button").disabled = !event.target.value;
});
byId("load-analysis-button").addEventListener("click", loadAnalysis);
byId("analyses-prev").addEventListener("click", () => { state.analysis.analysisOffset = Math.max(0, state.analysis.analysisOffset - ANALYSIS_PAGE_SIZE); refreshAnalysisLists(); });
byId("analyses-next").addEventListener("click", () => { state.analysis.analysisOffset += ANALYSIS_PAGE_SIZE; refreshAnalysisLists(); });
byId("run-reconstruction-button").addEventListener("click", runReconstruction);
byId("reconstruction-run-select").addEventListener("change", (event) => {
  const a = state.analysis;
  a.reconstructionId = event.target.value || null; a.reconstruction = null; a.hypothesisOffset = 0; a.skippedOffset = 0;
  byId("reconstruction-summary").replaceChildren(element("p", "form-help", event.target.value ? "Load this stored reconstruction to view its current result page." : "No reconstruction run selected."));
  byId("reconstruction-detail").replaceChildren(); byId("load-reconstruction-button").disabled = !event.target.value;
});
byId("load-reconstruction-button").addEventListener("click", loadReconstruction);
byId("reconstructions-prev").addEventListener("click", () => { state.analysis.runsOffset = Math.max(0, state.analysis.runsOffset - ANALYSIS_PAGE_SIZE); refreshAnalysisLists(); });
byId("reconstructions-next").addEventListener("click", () => { state.analysis.runsOffset += ANALYSIS_PAGE_SIZE; refreshAnalysisLists(); });
window.addEventListener("hashchange", () => showView(location.hash.slice(1)));

const initialView = location.hash.slice(1);
showView(views[initialView] ? initialView : "dashboard");
updateApiSessionButton();
refreshData().then(() => {
  if (!apiAccessToken) openApiAuthDialog();
});


/* =========================================================================
   HACKATHON EXTENSIONS: RECOVERY VAULT, MTLS LAB, DATASET REPLAY, INTELLIGENCE
   ========================================================================= */

// --- 1. RECOVERY VAULT ---
async function loadRecoveryStatus() {
  try {
    const res = await apiGet("/api/v1/recovery/status");
    if (byId("rec-copies-count")) byId("rec-copies-count").textContent = res.total_recovery_copies ?? 0;
    if (byId("rec-valid-count")) byId("rec-valid-count").textContent = res.primary_valid_count ?? 0;
    if (byId("rec-tampered-count")) byId("rec-tampered-count").textContent = res.primary_tampered_count ?? 0;
    if (byId("rec-missing-count")) byId("rec-missing-count").textContent = res.primary_missing_count ?? 0;
  } catch (err) {
    console.warn("Could not load recovery status", err);
  }
}

async function bootstrapRecovery() {
  const btn = byId("recovery-sync-btn");
  if (btn) btn.disabled = true;
  try {
    const res = await apiPostJson("/api/v1/recovery/bootstrap", {});
    alert(`Recovery Vault Synchronized!\nNew copies created: ${res.copied_count}\nTotal verified: ${res.total_copies}\nBytes stored: ${res.total_bytes}`);
    await loadRecoveryStatus();
  } catch (err) {
    alert("Recovery sync failed: " + err.message);
  } finally {
    if (btn) btn.disabled = false;
  }
}

async function runDisposableRecoveryDemo() {
  const btn = byId("recovery-demo-btn");
  const panel = byId("recovery-demo-panel");
  const stepsList = byId("recovery-demo-steps");
  if (btn) btn.disabled = true;
  if (panel) panel.hidden = false;
  if (stepsList) stepsList.replaceChildren(element("div", "", "Executing 4-stage disposable tamper & recovery sequence in temporary sandbox…"));

  try {
    const res = await apiPostJson("/api/v1/recovery/demo-disposable", {});
    if (stepsList) {
      stepsList.replaceChildren();
      
      const step1 = element("div", "", `[STAGE 1] Ingested clean evidence (${res.test_evidence_id}): `);
      step1.append(element("span", "badge badge-valid", res.initial_valid ? "INITIAL VALID" : "FAILED"));
      
      const step2 = element("div", "", `[STAGE 2] Snapshot stored in SHA-256 Recovery Vault: `);
      step2.append(element("span", "badge badge-valid", "COPIED"));

      const step3 = element("div", "", `[STAGE 3] Primary file deleted -> State detected: `);
      step3.append(element("span", "badge badge-tampered", res.missing_detected ? "MISSING DETECTED" : "UNNOTICED"));
      step3.append(document.createTextNode(" -> Restored from recovery copy: "));
      step3.append(element("span", "badge badge-valid", res.restore_missing_status));

      const step4 = element("div", "", `[STAGE 4] Primary file bytes corrupted -> State detected: `);
      step4.append(element("span", "badge badge-tampered", res.tamper_detected ? "TAMPERED DETECTED" : "UNNOTICED"));
      step4.append(document.createTextNode(" -> Corrupted copy quarantined -> Restored from recovery copy: "));
      step4.append(element("span", "badge badge-valid", res.restore_tampered_status));

      const step5 = element("div", "", `[CONCLUSION] Final vault state: `);
      step5.append(element("span", "badge badge-valid", res.final_state));
      step5.append(document.createTextNode(` (${res.disclaimer})`));

      stepsList.append(step1, step2, step3, step4, step5);
    }
    await loadRecoveryStatus();
  } catch (err) {
    if (stepsList) stepsList.textContent = "Demo error: " + err.message;
  } finally {
    if (btn) btn.disabled = false;
  }
}

if (byId("recovery-sync-btn")) byId("recovery-sync-btn").addEventListener("click", bootstrapRecovery);
if (byId("recovery-demo-btn")) byId("recovery-demo-btn").addEventListener("click", runDisposableRecoveryDemo);


// --- 2. ADAPTIVE MTLS PERFORMANCE LAB ---
let mtlsInitDone = false;

function initMtlsView() {
  if (mtlsInitDone) return;
  mtlsInitDone = true;
  runMtlsSimulation();
  runProfileComparison();
}

const slider = byId("mtls-risk-slider");
if (slider) {
  slider.addEventListener("input", (e) => {
    const val = parseInt(e.target.value, 10);
    const label = byId("mtls-risk-val");
    if (!label) return;
    if (val < 30) label.textContent = `${val} (GREEN · 120s TTL)`;
    else if (val <= 70) label.textContent = `${val} (YELLOW · 15s freshness)`;
    else label.textContent = `${val} (RED · Context evicted, full mTLS)`;
  });
}

async function runMtlsSimulation() {
  const btn = byId("mtls-run-sim-btn");
  if (btn) btn.disabled = true;
  setAlert("mtls-error", "");

  const profile = document.querySelector('input[name="mtls-profile"]:checked')?.value || "adaptive";
  const risk_score = parseInt(byId("mtls-risk-slider")?.value || "15", 10);
  const inject_cert_mismatch = Boolean(byId("mtls-mismatch-check")?.checked);

  try {
    const res = await apiPostJson("/api/v1/mtls/simulate", {
      profile,
      risk_score,
      inject_cert_mismatch,
      seed: 42
    });

    const statusP = byId("mtls-topology-status");
    if (statusP) {
      statusP.textContent = `${res.summary} | Latency: ${res.total_latency_ms.toFixed(2)}ms`;
    }

    const badge = byId("mtls-run-summary-badge");
    if (badge) {
      badge.className = `badge ${res.status === "COMPLETED" ? "badge-valid" : "badge-tampered"}`;
      badge.textContent = `${res.status} · ${res.risk_band} RISK`;
    }

    renderMtlsTopologySvg(res.hops, res.status, res.context_evicted);

    const tbody = byId("mtls-hop-rows");
    if (tbody) {
      tbody.replaceChildren();
      res.hops.forEach((h) => {
        const tr = element("tr");
        const decision = h.decision || h.outcome || "ALLOW";
        const isErr = decision === "REJECT";
        const isBlocked = decision === "BLOCKED";
        const authPath = (h.auth_path || h.verification_method || "").replace(/_/g, " ");
        const tokenUsed = Boolean(h.context_token_used || h.context_token_valid);

        tr.append(element("td", "", String(h.hop_number)));
        tr.append(element("td", "", `${h.source_service} → ${h.destination_service || h.target_service}`));
        tr.append(element("td", "timestamp-cell", h.latency_ms > 0 ? `${h.latency_ms.toFixed(2)}ms` : "0.00ms"));
        tr.append(element("td", "", authPath));
        
        const outcomeCell = element("td", "");
        const badgeClass = isErr ? "badge-tampered" : (isBlocked ? "badge-simulated" : "badge-valid");
        outcomeCell.append(element("span", `badge ${badgeClass}`, decision));
        tr.append(outcomeCell);

        const tokCell = element("td", "");
        tokCell.append(element("span", tokenUsed ? "badge badge-valid" : "badge badge-simulated", tokenUsed ? "ACTIVE" : (isErr ? "EVICTED" : (isBlocked ? "BLOCKED" : "NONE"))));
        tr.append(tokCell);
        tbody.append(tr);
      });
    }

    await runProfileComparison(risk_score);
  } catch (err) {
    setAlert("mtls-error", err.message);
  } finally {
    if (btn) btn.disabled = false;
  }
}

async function runProfileComparison(riskScore = 15) {
  try {
    const comp = await apiGet(`/api/v1/mtls/compare?risk_score=${riskScore}&seed=42`);
    if (comp && comp.comparison) {
      renderLatencyComparisonSvg(comp.comparison);
    }
  } catch (err) {
    console.warn("Could not load latency comparison", err);
  }
}

async function runMtlsCalibration() {
  const btn = byId("mtls-calibrate-btn");
  if (btn) btn.disabled = true;
  try {
    const cal = await apiPostJson("/api/v1/mtls/calibrate", {});
    alert(`Host-Local Loopback TLS Calibration (127.0.0.1):\nSamples: ${cal.successful_samples}\nMean Handshake: ${cal.handshake_latency_ms.mean}ms\nMedian: ${cal.handshake_latency_ms.median}ms\np95: ${cal.handshake_latency_ms.p95}ms\n\nNotice: ${cal.disclaimer}`);
  } catch (err) {
    alert("Calibration failed: " + err.message);
  } finally {
    if (btn) btn.disabled = false;
  }
}

async function exportMtlsTelemetry() {
  const btn = byId("mtls-export-btn");
  if (btn) btn.disabled = true;
  try {
    const profile = document.querySelector('input[name="mtls-profile"]:checked')?.value || "adaptive";
    const risk_score = parseInt(byId("mtls-risk-slider")?.value || "15", 10);
    const inject_cert_mismatch = Boolean(byId("mtls-mismatch-check")?.checked);
    const res = await apiPostJson("/api/v1/mtls/export-evidence", {
      profile,
      risk_score,
      inject_cert_mismatch,
      seed: 42
    });
    alert(`mTLS Telemetry Successfully Exported to Primary Vault!\nEvidence ID: ${res.evidence_id}\nStatus: Ingested, Verified & Parsed\nRecovery Snapshot: Created`);
    await refreshData();
  } catch (err) {
    alert("Export failed: " + err.message);
  } finally {
    if (btn) btn.disabled = false;
  }
}

function renderMtlsTopologySvg(hops, status, contextEvicted) {
  const svg = byId("mtls-topology-svg");
  if (!svg) return;
  svg.replaceChildren();

  const services = [
    "Client", "API Gateway", "Identity", "Policy Engine", "Order Svc", "Inventory", "Payment"
  ];
  const nodeW = 90;
  const nodeH = 46;
  const startX = 15;
  const gapX = 30;
  const startY = 46;

  services.forEach((sName, i) => {
    const x = startX + i * (nodeW + gapX);
    const g = document.createElementNS("http://www.w3.org/2000/svg", "g");
    g.setAttribute("class", "topology-node");

    let strokeColor = "#4295e5";
    let strokeDash = "none";
    let fillColor = "#141c26";
    let textColor = "#e5ebf1";

    if (hops && hops.length > 0) {
      if (i === 0) {
        strokeColor = "#72c9a2";
      } else {
        const hop = hops.find(h => h.hop_number === i);
        if (!hop) {
          strokeColor = "#303e4c";
          fillColor = "#0f151c";
          textColor = "#6f7d8c";
        } else {
          const dec = hop.decision || hop.outcome;
          if (dec === "REJECT") {
            strokeColor = "#ed8b91";
            fillColor = "#2b1618";
            textColor = "#ff9fa5";
          } else if (dec === "BLOCKED") {
            strokeColor = "#556475";
            strokeDash = "4, 4";
            fillColor = "#0e1319";
            textColor = "#657484";
          } else {
            strokeColor = "#72c9a2";
          }
        }
      }
    }

    const rect = document.createElementNS("http://www.w3.org/2000/svg", "rect");
    rect.setAttribute("x", x);
    rect.setAttribute("y", startY);
    rect.setAttribute("width", nodeW);
    rect.setAttribute("height", nodeH);
    rect.setAttribute("rx", "5");
    rect.setAttribute("fill", fillColor);
    rect.setAttribute("stroke", strokeColor);
    if (strokeDash !== "none") rect.setAttribute("stroke-dasharray", strokeDash);
    rect.setAttribute("stroke-width", "1.5");

    const text = document.createElementNS("http://www.w3.org/2000/svg", "text");
    text.setAttribute("x", x + nodeW / 2);
    text.setAttribute("y", startY + 28);
    text.setAttribute("text-anchor", "middle");
    text.setAttribute("fill", textColor);
    text.setAttribute("font-size", "11");
    text.setAttribute("font-family", "Inter, sans-serif");
    text.setAttribute("font-weight", "600");
    text.textContent = sName;

    g.append(rect, text);
    svg.append(g);

    // Connecting arrow to next node
    if (i < services.length - 1) {
      const hopIdx = i + 1;
      const hop = hops ? hops.find(h => h.hop_number === hopIdx) : null;
      let arrowColor = "#303e4c";
      let arrowDash = "none";
      if (hop) {
        const dec = hop.decision || hop.outcome;
        if (dec === "REJECT") {
          arrowColor = "#ed8b91";
        } else if (dec === "BLOCKED") {
          arrowColor = "#445363";
          arrowDash = "3, 3";
        } else {
          arrowColor = "#72c9a2";
        }
      }

      const line = document.createElementNS("http://www.w3.org/2000/svg", "line");
      const x1 = x + nodeW;
      const x2 = x + nodeW + gapX;
      const y = startY + nodeH / 2;
      line.setAttribute("x1", x1);
      line.setAttribute("y1", y);
      line.setAttribute("x2", x2);
      line.setAttribute("y2", y);
      line.setAttribute("stroke", arrowColor);
      line.setAttribute("stroke-width", "2");
      if (arrowDash !== "none") line.setAttribute("stroke-dasharray", arrowDash);

      const head = document.createElementNS("http://www.w3.org/2000/svg", "polygon");
      head.setAttribute("points", `${x2-5},${y-4} ${x2},${y} ${x2-5},${y+4}`);
      head.setAttribute("fill", arrowColor);

      svg.append(line, head);

      if (hop && hop.latency_ms > 0) {
        const latText = document.createElementNS("http://www.w3.org/2000/svg", "text");
        latText.setAttribute("x", x1 + gapX / 2);
        latText.setAttribute("y", y - 7);
        latText.setAttribute("text-anchor", "middle");
        latText.setAttribute("fill", arrowColor);
        latText.setAttribute("font-size", "9");
        latText.setAttribute("font-family", "monospace");
        latText.textContent = `${hop.latency_ms.toFixed(1)}ms`;
        svg.append(latText);
      }
    }
  });
}

function renderLatencyComparisonSvg(comparison) {
  const svg = byId("mtls-latency-svg");
  if (!svg || !comparison) return;
  svg.replaceChildren();

  const churn = comparison.churn?.total_latency_ms || 60;
  const persistent = comparison.persistent?.total_latency_ms || 28;
  const adaptive = comparison.adaptive?.total_latency_ms || 18;

  const maxVal = Math.max(churn, persistent, adaptive, 70);
  const barHeight = 22;
  const barYStart = 20;
  const barGap = 38;
  const maxBarWidth = 400;
  const labelX = 140;

  const modes = [
    { name: "High Churn mTLS", val: churn, color: "#ed8b91" },
    { name: "Persistent Baseline", val: persistent, color: "#83b8e7" },
    { name: "Risk-Adaptive mTLS", val: adaptive, color: "#72c9a2" },
  ];

  modes.forEach((m, idx) => {
    const y = barYStart + idx * barGap;
    const w = (m.val / maxVal) * maxBarWidth;

    const label = document.createElementNS("http://www.w3.org/2000/svg", "text");
    label.setAttribute("x", labelX - 10);
    label.setAttribute("y", y + 16);
    label.setAttribute("text-anchor", "end");
    label.setAttribute("fill", "#c0cad4");
    label.setAttribute("font-size", "12");
    label.setAttribute("font-family", "Inter, sans-serif");
    label.textContent = m.name;

    const rect = document.createElementNS("http://www.w3.org/2000/svg", "rect");
    rect.setAttribute("x", labelX);
    rect.setAttribute("y", y);
    rect.setAttribute("width", Math.max(w, 8));
    rect.setAttribute("height", barHeight);
    rect.setAttribute("rx", "3");
    rect.setAttribute("fill", m.color);

    const valText = document.createElementNS("http://www.w3.org/2000/svg", "text");
    valText.setAttribute("x", labelX + w + 10);
    valText.setAttribute("y", y + 16);
    valText.setAttribute("fill", "#eaf1f7");
    valText.setAttribute("font-size", "12");
    valText.setAttribute("font-family", "monospace");
    valText.setAttribute("font-weight", "600");
    valText.textContent = `${m.val.toFixed(2)} ms`;

    svg.append(label, rect, valText);
  });
}

if (byId("mtls-run-sim-btn")) byId("mtls-run-sim-btn").addEventListener("click", runMtlsSimulation);
if (byId("mtls-calibrate-btn")) byId("mtls-calibrate-btn").addEventListener("click", runMtlsCalibration);
if (byId("mtls-export-btn")) byId("mtls-export-btn").addEventListener("click", exportMtlsTelemetry);


// --- 3. SYNTHETIC DATASET REPLAY ---
let replayPollTimer = null;

async function loadDatasetInfo() {
  try {
    const info = await apiGet("/api/v1/dataset/info");
    const badge = byId("replay-status-badge");
    if (info.valid) {
      if (badge) {
        badge.className = "badge badge-valid";
        badge.textContent = `CORPUS VALID (v${info.version})`;
      }
    }
    await pollReplayStatus();
  } catch (err) {
    console.warn("Could not load dataset info", err);
  }
}

let isReplayPolling = false;
async function pollReplayStatus() {
  if (isReplayPolling) return;
  isReplayPolling = true;
  try {
    const st = await apiGet("/api/v1/dataset/replay/status");
    if (!st) return;

    if (byId("replay-run-id-text")) {
      byId("replay-run-id-text").textContent = st.run_id ? `Run ID: ${st.run_id}` : "No active replay run.";
    }

    const badge = byId("replay-status-badge");
    if (badge && st.status) {
      badge.textContent = st.status.toUpperCase();
      badge.className = `badge ${st.status === "running" ? "badge-valid" : (st.status === "completed" ? "badge-pending" : "badge-simulated")}`;
    }

    const prepared = st.records_prepared || st.records_selected || 0;
    const target = st.target_total || st.records_selected || st.record_limit || 1000;
    const pct = target > 0 ? Math.min(100, Math.round((prepared / target) * 100)) : 0;
    if (byId("replay-progress-fill")) byId("replay-progress-fill").style.width = `${pct}%`;
    if (byId("replay-progress-pct")) byId("replay-progress-pct").textContent = `${pct}% (${st.records_ingested}/${prepared})`;
    if (byId("replay-elapsed-time")) byId("replay-elapsed-time").textContent = `Elapsed: ${st.elapsed_seconds.toFixed(1)}s`;

    if (byId("replay-count-ingested")) byId("replay-count-ingested").textContent = st.records_ingested;
    if (byId("replay-count-parsed")) byId("replay-count-parsed").textContent = st.records_parsed;
    if (byId("replay-count-batches")) byId("replay-count-batches").textContent = st.batches_created;
    if (byId("replay-count-failed")) byId("replay-count-failed").textContent = st.records_failed;

    if (byId("replay-cur-source")) byId("replay-cur-source").textContent = st.current_source || "—";
    if (byId("replay-cur-batch")) byId("replay-cur-batch").textContent = st.current_batch ? `Batch #${st.current_batch}` : "—";

    // Button states
    const isRunning = st.status === "running";
    const isPaused = st.status === "paused";
    if (byId("replay-start-btn")) byId("replay-start-btn").disabled = isRunning;
    if (byId("replay-pause-btn")) byId("replay-pause-btn").disabled = !isRunning;
    if (byId("replay-resume-btn")) byId("replay-resume-btn").disabled = !isPaused;
    if (byId("replay-stop-btn")) byId("replay-stop-btn").disabled = !(isRunning || isPaused);

    if (st.status === "completed" || st.status === "stopped" || st.status === "error") {
      if (replayPollTimer) {
        clearInterval(replayPollTimer);
        replayPollTimer = null;
      }
      refreshData();
      loadInvestigationRisk();
      loadCorrelationGraph();
    }
  } catch (err) {
    console.warn("Replay poll error", err);
  } finally {
    isReplayPolling = false;
  }
}

async function startReplay() {
  const sources = Array.from(document.querySelectorAll('input[name="replay-source"]:checked')).map(cb => cb.value);
  if (!sources.length) {
    alert("Please select at least one source file.");
    return;
  }
  const seed = parseInt(byId("replay-seed")?.value || "42", 10);
  const record_limit = parseInt(byId("replay-cap")?.value || "1000", 10);
  const batch_size = parseInt(byId("replay-batch-size")?.value || "200", 10);
  const inter_batch_delay_ms = parseInt(byId("replay-delay")?.value || "50", 10);

  setAlert("replay-error", "");
  try {
    await apiPostJson("/api/v1/dataset/replay/start", {
      sources,
      seed,
      record_limit,
      batch_size,
      delay_ms: inter_batch_delay_ms,
      inter_batch_delay_ms
    });

    if (!replayPollTimer) {
      replayPollTimer = setInterval(pollReplayStatus, 800);
    }
    await pollReplayStatus();
  } catch (err) {
    setAlert("replay-error", err.message);
  }
}

async function pauseReplay() {
  try {
    await apiPostJson("/api/v1/dataset/replay/pause", {});
    await pollReplayStatus();
  } catch (err) {
    setAlert("replay-error", err.message);
  }
}

async function resumeReplay() {
  try {
    await apiPostJson("/api/v1/dataset/replay/resume", {});
    if (!replayPollTimer) {
      replayPollTimer = setInterval(pollReplayStatus, 800);
    }
    await pollReplayStatus();
  } catch (err) {
    setAlert("replay-error", err.message);
  }
}

async function stopReplay() {
  try {
    await apiPostJson("/api/v1/dataset/replay/stop", {});
    await pollReplayStatus();
  } catch (err) {
    setAlert("replay-error", err.message);
  }
}

if (byId("replay-start-btn")) byId("replay-start-btn").addEventListener("click", startReplay);
if (byId("replay-pause-btn")) byId("replay-pause-btn").addEventListener("click", pauseReplay);
if (byId("replay-resume-btn")) byId("replay-resume-btn").addEventListener("click", resumeReplay);
if (byId("replay-stop-btn")) byId("replay-stop-btn").addEventListener("click", stopReplay);


// --- 4. INVESTIGATION RISK & CORRELATION GRAPH ---
async function loadInvestigationRisk() {
  try {
    const res = await apiGet("/api/v1/investigation/risk-score");
    if (!res) return;

    if (byId("risk-score-number")) byId("risk-score-number").textContent = res.score ?? 0;
    if (byId("risk-score-band")) {
      byId("risk-score-band").textContent = res.risk_band || res.severity_band || "LOW";
      byId("risk-score-band").style.color = res.score > 70 ? "var(--red)" : (res.score > 30 ? "var(--amber)" : "var(--green)");
    }
    if (byId("risk-score-circle")) {
      const color = res.score > 70 ? "var(--red)" : (res.score > 30 ? "var(--amber)" : "var(--green)");
      byId("risk-score-circle").style.borderColor = color;
    }

    const factors = res.factors || {};
    if (byId("factor-sev")) byId("factor-sev").style.width = `${Math.min(100, (factors.severity_weight || 0) * 4)}%`;
    if (byId("factor-pat")) byId("factor-pat").style.width = `${Math.min(100, (factors.suspicious_patterns || 0) * 4)}%`;
    if (byId("factor-cor")) byId("factor-cor").style.width = `${Math.min(100, (factors.cross_source_corroboration || 0) * 4)}%`;
    if (byId("factor-prv")) byId("factor-prv").style.width = `${Math.min(100, (factors.privilege_persistence_indicators || 0) * 4)}%`;
    if (byId("factor-seq")) byId("factor-seq").style.width = `${Math.min(100, (factors.sequence_support || 0) * 4)}%`;
  } catch (err) {
    console.warn("Could not load risk score", err);
  }
}

async function loadCorrelationGraph() {
  try {
    const data = await apiGet("/api/v1/investigation/correlation-graph?max_nodes=12");
    if (data) {
      renderCorrelationGraphSvg(data.nodes || [], data.edges || []);
    }
  } catch (err) {
    console.warn("Could not load correlation graph", err);
  }
}

function renderCorrelationGraphSvg(nodes, edges) {
  const svg = byId("correlation-graph-svg");
  if (!svg) return;
  svg.replaceChildren();

  if (!nodes || nodes.length === 0) {
    const txt = document.createElementNS("http://www.w3.org/2000/svg", "text");
    txt.setAttribute("x", "325");
    txt.setAttribute("y", "100");
    txt.setAttribute("text-anchor", "middle");
    txt.setAttribute("fill", "#6f7d8c");
    txt.setAttribute("font-size", "13");
    txt.textContent = "No correlated entities observed yet. Run dataset replay or event analysis.";
    svg.append(txt);
    return;
  }

  const cx = 325;
  const cy = 100;
  const r = 70;
  const positions = {};

  nodes.forEach((node, i) => {
    const angle = (2 * Math.PI / nodes.length) * i;
    const nx = cx + r * Math.cos(angle) * 1.8;
    const ny = cy + r * Math.sin(angle) * 0.9;
    positions[node.id] = { x: nx, y: ny, data: node };
  });

  // Render edges
  edges.forEach((edge) => {
    const p1 = positions[edge.source];
    const p2 = positions[edge.target];
    if (p1 && p2) {
      const line = document.createElementNS("http://www.w3.org/2000/svg", "line");
      line.setAttribute("x1", p1.x);
      line.setAttribute("y1", p1.y);
      line.setAttribute("x2", p2.x);
      line.setAttribute("y2", p2.y);
      line.setAttribute("stroke", "#2b3b4c");
      line.setAttribute("stroke-width", "1.5");
      svg.append(line);
    }
  });

  // Render nodes
  Object.values(positions).forEach(({ x, y, data }) => {
    const g = document.createElementNS("http://www.w3.org/2000/svg", "g");
    g.style.cursor = "pointer";

    let color = "#83b8e7";
    if (data.type === "host") color = "#72c9a2";
    else if (data.type === "user") color = "#e1bd72";
    else if (data.type === "ip") color = "#ed8b91";

    const circle = document.createElementNS("http://www.w3.org/2000/svg", "circle");
    circle.setAttribute("cx", x);
    circle.setAttribute("cy", y);
    circle.setAttribute("r", "16");
    circle.setAttribute("fill", "#141c25");
    circle.setAttribute("stroke", color);
    circle.setAttribute("stroke-width", "2");

    const text = document.createElementNS("http://www.w3.org/2000/svg", "text");
    text.setAttribute("x", x);
    text.setAttribute("y", y + 4);
    text.setAttribute("text-anchor", "middle");
    text.setAttribute("fill", "#f0f4f8");
    text.setAttribute("font-size", "9");
    text.setAttribute("font-family", "monospace");
    text.textContent = (data.label || data.id).slice(0, 4);

    g.append(circle, text);

    g.addEventListener("click", () => {
      const detail = byId("correlation-node-detail");
      if (detail) {
        detail.hidden = false;
        detail.innerHTML = `<strong>Entity:</strong> ${data.label || data.id} &nbsp;|&nbsp; <strong>Type:</strong> ${data.type} &nbsp;|&nbsp; <strong>Event Count:</strong> ${data.event_count || 1}`;
      }
    });

    svg.append(g);
  });
}

if (byId("risk-refresh-btn")) byId("risk-refresh-btn").addEventListener("click", loadInvestigationRisk);
if (byId("correlation-refresh-btn")) byId("correlation-refresh-btn").addEventListener("click", loadCorrelationGraph);
