const scenarios = JSON.parse(document.getElementById("scenario-data").textContent);
const defaultRuntimeConfig = JSON.parse(document.getElementById("runtime-config-data").textContent);
const initialConnectors = JSON.parse(document.getElementById("mcp-connectors-data").textContent);

const scenarioGrid = document.getElementById("scenario-grid");
const resultsGrid = document.getElementById("results-grid");
const resultsStatus = document.getElementById("results-status");
const modeSelect = document.getElementById("mode");
const runButton = document.getElementById("run-selected");
const resetInputsButton = document.getElementById("reset-inputs");
const enableDualInput = document.getElementById("enable-dual");
const maxRoundsInput = document.getElementById("max-rounds");
const flowRail = document.getElementById("flow-rail");
const flowQLabel = document.getElementById("flow-q-label");
const flowQModel = document.getElementById("flow-q-model");
const flowPLabel = document.getElementById("flow-p-label");
const flowPModel = document.getElementById("flow-p-model");

const qLabelInput = document.getElementById("q-label");
const qModelInput = document.getElementById("q-model");
const qPromptInput = document.getElementById("q-prompt");
const pLabelInput = document.getElementById("p-label");
const pModelInput = document.getElementById("p-model");
const pPromptInput = document.getElementById("p-prompt");
const baselinePromptInput = document.getElementById("baseline-prompt");

const emailFromInput = document.getElementById("email-from");
const emailSubjectInput = document.getElementById("email-subject");
const emailBodyInput = document.getElementById("email-body");
const externalLabelInput = document.getElementById("external-label");
const externalRefInput = document.getElementById("external-ref");
const externalDataInput = document.getElementById("external-data");
const businessGoalInput = document.getElementById("business-goal");

const connectorPresetInput = document.getElementById("connector-preset");
const connectorNameInput = document.getElementById("connector-name");
const connectorUrlInput = document.getElementById("connector-url");
const connectorAuthModeInput = document.getElementById("connector-auth-mode");
const connectorTokenWrap = document.getElementById("connector-token-wrap");
const connectorTokenInput = document.getElementById("connector-token");
const connectorSaveButton = document.getElementById("connector-save");
const connectorRefreshButton = document.getElementById("connector-refresh");
const connectorOAuthButton = document.getElementById("connector-oauth");
const connectorDeleteButton = document.getElementById("connector-delete");
const connectorList = document.getElementById("connector-list");
const connectorStatus = document.getElementById("connector-status");
const resourceList = document.getElementById("resource-list");
const toolList = document.getElementById("tool-list");
const resourceImportButton = document.getElementById("resource-import");
const toolImportButton = document.getElementById("tool-import");
const toolArgsInput = document.getElementById("tool-args");

let selectedScenarioId = scenarios[0]?.id;
let connectors = initialConnectors;
let selectedConnectorId = connectors[0]?.id || null;
let selectedResourceUri = null;
let selectedToolName = null;
let connectorSnapshot = null;

const presets = {
  custom: {
    name: "",
    url: "",
    authMode: "oauth",
  },
  notion: {
    name: "Notion MCP",
    url: "https://mcp.notion.com/mcp",
    authMode: "oauth",
  },
  gmail: {
    name: "Gmail MCP",
    url: "",
    authMode: "oauth",
  },
};

const urlParams = new URLSearchParams(window.location.search);
const connectedConnectorId = urlParams.get("mcp_connected");
if (connectedConnectorId) {
  selectedConnectorId = connectedConnectorId;
}

function pretty(value) {
  return typeof value === "string" ? value : JSON.stringify(value, null, 2);
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function verdictClass(status) {
  return status === "needs_human" ? "needs-human" : status;
}

function getSelectedScenario() {
  return scenarios.find((scenario) => scenario.id === selectedScenarioId) || scenarios[0];
}

function getSelectedConnector() {
  return connectors.find((connector) => connector.id === selectedConnectorId) || null;
}

function populateRuntimeConfig() {
  enableDualInput.checked = defaultRuntimeConfig.enable_dual_analysis;
  maxRoundsInput.value = defaultRuntimeConfig.max_quarantine_rounds;
  qLabelInput.value = defaultRuntimeConfig.quarantined_llm.label;
  qModelInput.value = defaultRuntimeConfig.quarantined_llm.model_name;
  qPromptInput.value = defaultRuntimeConfig.quarantined_llm.prompt;
  pLabelInput.value = defaultRuntimeConfig.privileged_llm.label;
  pModelInput.value = defaultRuntimeConfig.privileged_llm.model_name;
  pPromptInput.value = defaultRuntimeConfig.privileged_llm.prompt;
  baselinePromptInput.value = defaultRuntimeConfig.baseline_prompt;
  syncFlowLabels();
}

function populateInputFieldsFromScenario() {
  const scenario = getSelectedScenario();
  emailFromInput.value = scenario.email_from;
  emailSubjectInput.value = scenario.email_subject;
  emailBodyInput.value = scenario.email_body;
  externalLabelInput.value = "Fetched URL / API endpoint";
  externalRefInput.value = scenario.link_url;
  externalDataInput.value = scenario.web_content;
  businessGoalInput.value = scenario.business_goal;
}

function renderScenarioCards() {
  scenarioGrid.innerHTML = "";
  scenarios.forEach((scenario) => {
    const card = document.createElement("article");
    card.className = "scenario-card";
    if (scenario.id === selectedScenarioId) {
      card.classList.add("is-selected");
    }
    card.innerHTML = `
      <div class="pill">${escapeHtml(scenario.attack_type.replaceAll("_", " "))}</div>
      <h4>${escapeHtml(scenario.title)}</h4>
      <p>${escapeHtml(scenario.description)}</p>
      <small>${escapeHtml(scenario.expected_safe_outcome)}</small>
    `;
    card.addEventListener("click", () => {
      selectedScenarioId = scenario.id;
      renderScenarioCards();
      populateInputFieldsFromScenario();
    });
    scenarioGrid.appendChild(card);
  });
}

function buildRuntimeConfig() {
  return {
    enable_dual_analysis: enableDualInput.checked,
    max_quarantine_rounds: Number.parseInt(maxRoundsInput.value || "1", 10),
    quarantined_llm: {
      label: qLabelInput.value.trim() || "LLM1 Quarantine",
      model_name: qModelInput.value.trim() || "quarantine-replay-model",
      prompt: qPromptInput.value.trim(),
    },
    privileged_llm: {
      label: pLabelInput.value.trim() || "LLM2 Main Agent",
      model_name: pModelInput.value.trim() || "privileged-replay-model",
      prompt: pPromptInput.value.trim(),
    },
    baseline_prompt: baselinePromptInput.value.trim(),
  };
}

function buildInputOverride() {
  return {
    email_from: emailFromInput.value.trim(),
    email_subject: emailSubjectInput.value.trim(),
    email_body: emailBodyInput.value,
    external_source_label: externalLabelInput.value.trim() || "Fetched URL / API endpoint",
    external_source_ref: externalRefInput.value.trim(),
    external_data: externalDataInput.value,
    business_goal: businessGoalInput.value,
  };
}

function syncFlowLabels() {
  flowQLabel.textContent = qLabelInput.value.trim() || "LLM1";
  flowQModel.textContent = qModelInput.value.trim() || "Quarantine scan";
  flowPLabel.textContent = pLabelInput.value.trim() || "LLM2";
  flowPModel.textContent = pModelInput.value.trim() || "Privileged reasoning";
}

function setFlowState(traceMode) {
  flowRail.querySelectorAll(".flow-node").forEach((node) => node.classList.remove("is-active"));
  ["source", "privileged", "policy", "output"].forEach((name) => {
    flowRail.querySelector(`.flow-node.${name}`)?.classList.add("is-active");
  });
  if (traceMode === "dual") {
    flowRail.querySelector(".flow-node.quarantine")?.classList.add("is-active");
  }
}

function setRunningState(isRunning) {
  runButton.disabled = isRunning;
  runButton.textContent = isRunning ? "Analyzing..." : "Analyze current input";
}

function renderRun(trace) {
  const column = document.createElement("section");
  column.className = "trace-column";
  const roleSummary = trace.llm_traces.map((item) => `${item.role}:${item.model_name}`).join(", ");
  column.innerHTML = `
    <header>
      <div>
        <p class="eyebrow">${trace.mode === "baseline" ? "Single-model path" : "Dual-LLM path"}</p>
        <h3>${escapeHtml(trace.scenario_title)}</h3>
        <p>${escapeHtml(trace.final_user_outcome)}</p>
      </div>
      <span class="badge ${verdictClass(trace.policy_verdict.status)}">${trace.policy_verdict.status.replaceAll("_", " ")}</span>
    </header>
    <div class="panel-grid">
      ${trace.trace_panels
        .map(
          (panel) => `
            <article class="panel">
              <h4>${escapeHtml(panel.title)}</h4>
              <pre>${escapeHtml(pretty(panel.content))}</pre>
            </article>
          `,
        )
        .join("")}
    </div>
    <div class="meta-list">
      <div>Configured roles: ${escapeHtml(roleSummary)}</div>
      <div>Latency: ${escapeHtml(trace.llm_traces.map((item) => `${item.role} ${item.latency_ms}ms`).join(" | "))}</div>
      <div>Replay mode: ${trace.llm_traces.every((item) => item.used_replay) ? "yes" : "no"}</div>
      <div>Notes: ${escapeHtml((trace.notes || []).join(" | ") || "none")}</div>
    </div>
  `;
  return column;
}

async function runScenario(mode) {
  const response = await fetch("/api/run", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      scenario_id: selectedScenarioId,
      mode,
      runtime_config: buildRuntimeConfig(),
      input_override: buildInputOverride(),
    }),
  });

  const payload = await response.json();
  if (!response.ok) {
    throw new Error(payload.detail || "Scenario run failed.");
  }
  return payload;
}

function renderConnectorForm() {
  const connector = getSelectedConnector();
  if (!connector) {
    connectorNameInput.value = "";
    connectorUrlInput.value = "";
    connectorAuthModeInput.value = "oauth";
    connectorTokenInput.value = "";
  } else {
    connectorNameInput.value = connector.name || "";
    connectorUrlInput.value = connector.server_url || "";
    connectorAuthModeInput.value = connector.auth_mode || "oauth";
    connectorTokenInput.value = connector.bearer_token || "";
  }
  toggleTokenVisibility();
}

function renderConnectorList() {
  connectorList.innerHTML = "";
  if (!connectors.length) {
    connectorList.innerHTML = `<div class="browser-item"><p>No MCP servers connected yet. Add a hosted or custom connector above.</p></div>`;
    return;
  }
  connectors.forEach((connector) => {
    const item = document.createElement("article");
    item.className = "connector-item";
    if (connector.id === selectedConnectorId) {
      item.classList.add("is-selected");
    }
    const authLabel = connector.auth_mode === "oauth" ? "oauth" : connector.auth_mode === "bearer" ? "bearer" : "open";
    item.innerHTML = `
      <div class="pill">${escapeHtml(authLabel)}</div>
      <h4>${escapeHtml(connector.discovered_name || connector.name)}</h4>
      <p>${escapeHtml(connector.server_url)}</p>
      <small>${escapeHtml(connector.description || "")}</small>
    `;
    item.addEventListener("click", async () => {
      selectedConnectorId = connector.id;
      connectorSnapshot = null;
      selectedResourceUri = null;
      selectedToolName = null;
      renderConnectorList();
      renderConnectorForm();
      await refreshSelectedConnector();
    });
    connectorList.appendChild(item);
  });
}

function renderResources() {
  const resources = connectorSnapshot?.resources || [];
  resourceList.innerHTML = "";
  if (!resources.length) {
    resourceList.innerHTML = `<div class="browser-item"><p>No MCP resources exposed by this server.</p></div>`;
    return;
  }
  resources.forEach((resource) => {
    const item = document.createElement("article");
    item.className = "browser-item";
    if (resource.uri === selectedResourceUri) {
      item.classList.add("is-selected");
    }
    item.innerHTML = `
      <h4>${escapeHtml(resource.title || resource.name)}</h4>
      <p>${escapeHtml(resource.description || resource.uri)}</p>
      <small>${escapeHtml(resource.uri)}</small>
    `;
    item.addEventListener("click", () => {
      selectedResourceUri = resource.uri;
      renderResources();
    });
    resourceList.appendChild(item);
  });
}

function renderTools() {
  const tools = connectorSnapshot?.tools || [];
  toolList.innerHTML = "";
  if (!tools.length) {
    toolList.innerHTML = `<div class="browser-item"><p>No MCP tools exposed by this server.</p></div>`;
    return;
  }
  tools.forEach((tool) => {
    const item = document.createElement("article");
    item.className = "browser-item";
    if (tool.name === selectedToolName) {
      item.classList.add("is-selected");
    }
    item.innerHTML = `
      <h4>${escapeHtml(tool.title || tool.name)}</h4>
      <p>${escapeHtml(tool.description || "No description")}</p>
      <small>${escapeHtml(pretty(tool.input_schema || {}))}</small>
    `;
    item.addEventListener("click", () => {
      selectedToolName = tool.name;
      const schema = tool.input_schema || {};
      if (schema.properties && Object.keys(schema.properties).length > 0) {
        const seed = {};
        Object.keys(schema.properties).forEach((key) => {
          seed[key] = "";
        });
        toolArgsInput.value = JSON.stringify(seed, null, 2);
      } else {
        toolArgsInput.value = "{}";
      }
      renderTools();
    });
    toolList.appendChild(item);
  });
}

function renderConnectorSnapshot() {
  if (!connectorSnapshot) {
    connectorStatus.textContent = "Choose or connect an MCP server to browse live data.";
    resourceList.innerHTML = `<div class="browser-item"><p>No connector snapshot loaded yet.</p></div>`;
    toolList.innerHTML = `<div class="browser-item"><p>No connector snapshot loaded yet.</p></div>`;
    return;
  }
  if (!connectorSnapshot.connected) {
    connectorStatus.textContent = connectorSnapshot.error || "This MCP server needs authentication or could not be reached.";
  } else {
    connectorStatus.textContent = `${connectorSnapshot.server_title || connectorSnapshot.server_name || "Connected"} • protocol ${connectorSnapshot.protocol_version || "unknown"} • ${connectorSnapshot.resources.length} resources • ${connectorSnapshot.tools.length} tools`;
  }
  renderResources();
  renderTools();
}

function toggleTokenVisibility() {
  const show = connectorAuthModeInput.value === "bearer";
  connectorTokenWrap.style.display = show ? "grid" : "none";
}

function applyPreset() {
  const preset = presets[connectorPresetInput.value];
  connectorNameInput.value = preset.name;
  connectorUrlInput.value = preset.url;
  connectorAuthModeInput.value = preset.authMode;
  toggleTokenVisibility();
}

function parseToolArguments() {
  try {
    return JSON.parse(toolArgsInput.value || "{}");
  } catch (error) {
    throw new Error("Tool arguments must be valid JSON.");
  }
}

async function fetchConnectors() {
  const response = await fetch("/api/mcp/connectors");
  connectors = await response.json();
  if (!selectedConnectorId && connectors.length) {
    selectedConnectorId = connectors[0].id;
  }
  renderConnectorList();
  renderConnectorForm();
}

async function saveConnector() {
  const payload = {
    name: connectorNameInput.value.trim() || "Untitled MCP server",
    server_url: connectorUrlInput.value.trim(),
    auth_mode: connectorAuthModeInput.value,
    bearer_token: connectorTokenInput.value.trim() || null,
  };
  if (!payload.server_url) {
    throw new Error("Server URL is required.");
  }
  const current = getSelectedConnector();
  const url = current ? `/api/mcp/connectors/${current.id}` : "/api/mcp/connectors";
  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  const result = await response.json();
  if (!response.ok) {
    throw new Error(result.detail || "Failed to save connector.");
  }
  selectedConnectorId = result.id;
  await fetchConnectors();
  connectorSnapshot = null;
  selectedResourceUri = null;
  selectedToolName = null;
  await refreshSelectedConnector();
}

async function refreshSelectedConnector() {
  const connector = getSelectedConnector();
  if (!connector) {
    renderConnectorSnapshot();
    return;
  }
  connectorStatus.textContent = "Refreshing MCP connector snapshot...";
  const response = await fetch(`/api/mcp/connectors/${connector.id}/snapshot`);
  const snapshot = await response.json();
  if (!response.ok) {
    connectorSnapshot = { connected: false, error: snapshot.detail, resources: [], tools: [] };
    renderConnectorSnapshot();
    return;
  }
  connectorSnapshot = snapshot;
  renderConnectorSnapshot();
}

async function importSelectedResource() {
  const connector = getSelectedConnector();
  if (!connector || !selectedResourceUri) {
    throw new Error("Select a connector resource first.");
  }
  const response = await fetch(`/api/mcp/connectors/${connector.id}/resources/import`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ uri: selectedResourceUri }),
  });
  const payload = await response.json();
  if (!response.ok) {
    throw new Error(payload.detail || "Failed to import resource.");
  }
  emailFromInput.value = payload.email_from;
  emailSubjectInput.value = payload.email_subject;
  emailBodyInput.value = payload.email_body;
  externalLabelInput.value = payload.external_source_label;
  externalRefInput.value = payload.external_source_ref;
  externalDataInput.value = payload.external_data;
  businessGoalInput.value = payload.business_goal;
  resultsStatus.textContent = "Imported MCP resource content into the analysis studio.";
}

async function importSelectedTool() {
  const connector = getSelectedConnector();
  if (!connector || !selectedToolName) {
    throw new Error("Select a connector tool first.");
  }
  const response = await fetch(`/api/mcp/connectors/${connector.id}/tools/${encodeURIComponent(selectedToolName)}/import`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ arguments: parseToolArguments() }),
  });
  const payload = await response.json();
  if (!response.ok) {
    throw new Error(payload.detail || "Failed to import tool result.");
  }
  emailFromInput.value = payload.email_from;
  emailSubjectInput.value = payload.email_subject;
  emailBodyInput.value = payload.email_body;
  externalLabelInput.value = payload.external_source_label;
  externalRefInput.value = payload.external_source_ref;
  externalDataInput.value = payload.external_data;
  businessGoalInput.value = payload.business_goal;
  resultsStatus.textContent = "Imported MCP tool output into the analysis studio.";
}

async function deleteSelectedConnector() {
  const connector = getSelectedConnector();
  if (!connector) {
    return;
  }
  await fetch(`/api/mcp/connectors/${connector.id}`, { method: "DELETE" });
  selectedConnectorId = null;
  connectorSnapshot = null;
  selectedResourceUri = null;
  selectedToolName = null;
  await fetchConnectors();
  renderConnectorSnapshot();
}

async function runSelected() {
  const mode = modeSelect.value;
  resultsGrid.innerHTML = "";
  resultsStatus.textContent = "Running the quarantine and privileged pipeline...";
  setRunningState(true);

  try {
    if (mode === "compare") {
      const [baseline, dual] = await Promise.all([runScenario("baseline"), runScenario("dual")]);
      resultsGrid.appendChild(renderRun(baseline));
      resultsGrid.appendChild(renderRun(dual));
      setFlowState("dual");
      resultsStatus.textContent =
        "Comparison complete. The baseline saw raw content directly, while the dual path inserted a quarantine boundary first.";
      return;
    }

    const trace = await runScenario(mode);
    resultsGrid.appendChild(renderRun(trace));
    setFlowState(trace.mode);
    resultsStatus.textContent =
      trace.mode === "dual"
        ? "LLM1 scanned the imported MCP content first, then handed structured findings to LLM2."
        : "Baseline run complete. The main model saw raw content directly.";
  } catch (error) {
    resultsStatus.textContent = error.message;
  } finally {
    setRunningState(false);
  }
}

populateRuntimeConfig();
renderScenarioCards();
populateInputFieldsFromScenario();
renderConnectorList();
renderConnectorForm();
renderConnectorSnapshot();
if (!getSelectedConnector()) {
  applyPreset();
}

[qLabelInput, qModelInput, pLabelInput, pModelInput].forEach((element) => {
  element.addEventListener("input", syncFlowLabels);
});

connectorPresetInput.addEventListener("change", applyPreset);
connectorAuthModeInput.addEventListener("change", toggleTokenVisibility);
connectorSaveButton.addEventListener("click", async () => {
  try {
    await saveConnector();
    resultsStatus.textContent = "Saved MCP connector configuration.";
  } catch (error) {
    resultsStatus.textContent = error.message;
  }
});
connectorRefreshButton.addEventListener("click", async () => {
  try {
    await refreshSelectedConnector();
  } catch (error) {
    resultsStatus.textContent = error.message;
  }
});
connectorOAuthButton.addEventListener("click", () => {
  const connector = getSelectedConnector();
  if (!connector) {
    resultsStatus.textContent = "Save a connector before starting OAuth.";
    return;
  }
  window.location.href = `/auth/mcp/${connector.id}/start`;
});
connectorDeleteButton.addEventListener("click", async () => {
  try {
    await deleteSelectedConnector();
    resultsStatus.textContent = "Deleted MCP connector.";
  } catch (error) {
    resultsStatus.textContent = error.message;
  }
});
resourceImportButton.addEventListener("click", async () => {
  try {
    await importSelectedResource();
  } catch (error) {
    resultsStatus.textContent = error.message;
  }
});
toolImportButton.addEventListener("click", async () => {
  try {
    await importSelectedTool();
  } catch (error) {
    resultsStatus.textContent = error.message;
  }
});

runButton.addEventListener("click", runSelected);
resetInputsButton.addEventListener("click", populateInputFieldsFromScenario);

if (selectedConnectorId) {
  refreshSelectedConnector();
}
