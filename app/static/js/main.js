// Cockpit bootstrap: wires controls, polls read-only endpoints and dispatches
// operator actions. No inline handlers: every listener is attached here.

import { ApiError, clearApiKey, endpoints, getApiKey, setApiKey } from "./api.js";
import { verifyInclusionProof } from "./merkle.js";
import {
  renderApprovals,
  renderChainVerdict,
  renderCheckpoints,
  renderLedger,
  renderLocked,
  renderMessageVerdict,
  renderPins,
  renderProofVerdict,
  renderSummary,
  summaryDetail,
} from "./panels.js";

const REFRESH_MS = 10000;
const byId = (id) => document.getElementById(id);

const state = { pins: [], timer: null, busy: false };

function notify(message, tone = "warn") {
  const notice = byId("notice");
  if (!message) {
    notice.hidden = true;
    notice.textContent = "";
    return;
  }
  notice.hidden = false;
  notice.dataset.tone = tone;
  notice.textContent = message;
}

function describe(error) {
  if (error instanceof ApiError) {
    if (error.status === 401) {
      return "Authentication required: enter a valid X-API-Key for this session.";
    }
    if (error.status === 403) {
      return `Forbidden: ${error.message}`;
    }
    return `Request failed (${error.status}): ${error.message}`;
  }
  return `Network error: ${error.message}`;
}

function syncKeyStatus() {
  const hasKey = getApiKey() !== "";
  byId("key-status").textContent = hasKey
    ? "Key held in sessionStorage for this tab only."
    : "No key in this session.";
}

async function loadReadOnly() {
  const [summary, entries, checkpoints] = await Promise.all([
    endpoints.summary(),
    endpoints.entries(50),
    endpoints.checkpoints(),
  ]);
  renderSummary(byId("kpi-strip"), summary);
  byId("kpi-detail").textContent = summaryDetail(summary);
  renderLedger(byId("ledger-body"), entries);
  renderCheckpoints(byId("checkpoints"), checkpoints);
  return summary;
}

function adminLockedMessage(summary, error) {
  if (!summary.api_key_required && summary.auth_mode === "api_key") {
    return "Disabled: set AEGIS_API_KEY on the gateway to enable administration.";
  }
  if (error instanceof ApiError && (error.status === 401 || error.status === 403)) {
    return "Requires the admin X-API-Key";
  }
  return describe(error);
}

async function loadAdmin(summary) {
  const canAct = getApiKey() !== "";
  const [pins, approvals] = await Promise.allSettled([endpoints.pins(), endpoints.approvals(50)]);
  if (pins.status === "fulfilled") {
    state.pins = pins.value;
    renderPins(byId("toolguard-body"), state.pins, canAct);
  } else {
    state.pins = [];
    renderLocked(byId("toolguard-body"), adminLockedMessage(summary, pins.reason), true, 5);
  }
  if (approvals.status === "fulfilled") {
    renderApprovals(byId("approvals"), approvals.value);
  } else {
    renderLocked(byId("approvals"), adminLockedMessage(summary, approvals.reason), false);
  }
}

async function refresh() {
  if (state.busy) {
    return;
  }
  state.busy = true;
  try {
    const summary = await loadReadOnly();
    await loadAdmin(summary);
    notify("");
    byId("updated-at").textContent = `Updated ${new Date().toISOString().slice(11, 19)} UTC`;
  } catch (error) {
    notify(describe(error), "error");
  } finally {
    state.busy = false;
  }
}

function schedule() {
  window.clearInterval(state.timer);
  state.timer = byId("auto-refresh").checked ? window.setInterval(refresh, REFRESH_MS) : null;
}

async function verifyChain(button) {
  button.disabled = true;
  try {
    renderChainVerdict(byId("chain-result"), await endpoints.verify());
  } catch (error) {
    renderMessageVerdict(byId("chain-result"), describe(error));
  } finally {
    button.disabled = false;
  }
}

async function checkProof(entryId) {
  const target = byId("proof-result");
  renderMessageVerdict(target, `Fetching inclusion proof for entry ${entryId}`, "");
  let proof;
  try {
    proof = await endpoints.proof(entryId);
  } catch (error) {
    renderMessageVerdict(target, describe(error));
    return;
  }
  let local;
  try {
    local = await verifyInclusionProof(proof);
  } catch (error) {
    local = { valid: false, computedRoot: "", error: error.message };
  }
  renderProofVerdict(target, proof, local);
}

async function approvePin(button) {
  const pin = state.pins[Number(button.dataset.pinIndex)];
  if (!pin) {
    return;
  }
  button.disabled = true;
  try {
    await endpoints.approvePin(pin, button.dataset.fingerprint);
    notify(`Approved ${pin.kind} ${pin.name} on ${pin.server_name}.`, "ok");
    await refresh();
  } catch (error) {
    notify(describe(error), "error");
    button.disabled = false;
  }
}

async function resolveApproval(button) {
  const { approvalId, status } = button.dataset;
  button.disabled = true;
  try {
    await endpoints.resolveApproval(approvalId, status, `cockpit operator ${status}`);
    notify(`Approval ${approvalId.slice(0, 8)} ${status}.`, "ok");
    await refresh();
  } catch (error) {
    notify(describe(error), "error");
    button.disabled = false;
  }
}

const ACTIONS = {
  prove: (button) => {
    byId("proof-id").value = button.dataset.entryId;
    return checkProof(button.dataset.entryId);
  },
  "approve-pin": approvePin,
  resolve: resolveApproval,
};

function onAction(event) {
  const button = event.target.closest("button[data-action]");
  if (!button || button.disabled) {
    return;
  }
  const handler = ACTIONS[button.dataset.action];
  if (handler) {
    handler(button);
  }
}

function bind() {
  byId("key-form").addEventListener("submit", (event) => {
    event.preventDefault();
    const input = byId("api-key");
    setApiKey(input.value);
    input.value = "";
    syncKeyStatus();
    refresh();
  });
  byId("key-clear").addEventListener("click", () => {
    clearApiKey();
    syncKeyStatus();
    refresh();
  });
  byId("refresh").addEventListener("click", refresh);
  byId("auto-refresh").addEventListener("change", schedule);
  byId("verify-chain").addEventListener("click", (event) => verifyChain(event.currentTarget));
  byId("proof-form").addEventListener("submit", (event) => {
    event.preventDefault();
    const value = Number.parseInt(byId("proof-id").value, 10);
    if (Number.isInteger(value) && value > 0) {
      checkProof(value);
    }
  });
  document.querySelector(".layout").addEventListener("click", onAction);
}

function start() {
  bind();
  syncKeyStatus();
  refresh();
  schedule();
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", start, { once: true });
} else {
  start();
}
