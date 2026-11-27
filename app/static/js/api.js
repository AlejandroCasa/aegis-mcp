// Same-origin API client. The operator X-API-Key lives only in sessionStorage
// (cleared when the tab closes); it is never hardcoded or persisted durably.

const KEY_SLOT = "aegis.cockpit.apiKey";

export class ApiError extends Error {
  constructor(status, detail) {
    super(detail || `HTTP ${status}`);
    this.name = "ApiError";
    this.status = status;
  }
}

export function getApiKey() {
  try {
    return window.sessionStorage.getItem(KEY_SLOT) || "";
  } catch {
    return "";
  }
}

export function setApiKey(value) {
  const key = String(value || "").trim();
  if (key) {
    window.sessionStorage.setItem(KEY_SLOT, key);
  } else {
    window.sessionStorage.removeItem(KEY_SLOT);
  }
  return key !== "";
}

export function clearApiKey() {
  window.sessionStorage.removeItem(KEY_SLOT);
}

function detailOf(payload) {
  return payload && typeof payload.detail === "string" ? payload.detail : "";
}

export async function apiFetch(path, { method = "GET", body } = {}) {
  const headers = { Accept: "application/json" };
  const key = getApiKey();
  if (key) {
    headers["X-API-Key"] = key;
  }
  const init = { method, headers, credentials: "same-origin", cache: "no-store" };
  if (body !== undefined) {
    headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(body);
  }
  const response = await fetch(path, init);
  const payload = await response.json().catch(() => null);
  if (!response.ok) {
    throw new ApiError(response.status, detailOf(payload));
  }
  return payload;
}

export const endpoints = Object.freeze({
  summary: () => apiFetch("/api/v1/cockpit/summary"),
  entries: (limit = 50) => apiFetch(`/api/v1/audit/entries?limit=${Number(limit)}`),
  verify: () => apiFetch("/api/v1/audit/verify"),
  proof: (id) => apiFetch(`/api/v1/audit/proof/${encodeURIComponent(id)}`),
  checkpoints: () => apiFetch("/api/v1/audit/checkpoints"),
  pins: () => apiFetch("/api/v1/toolguard/pins"),
  approvePin: (pin, fingerprint) =>
    apiFetch("/api/v1/toolguard/approve", {
      method: "POST",
      body: { server_name: pin.server_name, kind: pin.kind, name: pin.name, fingerprint },
    }),
  approvals: (limit = 50) => apiFetch(`/api/v1/approvals?limit=${Number(limit)}`),
  resolveApproval: (id, status, reason) =>
    apiFetch(`/api/v1/approvals/${encodeURIComponent(id)}`, {
      method: "POST",
      body: { status, reason },
    }),
});
