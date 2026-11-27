// Pure renderers: API payload in, DOM nodes out. Actions are expressed as
// data-action attributes and handled by delegated listeners in main.js.

import {
  badge,
  el,
  emptyItem,
  emptyRow,
  facts,
  formatCount,
  formatTime,
  replaceChildren,
  riskLevel,
  shortHash,
} from "./dom.js";

export function renderSummary(root, summary) {
  const decisions = summary.decisions || {};
  const values = {
    requests: formatCount(summary.requests_total),
    allowed: formatCount(decisions.ALLOWED),
    sanitized: formatCount(decisions.SANITIZED),
    blocked: formatCount(decisions.BLOCKED),
    redactions: formatCount(summary.redactions_total),
    mode: summary.policy_mode,
    anomalies: formatCount(summary.rate_anomalies_total),
    entries: formatCount(summary.ledger_entries),
  };
  for (const [name, value] of Object.entries(values)) {
    const node = root.querySelector(`[data-kpi="${name}"]`);
    if (node) {
      node.textContent = value;
    }
  }
  const mode = root.querySelector('[data-kpi="mode"]');
  if (mode) {
    mode.dataset.tone = summary.fail_closed ? "alert" : summary.policy_mode;
  }
  const anomalies = root.querySelector('[data-kpi="anomalies"]');
  if (anomalies) {
    anomalies.dataset.tone = summary.rate_anomalies_total > 0 ? "alert" : "";
  }
}

export function summaryDetail(summary) {
  const parts = [
    `env ${summary.environment}`,
    `policy ${shortHash(summary.policy_version, 10)}`,
    `auth ${summary.auth_mode}`,
    `rate limiting ${summary.rate_limit_enabled ? "on" : "off"}`,
    `shadow would-block ${formatCount(summary.shadow_would_block)}`,
  ];
  if (summary.fail_closed) {
    parts.unshift("FAIL-CLOSED deny-all fallback active");
  }
  const categories = Object.entries(summary.redactions || {});
  if (categories.length) {
    parts.push(`DLP ${categories.map(([name, count]) => `${name}=${count}`).join(" ")}`);
  }
  return parts.join("  /  ");
}

function tags(values) {
  if (!values || values.length === 0) {
    return el("span", { className: "muted", text: "none" });
  }
  return el("div", {}, values.map((value) => el("span", { className: "tag", text: value })));
}

function ledgerRow(entry) {
  return el("tr", {}, [
    el("td", { className: "mono", text: entry.id }),
    el("td", { className: "mono", text: formatTime(entry.timestamp) }),
    el("td", {}, [
      el("div", { className: "stack" }, [
        el("strong", { text: entry.tool_name }),
        el("span", { className: "muted", text: `${entry.agent_id} @ ${entry.server_name}` }),
      ]),
    ]),
    el("td", {}, [
      el("div", { className: "stack" }, [
        badge(entry.decision),
        entry.would_block && entry.decision !== "BLOCKED" ? badge("would block", "monitor") : null,
      ]),
    ]),
    el("td", { className: "num" }, [
      el("span", {
        className: "risk",
        text: entry.risk_score,
        dataset: { level: riskLevel(entry.risk_score) },
      }),
    ]),
    el("td", {}, [tags([...(entry.violations || []), ...(entry.redacted_categories || []).map((c) => `dlp:${c}`)])]),
    el("td", {}, [
      el("div", { className: "stack mono" }, [
        el("span", { text: entry.session_id ? shortHash(entry.session_id, 14) : "no session" }),
        el("span", {
          className: "muted",
          text: `${entry.policy_mode} ${shortHash(entry.policy_version, 8)}`,
        }),
      ]),
    ]),
    el("td", {}, [
      el("button", {
        className: "btn btn--small",
        text: "Prove",
        attrs: { type: "button", "aria-label": `Check Merkle proof of entry ${entry.id}` },
        dataset: { action: "prove", entryId: entry.id },
      }),
    ]),
  ]);
}

export function renderLedger(body, entries) {
  if (!entries.length) {
    replaceChildren(body, [emptyRow(8, "The ledger is empty. No MCP tool call has been inspected yet.")]);
    return;
  }
  replaceChildren(body, entries.map(ledgerRow));
}

export function renderChainVerdict(root, result) {
  root.dataset.tone = result.valid ? "ok" : "fail";
  const title = result.valid
    ? "Chain intact"
    : `Tampering detected at entry ${result.corrupted_entry_id}`;
  replaceChildren(root, [
    el("p", { className: "verdict__title", text: title }),
    facts([
      ["Entries verified", formatCount(result.total_entries)],
      ["Legacy (v1) links", formatCount(result.legacy_entries)],
      ["Head hash", result.head_hash || "-", true],
    ]),
  ]);
}

export function renderProofVerdict(root, proof, local) {
  const serverOk = Boolean(proof.root_hash);
  const ok = local.valid && serverOk;
  root.hidden = false;
  root.dataset.tone = ok ? "ok" : "fail";
  const checkpoint = proof.checkpoint;
  replaceChildren(root, [
    el("p", {
      className: "verdict__title",
      text: ok
        ? `Entry ${proof.entry_id} is included in the Merkle tree`
        : `Entry ${proof.entry_id} inclusion proof did not verify`,
    }),
    facts([
      ["Leaf index", `${proof.leaf_index} of ${proof.tree_size}`],
      ["Audit path", `${(proof.audit_path || []).length} sibling hashes`],
      ["Server root", proof.root_hash, true],
      ["Recomputed root", local.computedRoot || local.error || "-", true],
      [
        "Signed tree head",
        checkpoint
          ? `Ed25519 ${shortHash(checkpoint.key_fingerprint, 16)} at ${formatTime(checkpoint.timestamp)}`
          : "unsigned (no checkpoint key configured)",
      ],
    ]),
  ]);
}

export function renderMessageVerdict(root, title, tone = "fail") {
  root.hidden = false;
  root.dataset.tone = tone;
  replaceChildren(root, [el("p", { className: "verdict__title", text: title })]);
}

export function renderCheckpoints(list, checkpoints) {
  if (!checkpoints.length) {
    replaceChildren(list, [emptyItem("No signed tree heads yet.")]);
    return;
  }
  const newest = [...checkpoints].reverse().slice(0, 8);
  replaceChildren(
    list,
    newest.map((item) =>
      el("li", { className: "checkpoint" }, [
        facts([
          ["Tree size", formatCount(item.tree_size)],
          ["Signed", formatTime(item.timestamp)],
          ["Root", item.root_hash, true],
          ["Key", shortHash(item.key_fingerprint, 16), true],
        ]),
      ]),
    ),
  );
}

export function pinState(pin) {
  if (pin.drift_fingerprint) {
    return "drifted";
  }
  return pin.status;
}

function pinRow(pin, index, canAct) {
  const state = pinState(pin);
  const target = state === "drifted" ? pin.drift_fingerprint : pin.fingerprint;
  const action =
    state === "approved"
      ? el("span", { className: "muted", text: "trusted" })
      : el("button", {
          className: "btn btn--small btn--approve",
          text: state === "drifted" ? "Approve drift" : "Approve",
          attrs: canAct ? { type: "button" } : { type: "button", disabled: "" },
          dataset: { action: "approve-pin", pinIndex: index, fingerprint: target },
        });
  return el("tr", {}, [
    el("td", { text: pin.server_name }),
    el("td", {}, [
      el("div", { className: "stack" }, [
        el("strong", { text: pin.name }),
        el("span", { className: "muted", text: pin.kind }),
      ]),
    ]),
    el("td", {}, [badge(state)]),
    el("td", {}, [
      el("div", { className: "stack mono" }, [
        el("span", { text: shortHash(pin.fingerprint, 16) }),
        pin.drift_fingerprint
          ? el("span", { className: "muted", text: `now ${shortHash(pin.drift_fingerprint, 16)}` })
          : null,
      ]),
    ]),
    el("td", {}, [action]),
  ]);
}

export function renderPins(body, pins, canAct) {
  if (!pins.length) {
    replaceChildren(body, [emptyRow(5, "No MCP definitions pinned yet.")]);
    return;
  }
  replaceChildren(body, pins.map((pin, index) => pinRow(pin, index, canAct)));
}

function approvalItem(item) {
  const pending = item.status === "pending";
  const children = [
    el("div", { className: "approval__head" }, [
      el("p", { className: "approval__tool", text: `${item.tool_name} on ${item.server_name}` }),
      badge(item.status),
    ]),
    el("p", {
      className: "muted mono",
      text: `${item.agent_id} / ${item.environment} / requested ${formatTime(item.created_at)} / expires ${formatTime(item.expires_at)}`,
    }),
    el("pre", {
      className: "approval__args",
      text: JSON.stringify(item.sanitized_arguments || {}, null, 2),
    }),
  ];
  if (pending) {
    children.push(
      el("div", { className: "approval__actions" }, [
        el("button", {
          className: "btn btn--small btn--approve",
          text: "Approve",
          attrs: { type: "button" },
          dataset: { action: "resolve", approvalId: item.id, status: "approved" },
        }),
        el("button", {
          className: "btn btn--small btn--deny",
          text: "Deny",
          attrs: { type: "button" },
          dataset: { action: "resolve", approvalId: item.id, status: "denied" },
        }),
      ]),
    );
  } else if (item.resolved_by) {
    children.push(
      el("p", {
        className: "muted",
        text: `Resolved by ${item.resolved_by} at ${formatTime(item.resolved_at)}${item.reason ? `: ${item.reason}` : ""}`,
      }),
    );
  }
  return el("li", { className: "approval" }, children);
}

export function renderApprovals(list, approvals) {
  if (!approvals.length) {
    replaceChildren(list, [emptyItem("No approval requests.")]);
    return;
  }
  const ordered = [...approvals].sort(
    (a, b) => Number(b.status === "pending") - Number(a.status === "pending"),
  );
  replaceChildren(list, ordered.map(approvalItem));
}

export function renderLocked(target, message, isTable, colspan = 1) {
  replaceChildren(target, [isTable ? emptyRow(colspan, message) : emptyItem(message)]);
}
