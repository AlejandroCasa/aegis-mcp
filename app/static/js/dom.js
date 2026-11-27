// Minimal DOM helpers. Text is always assigned via textContent (never parsed as
// HTML), so ledger data (agent ids, tool names, violations) cannot inject markup.

export function el(tag, options = {}, children = []) {
  const node = document.createElement(tag);
  const { className, text, attrs, dataset } = options;
  if (className) {
    node.className = className;
  }
  if (text !== undefined && text !== null) {
    node.textContent = String(text);
  }
  for (const [name, value] of Object.entries(attrs || {})) {
    node.setAttribute(name, String(value));
  }
  for (const [name, value] of Object.entries(dataset || {})) {
    node.dataset[name] = String(value);
  }
  for (const child of children) {
    if (child !== null && child !== undefined) {
      node.append(child);
    }
  }
  return node;
}

export function replaceChildren(parent, children) {
  parent.replaceChildren(...children);
}

export function emptyRow(colspan, message) {
  return el("tr", {}, [el("td", { className: "empty", text: message, attrs: { colspan } })]);
}

export function emptyItem(message) {
  return el("li", { className: "empty", text: message });
}

export function badge(label, variant) {
  const tone = String(variant || label).toLowerCase();
  return el("span", { className: `badge badge--${tone}`, text: label });
}

export function shortHash(value, size = 12) {
  const text = String(value || "");
  return text.length > size ? `${text.slice(0, size)}...` : text || "-";
}

export function formatTime(iso) {
  if (!iso) {
    return "-";
  }
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) {
    return String(iso);
  }
  return date.toISOString().replace("T", " ").slice(0, 19);
}

export function formatCount(value) {
  return Number(value || 0).toLocaleString("en-US");
}

export function riskLevel(score) {
  if (score >= 70) {
    return "high";
  }
  return score >= 40 ? "medium" : "low";
}

export function facts(pairs) {
  const list = el("dl", { className: "facts" });
  for (const [term, value, mono] of pairs) {
    list.append(el("dt", { text: term }), el("dd", { className: mono ? "mono" : "", text: value }));
  }
  return list;
}
