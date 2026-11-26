// Aegis-MCP load test: 500 rps open-model load against the firewall endpoints
// with a p99 < 10 ms SLO on http_req_duration.
//
//   uv run python benchmarks/mock_upstream.py --port 9100 &
//   AEGIS_MCP_UPSTREAMS='{"bench-mcp":"http://127.0.0.1:9100/mcp"}' \
//     uv run uvicorn app.main:app --port 8000 &
//   k6 run benchmarks/load_k6.js            # or: make load
//
// Environment overrides: BASE_URL (default http://127.0.0.1:8000),
// RATE (total requests/s, default 500), DURATION (default 60s),
// P99_MS (SLO, default 10), API_KEY (sent as X-API-Key when set).

import http from "k6/http";
import { check } from "k6";

const BASE_URL = __ENV.BASE_URL || "http://127.0.0.1:8000";
const RATE = parseInt(__ENV.RATE || "500", 10);
const DURATION = __ENV.DURATION || "60s";
const P99_MS = parseFloat(__ENV.P99_MS || "10");
const SERVER = "bench-mcp";

// Split the total rate evenly across the two endpoints.
const PER_ENDPOINT = Math.max(1, Math.floor(RATE / 2));

function arrival(exec) {
  return {
    executor: "constant-arrival-rate",
    exec,
    rate: PER_ENDPOINT,
    timeUnit: "1s",
    duration: DURATION,
    preAllocatedVUs: 50,
    maxVUs: 400,
  };
}

export const options = {
  scenarios: {
    inspect: arrival("inspect"),
    jsonrpc: arrival("jsonrpc"),
  },
  thresholds: {
    http_req_duration: [`p(99)<${P99_MS}`],
    "http_req_duration{endpoint:inspect}": [`p(99)<${P99_MS}`],
    "http_req_duration{endpoint:jsonrpc}": [`p(99)<${P99_MS}`],
    http_req_failed: ["rate<0.01"],
    checks: ["rate>0.99"],
  },
  summaryTrendStats: ["avg", "med", "p(95)", "p(99)", "max"],
};

const HEADERS = Object.assign(
  {
    "Content-Type": "application/json",
    "X-Aegis-Agent-Id": "k6-load",
    "X-Aegis-MCP-Server": SERVER,
  },
  __ENV.API_KEY ? { "X-API-Key": __ENV.API_KEY } : {},
);

const ARGUMENTS = {
  path: "docs/architecture.md",
  encoding: "utf-8",
  max_bytes: 65536,
};

const INSPECT_BODY = JSON.stringify({
  agent_id: "k6-load",
  server_name: SERVER,
  tool_name: "read_file",
  arguments: ARGUMENTS,
});

export function inspect() {
  const res = http.post(`${BASE_URL}/api/v1/mcp/inspect`, INSPECT_BODY, {
    headers: HEADERS,
    tags: { endpoint: "inspect" },
  });
  check(res, {
    "inspect 200": (r) => r.status === 200,
    "inspect allowed": (r) => r.json("decision") === "ALLOWED",
  });
}

export function jsonrpc() {
  const body = JSON.stringify({
    jsonrpc: "2.0",
    id: __ITER,
    method: "tools/call",
    params: { name: "read_file", arguments: ARGUMENTS },
  });
  const res = http.post(`${BASE_URL}/api/v1/mcp/jsonrpc`, body, {
    headers: HEADERS,
    tags: { endpoint: "jsonrpc" },
  });
  check(res, {
    "jsonrpc 200": (r) => r.status === 200,
    "jsonrpc result": (r) => {
      const reply = r.json();
      return reply.result !== undefined && reply.error === undefined;
    },
  });
}
