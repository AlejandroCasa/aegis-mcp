# Aegis-MCP performance targets (see README "Latency Budget & Load Testing").

ITERATIONS ?= 500
WARMUP ?= 50
MAX_P99_MS ?= 10.0
RATE ?= 500
DURATION ?= 60s
BASE_URL ?= http://127.0.0.1:8000

.PHONY: bench bench-gate load

## Reproducible latency benchmark (inspect + ASGI), JSON + Markdown summary
bench:
	uv run python -m scripts.benchmark_latency --iterations ${ITERATIONS} \
		--warmup ${WARMUP} --max-p99-ms ${MAX_P99_MS}

## CI p99 regression gate (exits 1 if MCPFirewall.inspect p99 > budget)
bench-gate:
	uv run python -m scripts.benchmark_latency --iterations 300 \
		--max-p99-ms ${MAX_P99_MS} --fail-on-regression

## k6 load test against a running gateway (start mock upstream + uvicorn first)
load:
	k6 run -e BASE_URL=${BASE_URL} -e RATE=${RATE} -e DURATION=${DURATION} \
		-e P99_MS=${MAX_P99_MS} benchmarks/load_k6.js
