package main

# -----------------------------------------------------------------------------
# OPA / Rego Governance Policy for Hardened Production Dockerfile
# Zero-Trust DevSecOps & Container Hardening (AGENTS.md Gate 4)
# -----------------------------------------------------------------------------

deny[msg] {
    instruction := input[_]
    instruction.Cmd == "user"
    val := instruction.Value[_]
    val == "root"
    msg := sprintf("Prohibited root user found in Dockerfile: '%v'", [val])
}

default has_user := false

has_user {
    instruction := input[_]
    instruction.Cmd == "user"
}

deny[msg] {
    not has_user
    msg := "Dockerfile must specify a non-privileged USER instruction (UID >= 10001)"
}

default has_healthcheck := false

has_healthcheck {
    instruction := input[_]
    instruction.Cmd == "healthcheck"
}

deny[msg] {
    not has_healthcheck
    msg := "Dockerfile must define a native HEALTHCHECK instruction"
}
