package main

# -----------------------------------------------------------------------------
# OPA / Rego Governance Policy for the rendered Aegis-MCP Helm chart
#   helm template aegis deploy/helm/aegis-mcp -f <values> | conftest test - \
#     --policy policy/helm.rego
# Pod Security Standards "restricted", single SQLite writer, default-deny
# egress NetworkPolicy. (`import rego.v1` keeps this valid on OPA 0.x and 1.x.)
# -----------------------------------------------------------------------------

import rego.v1

workload_kinds := {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job"}

pod_spec := input.spec.template.spec if input.kind in workload_kinds

name := input.metadata.name

# --- Pod-level PSS restricted -------------------------------------------------

deny contains msg if {
	pod_spec
	not pod_spec.securityContext.runAsNonRoot == true
	msg := sprintf("%v '%v': pod securityContext.runAsNonRoot must be true", [input.kind, name])
}

deny contains msg if {
	pod_spec
	not pod_spec.securityContext.runAsUser == 10001
	msg := sprintf("%v '%v': pod securityContext.runAsUser must be 10001", [input.kind, name])
}

deny contains msg if {
	pod_spec
	not pod_spec.securityContext.seccompProfile.type == "RuntimeDefault"
	msg := sprintf("%v '%v': pod seccompProfile.type must be RuntimeDefault", [input.kind, name])
}

deny contains msg if {
	pod_spec
	not pod_spec.automountServiceAccountToken == false
	msg := sprintf("%v '%v': automountServiceAccountToken must be false", [input.kind, name])
}

deny contains msg if {
	pod_spec.hostNetwork == true
	msg := sprintf("%v '%v': hostNetwork is forbidden", [input.kind, name])
}

deny contains msg if {
	pod_spec.hostPID == true
	msg := sprintf("%v '%v': hostPID is forbidden", [input.kind, name])
}

deny contains msg if {
	some volume in pod_spec.volumes
	volume.hostPath
	msg := sprintf("%v '%v': hostPath volume '%v' is forbidden", [input.kind, name, volume.name])
}

# --- Container-level PSS restricted -------------------------------------------

deny contains msg if {
	some c in pod_spec.containers
	not c.securityContext.allowPrivilegeEscalation == false
	msg := sprintf("%v '%v' container '%v': allowPrivilegeEscalation must be false", [input.kind, name, c.name])
}

deny contains msg if {
	some c in pod_spec.containers
	not c.securityContext.readOnlyRootFilesystem == true
	msg := sprintf("%v '%v' container '%v': readOnlyRootFilesystem must be true", [input.kind, name, c.name])
}

deny contains msg if {
	some c in pod_spec.containers
	not "ALL" in c.securityContext.capabilities.drop
	msg := sprintf("%v '%v' container '%v': capabilities.drop must contain ALL", [input.kind, name, c.name])
}

deny contains msg if {
	some c in pod_spec.containers
	count(object.get(c.securityContext, ["capabilities", "add"], [])) > 0
	msg := sprintf("%v '%v' container '%v': adding capabilities is forbidden", [input.kind, name, c.name])
}

deny contains msg if {
	some c in pod_spec.containers
	c.securityContext.privileged == true
	msg := sprintf("%v '%v' container '%v': privileged is forbidden", [input.kind, name, c.name])
}

deny contains msg if {
	some c in pod_spec.containers
	not c.resources.limits.memory
	msg := sprintf("%v '%v' container '%v': resources.limits.memory is required", [input.kind, name, c.name])
}

deny contains msg if {
	some c in pod_spec.containers
	endswith(c.image, ":latest")
	msg := sprintf("%v '%v' container '%v': mutable ':latest' image tag is forbidden", [input.kind, name, c.name])
}

deny contains msg if {
	some c in pod_spec.containers
	not c.livenessProbe.httpGet.path == "/healthz"
	msg := sprintf("%v '%v' container '%v': livenessProbe must target /healthz", [input.kind, name, c.name])
}

deny contains msg if {
	some c in pod_spec.containers
	not c.readinessProbe.httpGet.path == "/healthz"
	msg := sprintf("%v '%v' container '%v': readinessProbe must target /healthz", [input.kind, name, c.name])
}

# --- Single SQLite ledger writer ----------------------------------------------

deny contains msg if {
	input.kind == "Deployment"
	msg := sprintf("Deployment '%v': the SQLite audit ledger must run as a StatefulSet", [name])
}

deny contains msg if {
	input.kind == "StatefulSet"
	not input.spec.replicas == 1
	msg := sprintf("StatefulSet '%v': replicas must be exactly 1 (more SQLite writers fork the hash chain)", [name])
}

deny contains msg if {
	input.kind == "StatefulSet"
	count(object.get(input.spec, "volumeClaimTemplates", [])) == 0
	msg := sprintf("StatefulSet '%v': the audit ledger needs a volumeClaimTemplate", [name])
}

deny contains msg if {
	input.kind == "HorizontalPodAutoscaler"
	input.spec.maxReplicas > 1
	msg := sprintf("HorizontalPodAutoscaler '%v': scaling beyond 1 replica forks the SQLite hash chain", [name])
}

# --- ServiceAccount -----------------------------------------------------------

deny contains msg if {
	input.kind == "ServiceAccount"
	not input.automountServiceAccountToken == false
	msg := sprintf("ServiceAccount '%v': automountServiceAccountToken must be false", [name])
}

# --- NetworkPolicy: default-deny egress, ingress only on 8000 -----------------

deny contains msg if {
	input.kind == "NetworkPolicy"
	not "Egress" in input.spec.policyTypes
	msg := sprintf("NetworkPolicy '%v': policyTypes must include Egress (default-deny egress)", [name])
}

deny contains msg if {
	input.kind == "NetworkPolicy"
	not "Ingress" in input.spec.policyTypes
	msg := sprintf("NetworkPolicy '%v': policyTypes must include Ingress", [name])
}

deny contains msg if {
	input.kind == "NetworkPolicy"
	some rule in object.get(input.spec, "ingress", [])
	some port in object.get(rule, "ports", [{"port": "any"}])
	port.port != 8000
	msg := sprintf("NetworkPolicy '%v': ingress is only allowed on port 8000 (found %v)", [name, port.port])
}

deny contains msg if {
	input.kind == "NetworkPolicy"
	some rule in object.get(input.spec, "egress", [])
	count(object.get(rule, "ports", [])) == 0
	msg := sprintf("NetworkPolicy '%v': every egress rule must restrict ports", [name])
}

deny contains msg if {
	input.kind == "NetworkPolicy"
	some rule in object.get(input.spec, "egress", [])
	some peer in object.get(rule, "to", [])
	peer.ipBlock.cidr in {"0.0.0.0/0", "::/0"}
	msg := sprintf("NetworkPolicy '%v': egress to %v is not default-deny", [name, peer.ipBlock.cidr])
}
