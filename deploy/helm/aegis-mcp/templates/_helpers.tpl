{{/*
Chart name, truncated to the 63-char DNS label limit.
*/}}
{{- define "aegis-mcp.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Fully qualified app name.
*/}}
{{- define "aegis-mcp.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{- define "aegis-mcp.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "aegis-mcp.selectorLabels" -}}
app.kubernetes.io/name: {{ include "aegis-mcp.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "aegis-mcp.labels" -}}
helm.sh/chart: {{ include "aegis-mcp.chart" . }}
{{ include "aegis-mcp.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: aegis-mcp
app.kubernetes.io/component: security-gateway
{{- end }}

{{- define "aegis-mcp.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "aegis-mcp.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Image reference: an immutable digest wins over the tag.
*/}}
{{- define "aegis-mcp.image" -}}
{{- if .Values.image.digest }}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest }}
{{- else }}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) }}
{{- end }}
{{- end }}

{{/*
Fail-closed render-time guards.
*/}}
{{- define "aegis-mcp.validate" -}}
{{- if ne (int .Values.replicaCount) 1 }}
{{- fail "replicaCount must be 1: multiple SQLite ledger writers would fork the audit hash chain (wait for [persistence/postgres-ledger])" }}
{{- end }}
{{- if and (eq .Values.config.environment "prod") .Values.config.checkpointSigning (not .Values.signingKey.existingSecret) }}
{{- fail "signingKey.existingSecret is required when config.environment=prod and config.checkpointSigning=true (prod fails closed without an Ed25519 signing key)" }}
{{- end }}
{{- end }}
