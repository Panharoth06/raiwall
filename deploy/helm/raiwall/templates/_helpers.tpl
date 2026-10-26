{{/* Common name helpers. */}}
{{- define "raiwall.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "raiwall.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "raiwall.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "raiwall.labels" -}}
helm.sh/chart: {{ include "raiwall.chart" . }}
{{ include "raiwall.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "raiwall.selectorLabels" -}}
app.kubernetes.io/name: {{ include "raiwall.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "raiwall.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "raiwall.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "raiwall.image" -}}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) -}}
{{- end -}}

{{/* Name of the Secret injected into the pod. */}}
{{- define "raiwall.secretName" -}}
{{- if .Values.secrets.existingSecret -}}
{{- .Values.secrets.existingSecret -}}
{{- else -}}
{{- printf "%s-secrets" (include "raiwall.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/* PostgreSQL DSN assembled from values. Use an existing Secret for special characters. */}}
{{- define "raiwall.databaseURL" -}}
{{- $db := .Values.database -}}
{{- printf "postgres://%s:%s@%s:%v/%s?sslmode=%s" $db.user $db.password $db.host $db.port $db.name $db.sslmode -}}
{{- end -}}

{{/*
Generate a random secret once and preserve it across upgrades by reading the
existing chart-managed Secret. On `helm template` (no cluster) lookup returns
empty, so a fresh value is rendered.
*/}}
{{- define "raiwall.generatedSecret" -}}
{{- $ctx := .ctx -}}
{{- $existing := lookup "v1" "Secret" $ctx.Release.Namespace (printf "%s-secrets" (include "raiwall.fullname" $ctx)) -}}
{{- if and $existing $existing.data (hasKey $existing.data .env) -}}
{{- index $existing.data .env | b64dec -}}
{{- else -}}
{{- randAlphaNum 32 -}}
{{- end -}}
{{- end -}}

{{- define "raiwall.secretValue" -}}
{{- if .value -}}
{{- .value -}}
{{- else -}}
{{- include "raiwall.generatedSecret" (dict "ctx" .ctx "env" .env) -}}
{{- end -}}
{{- end -}}

{{/* Derive a numeric container port from a listen address such as ":8080". */}}
{{- define "raiwall.containerPort" -}}
{{- $parts := splitList ":" . -}}
{{- trimSuffix "]" (last $parts) -}}
{{- end -}}

{{- define "raiwall.probePortName" -}}
{{- if .Values.config.server.http.enabled -}}http{{- else -}}https{{- end -}}
{{- end -}}

{{- define "raiwall.probeScheme" -}}
{{- if .Values.config.server.http.enabled -}}HTTP{{- else -}}HTTPS{{- end -}}
{{- end -}}

{{- define "raiwall.dataVolumeClaim" -}}
{{- if .Values.persistence.existingClaim -}}
{{- .Values.persistence.existingClaim -}}
{{- else -}}
{{- printf "%s-data" (include "raiwall.fullname" .) -}}
{{- end -}}
{{- end -}}
