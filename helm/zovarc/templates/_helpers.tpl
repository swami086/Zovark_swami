{{/*
Expand the name of the chart.
*/}}
{{- define "zovarc.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "zovarc.fullname" -}}
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

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "zovarc.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "zovarc.labels" -}}
helm.sh/chart: {{ include "zovarc.chart" . }}
{{ include "zovarc.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "zovarc.selectorLabels" -}}
app.kubernetes.io/name: {{ include "zovarc.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
API selector labels
*/}}
{{- define "zovarc.api.selectorLabels" -}}
{{ include "zovarc.selectorLabels" . }}
app.kubernetes.io/component: api
{{- end }}

{{/*
Worker selector labels
*/}}
{{- define "zovarc.worker.selectorLabels" -}}
{{ include "zovarc.selectorLabels" . }}
app.kubernetes.io/component: worker
{{- end }}

{{/*
Dashboard selector labels
*/}}
{{- define "zovarc.dashboard.selectorLabels" -}}
{{ include "zovarc.selectorLabels" . }}
app.kubernetes.io/component: dashboard
{{- end }}
