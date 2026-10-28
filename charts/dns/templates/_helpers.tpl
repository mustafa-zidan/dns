{{- define "dns.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "dns.fullname" -}}
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

{{- define "dns.dashboardName" -}}
{{- printf "%s-dashboard" (include "dns.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "dns.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: {{ include "dns.name" . }}
{{- end }}

{{- define "dns.selectorLabels" -}}
app.kubernetes.io/name: {{ include "dns.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: server
{{- end }}

{{- define "dns.dashboardSelectorLabels" -}}
app.kubernetes.io/name: {{ include "dns.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: dashboard
{{- end }}

{{/* repository:tag, or repository@digest when a digest is pinned. */}}
{{- define "dns.image" -}}
{{- $image := index . 0 }}
{{- $root := index . 1 }}
{{- if $image.digest }}
{{- printf "%s@%s" $image.repository $image.digest }}
{{- else }}
{{- printf "%s:%s" $image.repository (default $root.Chart.AppVersion $image.tag) }}
{{- end }}
{{- end }}

{{/* The Secret holding dns.toml. */}}
{{- define "dns.configSecret" -}}
{{- default (include "dns.fullname" .) .Values.existingConfigSecret }}
{{- end }}

{{- define "dns.tlsSecret" -}}
{{- if .Values.tls.certManager.enabled }}
{{- printf "%s-tls" (include "dns.fullname" .) }}
{{- else }}
{{- required "tls.secretName or tls.certManager.enabled is required when tls.enabled is true" .Values.tls.secretName }}
{{- end }}
{{- end }}

{{/* URL for an ingress host: https when a TLS entry covers it. */}}
{{- define "dns.hostUrl" -}}
{{- $host := index . 0 }}
{{- $ingress := index . 1 }}
{{- $scheme := "http" }}
{{- range $ingress.tls }}
{{- if has $host .hosts }}{{ $scheme = "https" }}{{ end }}
{{- end }}
{{- printf "%s://%s" $scheme $host }}
{{- end }}

{{/* Where the browser reaches the API. */}}
{{- define "dns.apiUrl" -}}
{{- if .Values.dashboard.apiUrl }}
{{- .Values.dashboard.apiUrl }}
{{- else if and .Values.api.ingress.enabled .Values.api.ingress.hosts }}
{{- include "dns.hostUrl" (list (first .Values.api.ingress.hosts) .Values.api.ingress) }}
{{- else }}
{{- printf "http://localhost:%v" .Values.api.service.port }}
{{- end }}
{{- end }}

{{/* The API token: from values, else the one already installed, else new. */}}
{{- define "dns.apiToken" -}}
{{- if .Values.api.token }}
{{- .Values.api.token }}
{{- else }}
{{- $secret := lookup "v1" "Secret" .Release.Namespace (include "dns.fullname" .) }}
{{- if and $secret $secret.data (hasKey $secret.data "api-token") }}
{{- index $secret.data "api-token" | b64dec }}
{{- else }}
{{- randAlphaNum 40 }}
{{- end }}
{{- end }}
{{- end }}

{{/* dns.toml, from .Values.config plus what the chart manages. Takes a dict
     with the root context and the token. */}}
{{- define "dns.configToml" -}}
{{- $root := .root }}
{{- $v := $root.Values }}
{{- $config := deepCopy $v.config }}
{{- $server := merge (dict "listen" (list "0.0.0.0:53")) (default dict $config.server) }}
{{- $_ := set $config "server" $server }}
{{- $origins := list }}
{{- if $v.dashboard.enabled }}
{{- $origins = append $origins (printf "http://localhost:%v" $v.dashboard.service.port) }}
{{- if $v.dashboard.ingress.enabled }}
{{- range $v.dashboard.ingress.hosts }}
{{- $origins = append $origins (include "dns.hostUrl" (list . $v.dashboard.ingress)) }}
{{- end }}
{{- end }}
{{- end }}
{{- $origins = concat $origins $v.api.corsOrigins | uniq }}
{{- $api := dict "enabled" $v.api.enabled "listen" "0.0.0.0:8053" "token" .token "cors_origins" $origins }}
{{- $_ := set $config "api" $api }}
{{- if $v.tls.enabled }}
{{- $tls := dict "cert_file" "/etc/dns/tls/tls.crt" "key_file" "/etc/dns/tls/tls.key" "doh_path" $v.tls.dohPath }}
{{- if $v.tls.dot }}{{ $_ := set $tls "dot_listen" (list "0.0.0.0:853") }}{{ end }}
{{- if $v.tls.doh }}{{ $_ := set $tls "doh_listen" (list "0.0.0.0:443") }}{{ end }}
{{- $_ := set $config "tls" $tls }}
{{- end }}
{{- toToml $config }}
{{- end }}
