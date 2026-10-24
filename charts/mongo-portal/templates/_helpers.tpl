{{- define "mongo-portal.name" -}}
{{- .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "mongo-portal.fullname" -}}
{{- if contains .Chart.Name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "mongo-portal.selectorLabels" -}}
app.kubernetes.io/name: {{ include "mongo-portal.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "mongo-portal.labels" -}}
{{ include "mongo-portal.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/part-of: mongo-portal
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{- end -}}

{{- define "mongo-portal.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "mongo-portal.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/* Image reference: a digest wins over a tag. */}}
{{- define "mongo-portal.image" -}}
{{- $repo := required "image.repository is required (the published image or your registry mirror)" .Values.image.repository -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" $repo .Values.image.digest -}}
{{- else -}}
{{- $tag := default .Chart.AppVersion .Values.image.tag -}}
{{- if and (eq .Values.image.variant "debug") (not (hasSuffix "-debug" $tag)) -}}
{{- $tag = printf "%s-debug" $tag -}}
{{- end -}}
{{- printf "%s:%s" $repo $tag -}}
{{- end -}}
{{- end -}}

{{- define "mongo-portal.openshift" -}}
{{- if eq .Values.platform "openshift" }}true{{ end -}}
{{- end -}}

{{/* The configuration with the paths the chart mounts filled in. */}}
{{- define "mongo-portal.config" -}}
{{- $managed := dict
  "server" (dict "listenAddress" "0.0.0.0:8443" "opsListenAddress" "0.0.0.0:9090" "hsts" .Values.tls.enabled)
  "session" (dict "keyFile" "/etc/mongo-portal/session/session-key")
  "rbac" (dict "policyDir" "/etc/mongo-portal/rbac")
  "transfer" (dict "tempDir" "/var/lib/mongo-portal/transfer")
-}}
{{- if .Values.tls.enabled -}}
{{- $_ := set $managed.server "tls" (dict "certFile" "/etc/tls/private/tls.crt" "keyFile" "/etc/tls/private/tls.key") -}}
{{- end -}}
{{- if not (include "mongo-portal.openshift" .) -}}
{{- $_ := set $managed "identity" (dict "openshift" (dict "enabled" "false")) -}}
{{- end -}}
{{- toYaml (mergeOverwrite $managed (deepCopy .Values.config)) -}}
{{- end -}}

{{/* Volumes shared by the portal and the preflight test. */}}
{{- define "mongo-portal.volumes" -}}
- name: config
  configMap:
    name: {{ include "mongo-portal.fullname" . }}-config
- name: rbac
  configMap:
    name: {{ include "mongo-portal.fullname" . }}-rbac
    optional: true
{{- if .Values.tls.enabled }}
- name: serving-cert
  secret:
    secretName: {{ .Values.tls.secretName }}
{{- end }}
- name: session-key
  secret:
    secretName: {{ .Values.secrets.session }}
    optional: true
- name: mongodb-ca
  configMap:
    name: {{ .Values.mongodbCA.configMap }}
    optional: true
- name: mongodb-client-cert
  secret:
    secretName: {{ .Values.secrets.mongodbClient }}
    optional: true
- name: oidc
  secret:
    secretName: {{ .Values.secrets.oidc }}
    optional: true
- name: store
  secret:
    secretName: {{ .Values.secrets.store }}
    optional: true
- name: tmp
  emptyDir:
    medium: Memory
    sizeLimit: 64Mi
- name: transfer
  emptyDir:
    sizeLimit: {{ .Values.transfer.sizeLimit }}
{{- end -}}

{{- define "mongo-portal.volumeMounts" -}}
- name: config
  mountPath: /etc/mongo-portal/config
  readOnly: true
- name: rbac
  mountPath: /etc/mongo-portal/rbac
  readOnly: true
{{- if .Values.tls.enabled }}
- name: serving-cert
  mountPath: /etc/tls/private
  readOnly: true
{{- end }}
- name: session-key
  mountPath: /etc/mongo-portal/session
  readOnly: true
- name: mongodb-ca
  mountPath: /etc/mongo-portal/mongodb-ca
  readOnly: true
- name: mongodb-client-cert
  mountPath: /etc/mongo-portal/mongodb-client
  readOnly: true
- name: oidc
  mountPath: /etc/mongo-portal/oidc
  readOnly: true
- name: store
  mountPath: /etc/mongo-portal/store
  readOnly: true
- name: tmp
  mountPath: /tmp
- name: transfer
  mountPath: /var/lib/mongo-portal/transfer
{{- end -}}

{{- define "mongo-portal.env" -}}
- name: PORTAL_CONFIG
  value: /etc/mongo-portal/config/config.yaml
- name: POD_NAME
  valueFrom:
    fieldRef:
      fieldPath: metadata.name
- name: GOMEMLIMIT
  value: {{ .Values.goMemLimit | quote }}
{{- range $k, $v := .Values.env }}
- name: {{ $k }}
  value: {{ $v | quote }}
{{- end }}
{{- with .Values.extraEnv }}
{{ toYaml . }}
{{- end }}
{{- end -}}

{{- define "mongo-portal.securityContext" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
runAsNonRoot: true
capabilities:
  drop: ["ALL"]
{{- end -}}
