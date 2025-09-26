{{- define "cloud-controller-manager.name" -}}
{{- .Values.nameOverride }}
{{- end -}}

{{- define "aws-cloud-config.name" -}}
"aws-cloud-config"
{{- end }}
