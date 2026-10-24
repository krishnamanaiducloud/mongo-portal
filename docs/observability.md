# Observability

## Tracing (OpenTelemetry)

Every API request is a server span with the route and status; MongoDB
operations are child spans. Trace context from incoming `traceparent`
headers is continued. Spans never contain credentials, tokens, query texts
or documents.

```yaml
telemetry:
  tracing:
    enabled: auto          # auto: on when an endpoint is configured; true; false
    protocol: grpc         # or http/protobuf (default)
    endpoint: https://otel-collector.observability.svc:4317
    caFile: /etc/mongo-portal/otel/ca.crt
    headersFile: /etc/mongo-portal/otel/headers   # key=value lines, e.g. an API key
    sampleRatio: 0.2       # new traces; parent decisions are kept
    serviceName: mongo-portal
    resourceAttributes:
      service.namespace: databases
      deployment.environment: prod
```

Without `endpoint` the standard `OTEL_EXPORTER_OTLP_ENDPOINT` /
`OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` and related variables are used. Plain
`http` endpoints require `insecure: true`. Jaeger, Grafana Tempo and any
OTLP collector work. An unreachable collector never affects requests: the
SDK drops spans. The System status and Settings pages show the effective
tracing setup. With a collector on 4317/4318, add the
`components/tracing-egress` NetworkPolicy.

## Logs

Structured JSON on stdout. Every request log line has `request_id` (also the
`X-Request-Id` response header) and, when tracing is on, `trace_id` and
`span_id`, so logs, traces and audit events (`traceId`) correlate. Set
`PORTAL_LOG_LEVEL` to `debug`, `warn` or `error` to change the level.

## Metrics (Prometheus, port 9090 `/metrics`)

| Metric | Meaning |
| --- | --- |
| `mongo_portal_http_requests_total{route,method,code}` | Requests |
| `mongo_portal_http_request_duration_seconds` | Latency |
| `mongo_portal_auth_attempts_total{stage,result}` | Sign-ins and MongoDB logins (`stage`: sso, oidc, mongodb, mongodb-oidc) |
| `mongo_portal_authorization_denials_total{source,reason}` | RBAC, CSRF and MongoDB denials |
| `mongo_portal_sessions_active`, `mongo_portal_sessions_closed_total{reason}` | Sessions |
| `mongo_portal_mongodb_connections_open` | MongoDB connections of all sessions |
| `mongo_portal_mongodb_operation_duration_seconds{operation,outcome}` | MongoDB operation latency |
| `mongo_portal_transfer_jobs_total{kind,outcome}`, `mongo_portal_transfer_documents_total{kind}` | Import and export |
| `mongo_portal_operations_killed_total` | killOp from the portal |
| `mongo_portal_audit_events_dropped_total` | Audit events not persisted to the store |
| `mongo_portal_build_info` | Version |

Labels never contain user names, database names or query contents. The
`components/monitoring` ServiceMonitor scrapes them with OpenShift
user-workload monitoring.

The portal's Monitoring page shows the MongoDB deployment as seen by the
user's session ([monitoring.md](monitoring.md)). For long-term MongoDB
metrics and alerting use a MongoDB exporter or Ops Manager; the portal
keeps about one hour of samples in the browser.
