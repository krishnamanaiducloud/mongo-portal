// Package metrics defines the portal's Prometheus metrics. Label values are
// bounded (route patterns, outcomes, operation names); database names,
// user names and query contents are never used as labels.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

// Metrics holds all collectors.
type Metrics struct {
	Registry        *prometheus.Registry
	HTTPRequests    *prometheus.CounterVec
	HTTPDuration    *prometheus.HistogramVec
	AuthAttempts    *prometheus.CounterVec
	AuthzDenials    *prometheus.CounterVec
	ActiveSessions  prometheus.Gauge
	MongoConns      prometheus.Gauge
	MongoConnEvents *prometheus.CounterVec
	MongoOps        *prometheus.HistogramVec
	SessionsClosed  *prometheus.CounterVec
	BuildInfo       *prometheus.GaugeVec
}

// New registers and returns the portal metrics.
func New() *Metrics {
	r := prometheus.NewRegistry()
	m := &Metrics{
		Registry: r,
		HTTPRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "mongo_portal_http_requests_total", Help: "HTTP requests by route, method and status code.",
		}, []string{"route", "method", "code"}),
		HTTPDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "mongo_portal_http_request_duration_seconds", Help: "HTTP request latency.",
			Buckets: prometheus.DefBuckets,
		}, []string{"route", "method"}),
		AuthAttempts: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "mongo_portal_auth_attempts_total", Help: "Authentication attempts by stage (sso, mongodb) and result.",
		}, []string{"stage", "result"}),
		AuthzDenials: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "mongo_portal_authorization_denials_total", Help: "Authorization denials by source (portal, mongodb) and reason.",
		}, []string{"source", "reason"}),
		ActiveSessions: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "mongo_portal_sessions_active", Help: "Active MongoDB sessions held by this pod.",
		}),
		MongoConns: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "mongo_portal_mongodb_connections_open", Help: "Open MongoDB connections across all user sessions.",
		}),
		MongoConnEvents: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "mongo_portal_mongodb_connection_events_total", Help: "MongoDB connection pool events.",
		}, []string{"event"}),
		MongoOps: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "mongo_portal_mongodb_operation_duration_seconds", Help: "MongoDB operation latency by operation and outcome.",
			Buckets: []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10, 30, 60},
		}, []string{"operation", "outcome"}),
		SessionsClosed: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "mongo_portal_sessions_closed_total", Help: "Closed sessions by reason.",
		}, []string{"reason"}),
		BuildInfo: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "mongo_portal_build_info", Help: "Build information.",
		}, []string{"version", "commit", "goversion"}),
	}
	r.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		m.HTTPRequests, m.HTTPDuration, m.AuthAttempts, m.AuthzDenials, m.ActiveSessions,
		m.MongoConns, m.MongoConnEvents, m.MongoOps, m.SessionsClosed, m.BuildInfo,
	)
	return m
}
