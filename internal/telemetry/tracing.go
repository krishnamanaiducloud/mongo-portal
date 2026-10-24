// Package telemetry configures OpenTelemetry tracing. Tracing is optional:
// it is configured by telemetry.tracing or the standard OTEL_EXPORTER_OTLP_*
// environment variables, and an unusable collector never stops the portal
// (spans are dropped and the status page says why).
package telemetry

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"sort"
	"strings"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc/credentials"

	"github.com/krishnamanaiducloud/mongo-portal/internal/config"
	"github.com/krishnamanaiducloud/mongo-portal/internal/tlsx"
)

// Tracer is the portal tracer name.
const Tracer = "github.com/krishnamanaiducloud/mongo-portal"

// Status describes the effective tracing setup (no secrets).
type Status struct {
	Enabled     bool              `json:"enabled"`
	Protocol    string            `json:"protocol,omitempty"`
	Endpoint    string            `json:"endpoint,omitempty"`
	TLS         bool              `json:"tls"`
	SampleRatio float64           `json:"sampleRatio"`
	Source      string            `json:"source,omitempty"` // config or environment
	Reason      string            `json:"reason,omitempty"`
	Resource    map[string]string `json:"resource,omitempty"`
}

// Map returns the status as a map for JSON responses.
func (s Status) Map() map[string]any {
	m := map[string]any{"enabled": s.Enabled, "tls": s.TLS, "sampleRatio": s.SampleRatio}
	for k, v := range map[string]string{"protocol": s.Protocol, "endpoint": s.Endpoint, "source": s.Source, "reason": s.Reason} {
		if v != "" {
			m[k] = v
		}
	}
	if len(s.Resource) > 0 {
		m["resource"] = s.Resource
	}
	return m
}

// Setup installs a tracer provider. The returned function flushes and stops
// it. When tracing is off, a no-op provider stays installed.
func Setup(ctx context.Context, cfg config.TracingConfig, version string) (func(context.Context) error, Status) {
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}))
	noop := func(context.Context) error { return nil }
	ratio := 1.0
	if cfg.SampleRatio != nil {
		ratio = *cfg.SampleRatio
	}
	st := Status{SampleRatio: ratio}
	envEndpoint := os.Getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
	if envEndpoint == "" {
		envEndpoint = os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	}
	switch {
	case cfg.Enabled == config.EnabledFalse:
		st.Reason = "turned off in the configuration"
		return noop, st
	case cfg.Endpoint != "":
		st.Source, st.Endpoint = "config", cfg.Endpoint
	case envEndpoint != "":
		st.Source, st.Endpoint = "environment", envEndpoint
	default:
		st.Reason = "no OTLP endpoint configured"
		if cfg.Enabled == config.EnabledTrue {
			st.Reason = "telemetry.tracing.enabled is true but no endpoint is configured"
		}
		return noop, st
	}
	st.Protocol = cfg.Protocol
	if p := os.Getenv("OTEL_EXPORTER_OTLP_PROTOCOL"); st.Source == "environment" && p != "" {
		st.Protocol = p
	}
	exp, tlsOn, err := exporter(ctx, cfg, st)
	st.TLS = tlsOn
	if err != nil {
		st.Reason = "the OTLP exporter could not be configured: " + err.Error()
		return noop, st
	}
	attrs := []attribute.KeyValue{
		attribute.String("service.name", envOr("OTEL_SERVICE_NAME", cfg.ServiceName)),
		attribute.String("service.version", version),
	}
	st.Resource = map[string]string{"service.name": envOr("OTEL_SERVICE_NAME", cfg.ServiceName), "service.version": version}
	keys := make([]string, 0, len(cfg.ResourceAttributes))
	for k := range cfg.ResourceAttributes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		attrs = append(attrs, attribute.String(k, cfg.ResourceAttributes[k]))
		st.Resource[k] = cfg.ResourceAttributes[k]
	}
	res, err := resource.Merge(resource.Default(), resource.NewSchemaless(attrs...))
	if err != nil {
		st.Reason = err.Error()
		return noop, st
	}
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(ratio))),
	)
	otel.SetTracerProvider(tp)
	// Export failures are logged by the SDK through this handler and never
	// affect requests.
	otel.SetErrorHandler(otel.ErrorHandlerFunc(func(err error) {
		slog.Default().Debug("opentelemetry export error", "error", err.Error())
	}))
	st.Enabled = true
	return tp.Shutdown, st
}

func exporter(ctx context.Context, cfg config.TracingConfig, st Status) (sdktrace.SpanExporter, bool, error) {
	if st.Source == "environment" {
		// The SDK reads every OTEL_EXPORTER_OTLP_* variable itself.
		tlsOn := !strings.HasPrefix(st.Endpoint, "http://")
		if st.Protocol == "grpc" {
			e, err := otlptracegrpc.New(ctx)
			return e, tlsOn, err
		}
		e, err := otlptracehttp.New(ctx)
		return e, tlsOn, err
	}
	u, err := url.Parse(cfg.Endpoint)
	if err != nil {
		return nil, false, err
	}
	headers, err := readHeaders(cfg.HeadersFile)
	if err != nil {
		return nil, false, err
	}
	insecure := u.Scheme == "http"
	if insecure && !cfg.Insecure {
		return nil, false, errors.New("an http endpoint needs insecure: true")
	}
	var tc *tls.Config
	if !insecure {
		pool, perr := tlsx.Pool(cfg.CAFile)
		if perr != nil {
			return nil, false, perr
		}
		tc = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	if cfg.Protocol == "grpc" {
		opts := []otlptracegrpc.Option{otlptracegrpc.WithEndpoint(u.Host), otlptracegrpc.WithHeaders(headers)}
		if insecure {
			opts = append(opts, otlptracegrpc.WithInsecure())
		} else {
			opts = append(opts, otlptracegrpc.WithTLSCredentials(credentials.NewTLS(tc)))
		}
		e, err := otlptracegrpc.New(ctx, opts...)
		return e, !insecure, err
	}
	opts := []otlptracehttp.Option{otlptracehttp.WithEndpoint(u.Host), otlptracehttp.WithHeaders(headers)}
	if p := strings.TrimSuffix(u.Path, "/"); p != "" {
		opts = append(opts, otlptracehttp.WithURLPath(p))
	}
	if insecure {
		opts = append(opts, otlptracehttp.WithInsecure())
	} else {
		opts = append(opts, otlptracehttp.WithTLSClientConfig(tc))
	}
	e, err := otlptracehttp.New(ctx, opts...)
	return e, !insecure, err
}

// readHeaders reads "key=value" lines (blank lines and # comments ignored).
func readHeaders(path string) (map[string]string, error) {
	out := map[string]string{}
	if path == "" {
		return out, nil
	}
	f, err := os.Open(path) // #nosec G304 -- operator supplied secret mount
	if err != nil {
		return nil, fmt.Errorf("headers file: %w", err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok || strings.TrimSpace(k) == "" {
			return nil, errors.New("headers file lines must be key=value")
		}
		out[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return out, sc.Err()
}

// Start starts a span using the global provider.
func Start(ctx context.Context, name string, opts ...trace.SpanStartOption) (context.Context, trace.Span) {
	return otel.Tracer(Tracer).Start(ctx, name, opts...)
}

// LogHandler adds trace_id and span_id of the current span to every log
// record, so logs and traces correlate.
func LogHandler(h slog.Handler) slog.Handler { return traceHandler{h} }

type traceHandler struct{ slog.Handler }

func (t traceHandler) Handle(ctx context.Context, r slog.Record) error {
	if sc := trace.SpanContextFromContext(ctx); sc.IsValid() {
		r.AddAttrs(slog.String("trace_id", sc.TraceID().String()), slog.String("span_id", sc.SpanID().String()))
	}
	return t.Handler.Handle(ctx, r)
}

func (t traceHandler) WithAttrs(a []slog.Attr) slog.Handler {
	return traceHandler{t.Handler.WithAttrs(a)}
}
func (t traceHandler) WithGroup(n string) slog.Handler { return traceHandler{t.Handler.WithGroup(n)} }

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
