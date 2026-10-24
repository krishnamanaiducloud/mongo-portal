// Command mongo-portal runs the MongoDB management portal.
package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/krishnamanaiducloud/mongo-portal/internal/api"
	"github.com/krishnamanaiducloud/mongo-portal/internal/audit"
	"github.com/krishnamanaiducloud/mongo-portal/internal/config"
	"github.com/krishnamanaiducloud/mongo-portal/internal/identity"
	"github.com/krishnamanaiducloud/mongo-portal/internal/metrics"
	"github.com/krishnamanaiducloud/mongo-portal/internal/mongoconn"
	"github.com/krishnamanaiducloud/mongo-portal/internal/rbac"
	"github.com/krishnamanaiducloud/mongo-portal/internal/session"
	"github.com/krishnamanaiducloud/mongo-portal/internal/store"
	"github.com/krishnamanaiducloud/mongo-portal/internal/telemetry"
	"github.com/krishnamanaiducloud/mongo-portal/internal/webui"
)

// Set at build time with -ldflags "-X main.version=... -X main.commit=...".
var (
	version = "dev"
	commit  = "unknown"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		os.Exit(healthcheck(os.Args[2:]))
	}
	configPath := flag.String("config", envOr("PORTAL_CONFIG", "/etc/mongo-portal/config.yaml"), "path to the configuration file")
	showVersion := flag.Bool("version", false, "print version and exit")
	checkConfig := flag.Bool("check-config", false, "validate configuration and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("mongo-portal %s (%s) %s\n", version, commit, runtime.Version())
		return
	}

	logger := slog.New(telemetry.LogHandler(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel()})))
	slog.SetDefault(logger)

	cfg, err := config.Load(*configPath)
	if err != nil {
		logger.Error("invalid configuration", "error", err.Error())
		os.Exit(2)
	}
	if *checkConfig {
		fmt.Println("configuration is valid")
		return
	}
	if err := run(cfg, logger); err != nil {
		logger.Error("portal stopped with error", "error", err.Error())
		os.Exit(1)
	}
}

func run(cfg *config.Config, logger *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Optional integrations never stop the portal: an unusable tracing
	// endpoint is reported and tracing stays off.
	shutdownTracing, tracing := telemetry.Setup(ctx, cfg.Telemetry.Tracing, version)
	switch {
	case tracing.Enabled:
		logger.Info("tracing enabled", "protocol", tracing.Protocol, "endpoint", tracing.Endpoint, "tls", tracing.TLS, "sample_ratio", tracing.SampleRatio)
	case cfg.Telemetry.Tracing.Enabled == config.EnabledTrue || tracing.Source != "":
		logger.Warn("tracing disabled", "reason", tracing.Reason)
	}
	defer func() {
		c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = shutdownTracing(c)
	}()

	for _, p := range cfg.Profiles {
		if p.TLS.Mode == config.TLSDisabled {
			logger.Warn("connection profile uses plaintext MongoDB traffic: credentials and data are not encrypted in transit",
				"profile", p.Name, "plaintext_approved", p.PlaintextApproved, "security_exception", p.SecurityExceptionRef)
		}
	}
	if cfg.Identity.Dev.Enabled {
		logger.Warn("INSECURE development identity is enabled; never use this in a cluster", "user", cfg.Identity.Dev.User)
	}
	if cfg.Identity.Mode != "" {
		logger.Warn("identity.mode is deprecated; use identity.openshift.enabled, identity.header.enabled or identity.dev.enabled", "mode", cfg.Identity.Mode)
	}
	if len(cfg.Identity.DeveloperGroups)+len(cfg.Identity.SREGroups) > 0 {
		logger.Warn("identity.developerGroups and identity.sreGroups are deprecated; use rbac.policy (g, <group>, role:readonly|role:admin)")
	}

	key, err := loadKey(cfg.Session.KeyFile)
	if err != nil {
		logger.Warn("session key unusable; using a random per-process key (sign-ins do not survive restarts or move between replicas)", "error", err.Error())
		key = nil
	}
	if key == nil {
		if cfg.Session.KeyFile == "" {
			logger.Warn("session.keyFile not set; using a random per-process key (single replica only)")
		}
		key = make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return err
		}
	}

	rbacStore, err := rbac.NewStore(rbac.Source{
		Inline: cfg.RBAC.Policy, Extra: cfg.LegacyRBACPolicy(), DefaultRole: *cfg.RBAC.DefaultRole, Dir: cfg.RBAC.PolicyDir,
	}, logger)
	if err != nil {
		return fmt.Errorf("rbac: %w", err)
	}
	go rbacStore.Watch(ctx, cfg.RBAC.ReloadInterval)

	resolver, err := identity.NewResolver(identity.Options{
		Config: cfg.Identity, Key: key, SecureCookie: *cfg.Session.SecureCookie, MaxAge: cfg.Session.AbsoluteTimeout,
		KeepGroup: func(g string) bool {
			subjects := rbacStore.Policy().Subjects()
			return slices.Contains(subjects, g) || slices.Contains(subjects, "group:"+g)
		},
		Logger: logger,
	})
	if err != nil {
		return fmt.Errorf("identity: %w", err)
	}
	resolver.RunProviders(ctx)

	monitor := mongoconn.NewMonitor(cfg.Profiles, cfg.Monitoring.ProfileHealthInterval, logger)
	monitorDone := make(chan struct{})
	go func() {
		defer close(monitorDone)
		monitor.Run(ctx)
	}()

	m := metrics.New()
	m.BuildInfo.WithLabelValues(version, commit, runtime.Version()).Set(1)
	pod := podName()

	// Optional shared store: durable audit trail and session registry.
	st := store.New(cfg, logger)
	if cfg.Store.Enabled {
		cctx, ccancel := context.WithTimeout(ctx, 30*time.Second)
		err := st.Connect(cctx)
		ccancel()
		if err != nil && cfg.Store.Required {
			return fmt.Errorf("store: %w", err)
		}
		go st.Run(ctx)
	}
	auditOpts := audit.Options{Capacity: cfg.Audit.BufferSize, Pod: pod,
		OnDrop: func(n int) { m.AuditDropped.Add(float64(n)) }}
	if cfg.Audit.Persist {
		auditOpts.Sink = st.Audit()
	}
	auditLog := audit.NewWithOptions(logger, auditOpts)
	defer auditLog.Close()

	var srv *api.Server
	store := session.NewStore(session.Options{
		IdleTimeout: cfg.Session.IdleTimeout, AbsoluteTimeout: cfg.Session.AbsoluteTimeout,
		MaxPerUser: cfg.Session.MaxPerUser, MaxTotal: cfg.Session.MaxTotal,
		OnClose: func(s *session.Session, reason string) {
			if srv != nil {
				srv.OnSessionClosed(s, reason)
			}
		},
	})
	deps := api.Deps{
		Config: cfg, Identity: resolver, RBAC: rbacStore, Monitor: monitor, Store: store, Audit: auditLog, Metrics: m, Logger: logger,
		CSRFKey: key, UI: webui.Handler(), Build: api.BuildInfo{Version: version, Commit: commit},
		TracingEnabled: tracing.Enabled, Tracing: tracing.Map(), Pod: pod,
	}
	if cfg.Store.Enabled {
		deps.StoreStatus = func() map[string]any {
			s := st.Status()
			return map[string]any{"state": s.State, "reason": s.Reason, "database": s.Database, "checkedAt": s.CheckedAt}
		}
		if cfg.Audit.Persist {
			deps.AuditChain = st.Audit().Chain
		}
		if cfg.Session.Registry {
			deps.Registry = st.Sessions()
		}
	}
	srv = api.New(deps)
	go srv.RunRegistry(ctx, cfg.Session.RegistrySyncInterval)
	go srv.RunJobs(ctx)

	var ready atomic.Bool
	mainSrv := &http.Server{
		Addr: cfg.Server.ListenAddress, Handler: srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout, IdleTimeout: 120 * time.Second, MaxHeaderBytes: 64 << 10,
		ErrorLog: slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}
	opsSrv := &http.Server{
		Addr:              cfg.Server.OpsListenAddress,
		Handler:           api.OpsHandler(ready.Load, promhttp.HandlerFor(m.Registry, promhttp.HandlerOpts{})),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 30 * time.Second,
	}

	mainLn, err := net.Listen("tcp", cfg.Server.ListenAddress)
	if err != nil {
		return err
	}
	scheme := "http"
	if cfg.Server.TLS.CertFile != "" {
		cr := &certReloader{certFile: cfg.Server.TLS.CertFile, keyFile: cfg.Server.TLS.KeyFile}
		if _, err := cr.get(); err != nil {
			return fmt.Errorf("server tls: %w", err)
		}
		mainLn = tls.NewListener(mainLn, &tls.Config{
			MinVersion:     tls.VersionTLS12,
			GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return cr.get() },
		})
		scheme = "https"
	}
	opsLn, err := net.Listen("tcp", cfg.Server.OpsListenAddress)
	if err != nil {
		return err
	}
	errc := make(chan error, 2)
	go func() { errc <- serve(mainSrv, mainLn) }()
	go func() { errc <- serve(opsSrv, opsLn) }()
	ready.Store(true)
	logger.Info("mongo portal started", "version", version, "commit", commit, "listen", cfg.Server.ListenAddress, "scheme", scheme,
		"ops_listen", cfg.Server.OpsListenAddress, "openshift_login", cfg.Identity.OpenShift.Enabled, "header_identity", cfg.Identity.Header.Enabled,
		"require_sso", cfg.Identity.RequireSSO, "rbac", rbacStore.Status().Source, "profiles", len(cfg.Profiles), "environment", cfg.Environment)

	select {
	case <-ctx.Done():
	case err := <-errc:
		return err
	}

	// Stop receiving new traffic, give the endpoints controller time to
	// remove this pod, then drain and close all MongoDB sessions.
	ready.Store(false)
	logger.Info("shutting down", "delay", cfg.Server.ShutdownDelay.String())
	time.Sleep(cfg.Server.ShutdownDelay)
	sctx, cancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout)
	defer cancel()
	_ = mainSrv.Shutdown(sctx)
	store.Close()
	stop() // ends the background probes and closes the monitor clients
	<-monitorDone
	_ = opsSrv.Shutdown(sctx)
	auditLog.Close()
	st.Close(sctx)
	logger.Info("shutdown complete")
	return nil
}

// certReloader serves the current certificate and reloads it when the files
// change (the OpenShift service CA rotates serving certificates).
type certReloader struct {
	certFile, keyFile string
	mu                sync.Mutex
	cert              *tls.Certificate
	certMod, keyMod   time.Time
	checked           time.Time
}

func (c *certReloader) get() (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cert != nil && time.Since(c.checked) < 10*time.Second {
		return c.cert, nil
	}
	c.checked = time.Now()
	cs, err1 := os.Stat(c.certFile)
	ks, err2 := os.Stat(c.keyFile)
	if err := errors.Join(err1, err2); err != nil {
		if c.cert != nil {
			return c.cert, nil
		}
		return nil, err
	}
	if c.cert != nil && cs.ModTime().Equal(c.certMod) && ks.ModTime().Equal(c.keyMod) {
		return c.cert, nil
	}
	pair, err := tls.LoadX509KeyPair(c.certFile, c.keyFile)
	if err != nil {
		if c.cert != nil {
			return c.cert, nil // mid-rotation: keep serving the previous pair
		}
		return nil, err
	}
	c.cert, c.certMod, c.keyMod = &pair, cs.ModTime(), ks.ModTime()
	return c.cert, nil
}

func serve(s *http.Server, ln net.Listener) error {
	if err := s.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func loadKey(path string) ([]byte, error) {
	if path == "" {
		return nil, nil
	}
	b, err := os.ReadFile(path) // #nosec G304 -- operator supplied secret mount
	if err != nil {
		return nil, fmt.Errorf("read session key: %w", err)
	}
	b = []byte(strings.TrimSpace(string(b)))
	if len(b) < 32 {
		return nil, errors.New("session key must be at least 32 bytes")
	}
	return b, nil
}

// healthcheck probes the ops listener; used as a container HEALTHCHECK in
// images that contain no shell or curl.
func healthcheck(args []string) int {
	addr := envOr("PORTAL_HEALTHCHECK_URL", "http://127.0.0.1:9090/healthz")
	if len(args) > 0 {
		addr = args[0]
	}
	c := &http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get(addr) // #nosec G107 G704 -- operator-supplied local health endpoint, not user input
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintln(os.Stderr, "unhealthy:", resp.Status)
		return 1
	}
	return 0
}

func logLevel() slog.Level {
	switch strings.ToLower(os.Getenv("PORTAL_LOG_LEVEL")) {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	}
	return slog.LevelInfo
}

// podName identifies this replica (the pod name in Kubernetes).
func podName() string {
	if v := os.Getenv("POD_NAME"); v != "" {
		return v
	}
	h, _ := os.Hostname()
	return h
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
