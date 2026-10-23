// Package api implements the portal's REST API and serves the web UI.
package api

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"

	"github.com/krishnamanaiducloud/mongo-portal/internal/audit"
	"github.com/krishnamanaiducloud/mongo-portal/internal/config"
	"github.com/krishnamanaiducloud/mongo-portal/internal/identity"
	"github.com/krishnamanaiducloud/mongo-portal/internal/metrics"
	"github.com/krishnamanaiducloud/mongo-portal/internal/mongoconn"
	"github.com/krishnamanaiducloud/mongo-portal/internal/ratelimit"
	"github.com/krishnamanaiducloud/mongo-portal/internal/rbac"
	"github.com/krishnamanaiducloud/mongo-portal/internal/session"
	"github.com/krishnamanaiducloud/mongo-portal/internal/telemetry"
)

// BuildInfo identifies the running build.
type BuildInfo struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
}

// ConnectFunc authenticates a user against a profile. Replaceable in tests.
type ConnectFunc func(ctx context.Context, p *config.Profile, c mongoconn.Credentials, h mongoconn.PoolHooks) (*mongoconn.ConnectResult, error)

// Deps are the server's collaborators.
type Deps struct {
	Config   *config.Config
	Identity *identity.Resolver
	RBAC     *rbac.Store
	// Monitor reports connection profile health (optional).
	Monitor *mongoconn.Monitor
	Store   *session.Store
	Audit   *audit.Log
	Metrics *metrics.Metrics
	Logger  *slog.Logger
	// CSRFKey signs pre-login CSRF tokens and seals OAuth state; it must
	// be the same on every replica (session.keyFile).
	CSRFKey []byte
	Connect ConnectFunc
	UI      http.Handler
	Build   BuildInfo
	// TracingEnabled is reported on the status page.
	TracingEnabled bool
}

// Server is the HTTP API.
type Server struct {
	Deps
	limiter  *ratelimit.Limiter
	loginSem chan struct{}
	routes   []Route
	mux      *http.ServeMux
	state    *identity.Sealer
}

// Route describes a registered API route (used by the OpenAPI contract test).
type Route struct {
	Method string
	Path   string
}

type ctxKey int

const reqKey ctxKey = 0

type reqCtx struct {
	requestID string
	// p is the request principal: the SSO user, or the MongoDB user of a
	// MongoDB-only session. Nil for anonymous requests.
	p      *identity.Principal
	owner  string
	sess   *session.Session
	secret string
	span   trace.Span
}

// roles returns the principal's RBAC roles (for audit and the UI).
func (s *Server) roles(rc *reqCtx) []string {
	if rc.p == nil {
		return nil
	}
	return s.RBAC.Policy().Roles(rc.p.Subjects())
}

func from(r *http.Request) *reqCtx {
	rc, _ := r.Context().Value(reqKey).(*reqCtx)
	if rc == nil {
		rc = &reqCtx{}
	}
	return rc
}

// New creates the API server.
func New(d Deps) *Server {
	if d.Connect == nil {
		d.Connect = mongoconn.Connect
	}
	if len(d.CSRFKey) < 32 {
		k := make([]byte, 32)
		_, _ = rand.Read(k)
		d.CSRFKey = k
	}
	l := d.Config.Login
	state, err := identity.NewSealer(d.CSRFKey, "oauth-state")
	if err != nil {
		panic(err) // unreachable: the key is at least 32 bytes
	}
	s := &Server{
		Deps:     d,
		limiter:  ratelimit.New(l.AttemptsPerWindow, l.Window, l.FailuresBeforeLock, l.LockDuration, l.MaxLockDuration),
		loginSem: make(chan struct{}, l.MaxConcurrent),
		mux:      http.NewServeMux(),
		state:    state,
	}
	s.register()
	return s
}

// Routes returns the registered API routes.
func (s *Server) Routes() []Route { return s.routes }

// access levels for routes. Authorization of individual operations is done
// by the handlers with the RBAC policy (see authorize).
type level int

const (
	levelPublic   level = iota // anonymous allowed (identity optional)
	levelIdentity              // SSO identity or MongoDB session required
	levelSession               // MongoDB session required
)

type handlerFunc func(w http.ResponseWriter, r *http.Request, rc *reqCtx)

func (s *Server) handle(method, path string, lvl level, bodyLimit int64, h handlerFunc) {
	s.routes = append(s.routes, Route{Method: method, Path: path})
	pattern := method + " " + path
	s.mux.Handle(pattern, s.instrument(pattern, bodyLimit, s.guard(lvl, h)))
}

func (s *Server) register() {
	const v = "/api/v1"
	small := s.Config.Server.MaxBodyBytes
	docBody := s.Config.Query.MaxDocumentBytes*2 + 4096

	s.handle("GET", v+"/me", levelPublic, 0, s.handleMe)
	s.handle("GET", v+"/status", levelPublic, 0, s.handleStatus)
	s.handle("GET", v+"/profiles", levelPublic, 0, s.handleProfiles)
	s.handle("POST", v+"/session", levelPublic, small, s.handleLogin)
	s.handle("GET", v+"/session", levelSession, 0, s.handleSessionInfo)
	s.handle("DELETE", v+"/session", levelSession, 0, s.handleLogout)
	s.handle("POST", v+"/auth/logout", levelPublic, 0, s.handleSignOut)
	s.handle("GET", v+"/permissions", levelIdentity, 0, s.handlePermissions)
	s.handle("GET", v+"/sessions", levelIdentity, 0, s.handleListSessions)
	s.handle("DELETE", v+"/sessions/{handle}", levelIdentity, 0, s.handleTerminateSession)
	s.handle("GET", v+"/audit", levelIdentity, 0, s.handleAudit)
	s.handle("GET", v+"/server", levelSession, 0, s.handleServerInfo)
	s.handle("GET", v+"/monitoring", levelSession, 0, s.handleMonitoring)

	s.handle("GET", v+"/databases", levelSession, 0, s.handleListDatabases)
	s.handle("GET", v+"/databases/{db}/stats", levelSession, 0, s.handleDatabaseStats)
	s.handle("GET", v+"/databases/{db}/collections", levelSession, 0, s.handleListCollections)
	s.handle("POST", v+"/databases/{db}/collections", levelSession, small, s.handleCreateCollection)
	s.handle("DELETE", v+"/databases/{db}/collections/{coll}", levelSession, 0, s.handleDropCollection)
	s.handle("GET", v+"/databases/{db}/collections/{coll}/stats", levelSession, 0, s.handleCollectionStats)
	s.handle("GET", v+"/databases/{db}/collections/{coll}/documents", levelSession, 0, s.handleFindDocuments)
	s.handle("POST", v+"/databases/{db}/collections/{coll}/documents", levelSession, docBody, s.handleInsertDocument)
	s.handle("GET", v+"/databases/{db}/collections/{coll}/documents/{id}", levelSession, 0, s.handleGetDocument)
	s.handle("PUT", v+"/databases/{db}/collections/{coll}/documents/{id}", levelSession, docBody, s.handleReplaceDocument)
	s.handle("DELETE", v+"/databases/{db}/collections/{coll}/documents/{id}", levelSession, 0, s.handleDeleteDocument)
	s.handle("POST", v+"/databases/{db}/collections/{coll}/query", levelSession, small, s.handleQuery)
	s.handle("GET", v+"/databases/{db}/collections/{coll}/indexes", levelSession, 0, s.handleListIndexes)
	s.handle("POST", v+"/databases/{db}/collections/{coll}/indexes", levelSession, small, s.handleCreateIndex)
	s.handle("DELETE", v+"/databases/{db}/collections/{coll}/indexes/{name}", levelSession, 0, s.handleDropIndex)
	s.handle("POST", v+"/shell", levelSession, docBody, s.handleShell)

	s.routes = append(s.routes, Route{Method: "GET", Path: v + "/openapi.yaml"})
	s.mux.Handle("GET "+v+"/openapi.yaml", s.instrument("GET "+v+"/openapi.yaml", 0, http.HandlerFunc(serveOpenAPI)))

	// OpenShift OAuth login (browser redirects, not JSON API).
	s.mux.Handle("GET "+oauthStartPath, s.instrument("GET "+oauthStartPath, 0, http.HandlerFunc(s.handleOAuthStart)))
	s.mux.Handle("GET "+oauthCallbackPath, s.instrument("GET "+oauthCallbackPath, 0, http.HandlerFunc(s.handleOAuthCallback)))

	s.mux.Handle("/api/", s.instrument("api_not_found", 0, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeError(w, r, http.StatusNotFound, "not_found", "No such API endpoint")
	})))
	if s.UI != nil {
		// Registered without a method so it does not conflict with the
		// method-less "/api/" catch-all; non-GET requests are rejected here.
		s.mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				w.Header().Set("Allow", "GET, HEAD")
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			s.UI.ServeHTTP(w, r)
		}))
	}
}

// Handler returns the main HTTP handler with global middleware.
func (s *Server) Handler() http.Handler {
	return s.recoverer(s.requestID(securityHeaders(s.Config.Server.HSTS, s.mux)))
}

// guard resolves the principal and enforces CSRF and session requirements.
// Identity is optional: without SSO, a MongoDB-only session supplies the
// principal, and anonymous requests may use the public endpoints.
func (s *Server) guard(lvl level, h handlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rc := from(r)
		if c, err := r.Cookie(s.Config.Session.CookieName); err == nil {
			rc.secret = c.Value
		}
		rc.p = s.Identity.Resolve(w, r)
		if rc.p == nil {
			// A MongoDB-only session identifies its own principal.
			if owner, p := s.Store.OwnerOf(rc.secret); p != nil && p.Source == identity.SourceMongoDB {
				rc.p, rc.owner = p, owner
			}
		} else {
			rc.owner = rc.p.Key()
		}
		if rc.span != nil && rc.p != nil {
			rc.span.SetAttributes(attribute.String("portal.identity", string(rc.p.Source)))
		}

		if lvl >= levelIdentity {
			switch {
			case s.Config.Identity.RequireSSO && !rc.p.SSO():
				s.Metrics.AuthAttempts.WithLabelValues("sso", "unauthenticated").Inc()
				writeError(w, r, http.StatusUnauthorized, "sso_required", "Sign in with single sign-on to continue")
				return
			case rc.p == nil:
				writeError(w, r, http.StatusUnauthorized, "mongo_session_required", "Sign in to continue")
				return
			}
		}

		unsafe := r.Method != http.MethodGet && r.Method != http.MethodHead
		if unsafe {
			if err := s.checkOrigin(r); err != nil {
				s.Metrics.AuthzDenials.WithLabelValues("portal", "csrf_origin").Inc()
				writeError(w, r, http.StatusForbidden, "csrf_failed", "Cross-site request rejected")
				return
			}
			if r.ContentLength != 0 && !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
				writeError(w, r, http.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type must be application/json")
				return
			}
		}

		if lvl >= levelSession {
			sess, err := s.Store.Get(rc.secret, rc.owner)
			if err != nil {
				reason := "mongo_session_required"
				if errors.Is(err, session.ErrExpired) {
					reason = "mongo_session_expired"
				}
				if errors.Is(err, session.ErrWrongOwner) {
					s.Audit.Record(r.Context(), audit.Event{RequestID: rc.requestID, SSOUser: rc.user(), Identity: rc.source(), Owner: rc.owner, Action: "session_owner_mismatch", Outcome: audit.Denied})
				}
				s.clearCookie(w)
				writeError(w, r, http.StatusUnauthorized, reason, "Sign in to MongoDB to continue")
				return
			}
			rc.sess = sess
			if unsafe && !constantEq(r.Header.Get("X-CSRF-Token"), sess.CSRFToken) {
				s.Metrics.AuthzDenials.WithLabelValues("portal", "csrf_token").Inc()
				writeError(w, r, http.StatusForbidden, "csrf_failed", "Missing or invalid CSRF token")
				return
			}
		} else if unsafe {
			// Other unsafe requests (login, sign-out, terminate session) use the
			// session token when a session exists, else the pre-login token.
			ok := false
			if sess, err := s.Store.Get(rc.secret, rc.owner); err == nil {
				ok = constantEq(r.Header.Get("X-CSRF-Token"), sess.CSRFToken)
			}
			if !ok {
				ok = s.validPreauthToken(r.Header.Get("X-CSRF-Token"), s.csrfBinding(r, rc))
			}
			if !ok {
				s.Metrics.AuthzDenials.WithLabelValues("portal", "csrf_token").Inc()
				writeError(w, r, http.StatusForbidden, "csrf_failed", "Missing or invalid CSRF token")
				return
			}
		}
		h(w, r, rc)
	})
}

func (rc *reqCtx) user() string {
	if rc.p == nil {
		return ""
	}
	return rc.p.User
}

func (rc *reqCtx) source() string {
	if rc.p == nil {
		return ""
	}
	return string(rc.p.Source)
}

// allowed checks the RBAC policy for the request principal.
func (s *Server) allowed(rc *reqCtx, res rbac.Resource, act rbac.Action, object string) bool {
	if rc.p == nil {
		return false
	}
	return s.RBAC.Policy().Allowed(rc.p.Subjects(), res, act, object)
}

// authorize checks the RBAC policy and writes a 403 when denied.
func (s *Server) authorize(w http.ResponseWriter, r *http.Request, rc *reqCtx, res rbac.Resource, act rbac.Action, object string) bool {
	if s.allowed(rc, res, act, object) {
		return true
	}
	s.Metrics.AuthzDenials.WithLabelValues("portal", "rbac").Inc()
	s.auditEvent(r, rc, "rbac_denied", audit.Denied, fmt.Sprintf("%s %s %s", res, act, object))
	writeError(w, r, http.StatusForbidden, "portal_role_forbidden",
		fmt.Sprintf("Your portal role does not allow %s %s on %q", act, res, object))
	return false
}

// preCookie binds pre-login CSRF tokens of anonymous browsers.
func (s *Server) preCookieName() string {
	if *s.Config.Session.SecureCookie {
		return "__Host-mongo_portal_pre"
	}
	return "mongo_portal_pre"
}

// csrfBinding is what pre-login CSRF tokens are bound to: the principal, or
// for anonymous browsers a random per-browser cookie.
func (s *Server) csrfBinding(r *http.Request, rc *reqCtx) string {
	if rc.p != nil {
		return rc.owner
	}
	if c, err := r.Cookie(s.preCookieName()); err == nil && len(c.Value) >= 32 && len(c.Value) <= 128 {
		return "anon:" + c.Value
	}
	return ""
}

// ensurePreCookie issues the anonymous binding cookie if missing and
// returns the binding for this response.
func (s *Server) ensurePreCookie(w http.ResponseWriter, r *http.Request, rc *reqCtx) string {
	if b := s.csrfBinding(r, rc); b != "" {
		return b
	}
	v := session.NewToken()
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- HttpOnly, SameSite=Strict, Secure enforced by config
		Name: s.preCookieName(), Value: v, Path: "/", HttpOnly: true,
		Secure: *s.Config.Session.SecureCookie, SameSite: http.SameSiteStrictMode,
	})
	return "anon:" + v
}

// clientIP returns the client address for rate limiting. The OpenShift
// router appends the peer address to X-Forwarded-For, so the last entry is
// the one set by the router.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if ip := strings.TrimSpace(parts[len(parts)-1]); ip != "" {
			return ip
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// checkOrigin rejects cross-site state-changing requests.
func (s *Server) checkOrigin(r *http.Request) error {
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" {
		return errors.New("cross-site fetch")
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return nil
	}
	if s.Config.Server.PublicOrigin != "" {
		if strings.TrimSuffix(s.Config.Server.PublicOrigin, "/") != origin {
			return errors.New("origin mismatch")
		}
		return nil
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host != requestHost(r) {
		return errors.New("origin mismatch")
	}
	return nil
}

func requestHost(r *http.Request) string {
	if h := r.Header.Get("X-Forwarded-Host"); h != "" {
		return strings.TrimSpace(strings.Split(h, ",")[0])
	}
	return r.Host
}

// Pre-login CSRF tokens are HMACs bound to the principal (or the anonymous
// browser cookie) and the issue time.
func (s *Server) preauthToken(binding string, now time.Time) string {
	if binding == "" {
		return ""
	}
	ts := strconv.FormatInt(now.Unix(), 10)
	return "p1." + ts + "." + s.sign("login|"+binding+"|"+ts)
}

func (s *Server) validPreauthToken(tok, binding string) bool {
	if binding == "" {
		return false
	}
	user := binding
	parts := strings.Split(tok, ".")
	if len(parts) != 3 || parts[0] != "p1" {
		return false
	}
	ts, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return false
	}
	age := time.Since(time.Unix(ts, 0))
	if age < -time.Minute || age > 2*time.Hour {
		return false
	}
	return constantEq(parts[2], s.sign("login|"+user+"|"+parts[1]))
}

func (s *Server) sign(msg string) string {
	m := hmac.New(sha256.New, s.CSRFKey)
	m.Write([]byte(msg))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func constantEq(a, b string) bool {
	return a != "" && b != "" && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// Secure is always true except with the gated local development identity
// mode (config validation enforces this).
func (s *Server) setCookie(w http.ResponseWriter, secret string) {
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- HttpOnly and SameSite=Strict set; Secure enforced by config
		Name: s.Config.Session.CookieName, Value: secret, Path: "/",
		HttpOnly: true, Secure: *s.Config.Session.SecureCookie, SameSite: http.SameSiteStrictMode,
	})
}

func (s *Server) clearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- expiring cookie; same attributes as setCookie
		Name: s.Config.Session.CookieName, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: *s.Config.Session.SecureCookie, SameSite: http.SameSiteStrictMode,
	})
}

// statusWriter captures the response status.
type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += n
	return n, err
}

// instrument adds per-route body limits, tracing, metrics and access logs.
func (s *Server) instrument(route string, bodyLimit int64, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		if bodyLimit <= 0 {
			bodyLimit = 64 << 10
		}
		r.Body = http.MaxBytesReader(w, r.Body, bodyLimit)

		ctx := otel.GetTextMapPropagator().Extract(r.Context(), propagation.HeaderCarrier(r.Header))
		ctx, span := telemetry.Start(ctx, route, trace.WithSpanKind(trace.SpanKindServer),
			trace.WithAttributes(attribute.String("http.request.method", r.Method), attribute.String("http.route", route)))
		defer span.End()
		rc := from(r)
		rc.span = span
		r = r.WithContext(ctx)

		sw := &statusWriter{ResponseWriter: w}
		next.ServeHTTP(sw, r)
		if sw.status == 0 {
			sw.status = http.StatusOK
		}
		dur := time.Since(start)
		span.SetAttributes(attribute.Int("http.response.status_code", sw.status))
		if sw.status >= 500 {
			span.SetStatus(codes.Error, http.StatusText(sw.status))
		}
		s.Metrics.HTTPRequests.WithLabelValues(route, r.Method, strconv.Itoa(sw.status)).Inc()
		s.Metrics.HTTPDuration.WithLabelValues(route, r.Method).Observe(dur.Seconds())

		attrs := []slog.Attr{
			slog.String("request_id", rc.requestID),
			slog.String("method", r.Method),
			slog.String("route", route),
			slog.Int("status", sw.status),
			slog.Int64("duration_ms", dur.Milliseconds()),
			slog.Int("bytes", sw.bytes),
		}
		if sc := span.SpanContext(); sc.HasTraceID() {
			attrs = append(attrs, slog.String("trace_id", sc.TraceID().String()))
		}
		if rc.p != nil {
			attrs = append(attrs, slog.String("sso_user", rc.p.User), slog.String("identity", string(rc.p.Source)))
		}
		s.Logger.LogAttrs(r.Context(), slog.LevelInfo, "http_request", attrs...)
	})
}

var requestIDRe = regexp.MustCompile(`^[A-Za-z0-9._-]{8,128}$`)

func (s *Server) requestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-Id")
		if !requestIDRe.MatchString(id) {
			b := make([]byte, 16)
			_, _ = rand.Read(b)
			id = hex.EncodeToString(b)
		}
		w.Header().Set("X-Request-Id", id)
		rc := &reqCtx{requestID: id}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), reqKey, rc)))
	})
}

func (s *Server) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				if v == http.ErrAbortHandler {
					panic(v)
				}
				s.Logger.Error("panic serving request", "panic", fmt.Sprint(v), "stack", string(debug.Stack()))
				writeError(w, r, http.StatusInternalServerError, "internal_error", "An internal error occurred")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

const csp = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self' data:; " +
	"connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'"

func securityHeaders(hsts bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", csp)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
		if hsts {
			h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			h.Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

type apiError struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"requestId,omitempty"`
	MongoCode int32  `json:"mongoCode,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(true)
	_ = enc.Encode(v)
}

func writeError(w http.ResponseWriter, r *http.Request, status int, code, msg string) {
	writeJSON(w, status, map[string]any{"error": apiError{Code: code, Message: msg, RequestID: from(r).requestID}})
}

// decodeJSON decodes a JSON request body strictly.
func decodeJSON(w http.ResponseWriter, r *http.Request, into any) bool {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeError(w, r, http.StatusRequestEntityTooLarge, "body_too_large", "Request body is too large")
			return false
		}
		writeError(w, r, http.StatusBadRequest, "invalid_json", "Request body is not valid JSON for this endpoint")
		return false
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		writeError(w, r, http.StatusBadRequest, "invalid_json", "Request body must contain a single JSON object")
		return false
	}
	return true
}

func (s *Server) auditEvent(r *http.Request, rc *reqCtx, action, outcome, reason string) {
	e := s.baseEvent(rc, action, outcome, reason)
	e.Database, e.Collection = r.PathValue("db"), r.PathValue("coll")
	if n := r.PathValue("name"); n != "" {
		e.Target = n
	}
	s.Audit.Record(r.Context(), e)
}

// baseEvent fills the identity fields of an audit event.
func (s *Server) baseEvent(rc *reqCtx, action, outcome, reason string) audit.Event {
	e := audit.Event{RequestID: rc.requestID, Action: action, Outcome: outcome, Reason: reason, Owner: rc.owner}
	if rc.p != nil {
		e.SSOUser, e.Identity = rc.p.User, string(rc.p.Source)
		e.PortalRole = strings.Join(s.roles(rc), " ")
	}
	if rc.sess != nil {
		e.MongoUser, e.Profile = rc.sess.MongoUser+"@"+rc.sess.AuthSource, rc.sess.Profile
	}
	return e
}

// OpsHandler serves health, readiness and metrics on the ops listener.
func OpsHandler(ready func() bool, metricsHandler http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "ok\n")
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		if !ready() {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(w, "not ready\n")
			return
		}
		_, _ = io.WriteString(w, "ready\n")
	})
	mux.Handle("GET /metrics", metricsHandler)
	return mux
}
