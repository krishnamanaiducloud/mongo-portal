//go:build oidc

// Package oidc tests MONGODB-OIDC end to end against a disposable MongoDB
// Enterprise server that trusts a test identity provider (started by
// run.sh). It never contacts a shared deployment.
package oidc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/krishnamanaiducloud/mongo-portal/internal/api"
	"github.com/krishnamanaiducloud/mongo-portal/internal/audit"
	"github.com/krishnamanaiducloud/mongo-portal/internal/config"
	"github.com/krishnamanaiducloud/mongo-portal/internal/identity"
	"github.com/krishnamanaiducloud/mongo-portal/internal/metrics"
	"github.com/krishnamanaiducloud/mongo-portal/internal/preflight"
	"github.com/krishnamanaiducloud/mongo-portal/internal/rbac"
	"github.com/krishnamanaiducloud/mongo-portal/internal/session"
)

const (
	issuer   = "https://idp:8443"
	clientID = "mongo-portal-test"
	mongoURI = "mongodb://mongooidc:27017/?directConnection=true"
	ca       = "/certs/ca.crt"
)

func browser(t *testing.T) *http.Client {
	t.Helper()
	pem, err := os.ReadFile(ca)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem)
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func idpControl(t *testing.T, path string) {
	t.Helper()
	resp, err := browser(t).Post(issuer+path, "text/plain", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
}

func idpStats(t *testing.T) map[string]int {
	t.Helper()
	resp, err := browser(t).Get(issuer + "/test/stats")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var m map[string]int
	_ = json.NewDecoder(resp.Body).Decode(&m)
	return m
}

type portal struct {
	t *testing.T
	h http.Handler
}

func newPortal(t *testing.T, client string) *portal {
	t.Helper()
	cfg, err := config.Parse([]byte("identity:\n  header:\n    enabled: true\nserver:\n  publicOrigin: https://portal.test\nprofiles:\n  - name: placeholder\n    uri: mongodb://x/\n    tls: {mode: disabled}\n"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Profiles = []config.Profile{entProfile(client)}
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	key := []byte("oidc-test-session-key-0123456789abcdef")
	res, _ := identity.NewResolver(identity.Options{Config: cfg.Identity, Key: key, SecureCookie: true, MaxAge: time.Hour, Logger: logger})
	rb, _ := rbac.NewStore(rbac.Source{DefaultRole: *cfg.RBAC.DefaultRole}, logger)
	st := session.NewStore(session.Options{IdleTimeout: time.Hour, AbsoluteTimeout: time.Hour, MaxPerUser: 5, MaxTotal: 100})
	t.Cleanup(st.Close)
	srv := api.New(api.Deps{Config: cfg, Identity: res, RBAC: rb, CSRFKey: key, Store: st, Audit: audit.New(logger, 100), Metrics: metrics.New(), Logger: logger})
	return &portal{t: t, h: srv.Handler()}
}

func entProfile(client string) config.Profile {
	return config.Profile{Name: "ent", DisplayName: "ent", URI: mongoURI, DefaultAuthSource: "admin", AuthMechanisms: []string{"SCRAM-SHA-256", config.MechanismOIDC},
		ReadPreference: "primary", ConnectTimeout: 5 * time.Second, ServerSelectionTimeout: 10 * time.Second, OperationTimeout: 30 * time.Second,
		MaxPoolSize: 5, MaxConnIdleTime: time.Minute, TLS: config.TLSConfig{Mode: config.TLSEnabled, CAFile: ca, MinVersion: "1.2"},
		OIDC: &config.MongoOIDCConfig{Issuer: issuer, ClientID: client, Scopes: []string{"openid", "offline_access"}, CAFile: ca,
			AllowedHosts: []string{"mongooidc"}, RequestTimeout: 10 * time.Second}}
}

// The preflight reads which provider MongoDB trusts without sending any
// token, and reports a profile configured for another client.
func TestPreflightReadsServerIdP(t *testing.T) {
	ctx := context.Background()
	cfg := &config.Config{Profiles: []config.Profile{entProfile(clientID)}}
	before := idpStats(t)["issued"]
	rep := preflight.ProfileReport(ctx, cfg, "ent", preflight.Options{Timeout: 10 * time.Second})
	checks := map[string]preflight.Result{}
	for _, r := range rep.Results {
		checks[r.Check] = r
	}
	if r := checks["MONGODB-OIDC server"]; r.Status != preflight.Pass || !strings.Contains(r.Detail, issuer) {
		t.Fatalf("server idp: %+v", rep.Results)
	}
	if r := checks["MONGODB-OIDC provider"]; r.Status != preflight.Pass {
		t.Fatalf("provider discovery: %+v", r)
	}
	if r := checks["MongoDB version"]; r.Status != preflight.Pass || !strings.Contains(r.Detail, "Enterprise") {
		t.Fatalf("version: %+v", r)
	}
	// The test PKI is short-lived: expiry may warn, verification must pass.
	if r := checks["TLS"]; r.Status == preflight.Fail || !strings.Contains(r.Detail, "verified") {
		t.Fatalf("tls: %+v", r)
	}
	if rep.Failed() {
		t.Fatalf("unexpected failures: %+v", rep.Results)
	}
	if idpStats(t)["issued"] != before {
		t.Fatal("the preflight must not obtain tokens")
	}
	cfg.Profiles[0] = entProfile("other-client")
	rep = preflight.ProfileReport(ctx, cfg, "ent", preflight.Options{Timeout: 10 * time.Second})
	for _, r := range rep.Results {
		if r.Check == "MONGODB-OIDC server" && (r.Status != preflight.Fail || !strings.Contains(r.Detail, "other-client")) {
			t.Fatalf("client mismatch: %+v", r)
		}
	}
}

func (p *portal) do(method, path string, cookies []*http.Cookie, body io.Reader, hdr ...string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, body)
	r.RemoteAddr = "127.0.0.1:40000"
	r.Header.Set("X-Forwarded-User", "dana")
	r.Header.Set("X-Forwarded-Groups", "devs")
	for _, c := range cookies {
		r.AddCookie(c)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		r.Header.Set(hdr[i], hdr[i+1])
	}
	w := httptest.NewRecorder()
	p.h.ServeHTTP(w, r)
	return w
}

// connect runs the MONGODB-OIDC browser flow and returns the callback
// response.
func (p *portal) connect() *httptest.ResponseRecorder {
	p.t.Helper()
	w := p.do("GET", "/oauth/mongodb/ent/start?return=%2F", nil, nil)
	if w.Code != http.StatusFound {
		p.t.Fatalf("start: %d %s", w.Code, w.Header().Get("Location"))
	}
	var state *http.Cookie
	for _, c := range w.Result().Cookies() {
		if strings.HasSuffix(c.Name, "_oauth") {
			state = c
		}
	}
	resp, err := browser(p.t).Get(w.Header().Get("Location"))
	if err != nil {
		p.t.Fatal(err)
	}
	resp.Body.Close()
	cb, _ := url.Parse(resp.Header.Get("Location"))
	if cb.Path != "/oauth/mongodb/callback" {
		p.t.Fatalf("idp redirect: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	return p.do("GET", cb.Path+"?"+cb.RawQuery, []*http.Cookie{state}, nil)
}

func sessionCookie(w *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range w.Result().Cookies() {
		if c.Name == "__Host-mongo_portal_session" && c.MaxAge >= 0 {
			return c
		}
	}
	return nil
}

func decode(w *httptest.ResponseRecorder) map[string]any {
	var m map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &m)
	return m
}

func TestMongoDBOIDCEndToEnd(t *testing.T) {
	idpControl(t, "/test/user?sub=u-1001")
	idpControl(t, "/test/ttl?seconds=300")
	p := newPortal(t, clientID)
	w := p.connect()
	sc := sessionCookie(w)
	if w.Code != http.StatusFound || w.Header().Get("Location") != "/" || sc == nil {
		t.Fatalf("connect: %d %s", w.Code, w.Header().Get("Location"))
	}
	sess := decode(p.do("GET", "/api/v1/session", []*http.Cookie{sc}, nil))
	if sess["mechanism"] != "MONGODB-OIDC" || sess["mongoUser"] != "testidp/u-1001" || sess["authSource"] != "$external" {
		t.Fatalf("session: %v", sess)
	}
	// MongoDB authorizes with the roles of the OIDC user: read on app.
	if w := p.do("GET", "/api/v1/databases/app/collections/orders/documents", []*http.Cookie{sc}, nil); w.Code != 200 {
		t.Fatalf("read as OIDC user: %d %s", w.Code, w.Body)
	}
	csrf, _ := sess["csrfToken"].(string)
	w = p.do("POST", "/api/v1/databases/app/collections/orders/documents", []*http.Cookie{sc}, strings.NewReader(`{"document":"{\"x\":1}"}`),
		"Content-Type", "application/json", "X-CSRF-Token", csrf)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "mongo_unauthorized") {
		t.Fatalf("write as read-only OIDC user: %d %s", w.Code, w.Body)
	}
}

// An expired access token is refreshed with the refresh token when MongoDB
// asks the driver to re-authenticate.
func TestMongoDBOIDCRefresh(t *testing.T) {
	idpControl(t, "/test/user?sub=u-1001")
	idpControl(t, "/test/ttl?seconds=15")
	defer idpControl(t, "/test/ttl?seconds=300")
	p := newPortal(t, clientID)
	sc := sessionCookie(p.connect())
	if sc == nil {
		t.Fatal("no session")
	}
	before := idpStats(t)["refreshed"]
	time.Sleep(25 * time.Second)
	// New connections and re-authentication need a fresh token.
	if w := p.do("GET", "/api/v1/databases/app/collections/orders/documents", []*http.Cookie{sc}, nil); w.Code != 200 {
		t.Fatalf("read after expiry: %d %s", w.Code, w.Body)
	}
	if after := idpStats(t)["refreshed"]; after <= before {
		t.Fatalf("no refresh happened (%d -> %d)", before, after)
	}
}

// A user MongoDB does not know is refused by MongoDB; a profile configured
// for another client is refused before the token is sent.
func TestMongoDBOIDCRefusals(t *testing.T) {
	idpControl(t, "/test/ttl?seconds=300")
	idpControl(t, "/test/user?sub=u-9999")
	defer idpControl(t, "/test/user?sub=u-1001")
	p := newPortal(t, clientID)
	if w := p.connect(); !strings.HasPrefix(w.Header().Get("Location"), "/login?mongo=mongo_rejected") || sessionCookie(w) != nil {
		t.Fatalf("unknown user: %s", w.Header().Get("Location"))
	}
	idpControl(t, "/test/user?sub=u-1001")
	other := newPortal(t, "other-client")
	if w := other.connect(); !strings.HasPrefix(w.Header().Get("Location"), "/login?mongo=mongo_oidc_failed") || sessionCookie(w) != nil {
		t.Fatalf("client mismatch: %s", w.Header().Get("Location"))
	}
}

// The acceptance path: a user signs in through OpenShift, whose OAuth
// server federates to the corporate provider (simulated here by an
// interactive sign-in of another client at the same provider, which leaves
// a provider session in the browser). The portal then connects to MongoDB
// with MONGODB-OIDC without a password and without any further interaction,
// and MongoDB enforces that identity's own privileges.
func TestSeamlessMongoDBOIDCAfterSSO(t *testing.T) {
	idpControl(t, "/test/user?sub=u-1001")
	idpControl(t, "/test/ttl?seconds=300")
	idpControl(t, "/test/end-sessions")
	b := browser(t)
	b.Jar, _ = cookiejar.New(nil)

	// 1. Corporate sign-in on behalf of the OpenShift OAuth server.
	upstream := issuer + "/authorize?" + url.Values{"client_id": {"openshift-oauth"}, "response_type": {"code"}, "scope": {"openid"},
		"redirect_uri": {"https://oauth-openshift.apps.cluster.test/oauth2callback/corporate"}, "state": {"s"},
		"code_challenge": {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"}, "code_challenge_method": {"S256"}}.Encode()
	resp, err := b.Get(upstream)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	before := idpStats(t)["interactive"]

	// 2. The portal connects automatically (silent=1 is what the UI uses
	// for profiles with autoConnect).
	p := newPortal(t, clientID)
	w := p.do("GET", "/oauth/mongodb/ent/start?return=%2F&silent=1", nil, nil)
	auth, _ := url.Parse(w.Header().Get("Location"))
	if auth.Query().Get("prompt") != "none" {
		t.Fatalf("expected a silent authorization request: %s", auth)
	}
	var state *http.Cookie
	for _, c := range w.Result().Cookies() {
		if strings.HasSuffix(c.Name, "_oauth") {
			state = c
		}
	}
	resp, err = b.Get(auth.String())
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	cb, _ := url.Parse(resp.Header.Get("Location"))
	w = p.do("GET", cb.Path+"?"+cb.RawQuery, []*http.Cookie{state}, nil)
	sc := sessionCookie(w)
	if w.Code != http.StatusFound || w.Header().Get("Location") != "/" || sc == nil {
		t.Fatalf("automatic connection: %d %s", w.Code, w.Header().Get("Location"))
	}
	if after := idpStats(t)["interactive"]; after != before {
		t.Fatalf("the MongoDB connection needed an interactive sign-in (%d -> %d)", before, after)
	}

	// 3. MongoDB authenticated the user's own identity and authorizes it.
	sess := decode(p.do("GET", "/api/v1/session", []*http.Cookie{sc}, nil))
	if id, _ := sess["identity"].(map[string]any); sess["mechanism"] != "MONGODB-OIDC" || sess["mongoUser"] != "testidp/u-1001" || id["user"] != "dana" {
		t.Fatalf("session: %v", sess)
	}
	if w := p.do("GET", "/api/v1/databases/app/collections/orders/documents", []*http.Cookie{sc}, nil); w.Code != 200 {
		t.Fatalf("read: %d %s", w.Code, w.Body)
	}
	csrf, _ := sess["csrfToken"].(string)
	w = p.do("POST", "/api/v1/databases/app/collections/orders/documents", []*http.Cookie{sc}, strings.NewReader(`{"document":"{\"x\":1}"}`),
		"Content-Type", "application/json", "X-CSRF-Token", csrf)
	if w.Code != http.StatusForbidden {
		t.Fatalf("write must be refused by MongoDB: %d %s", w.Code, w.Body)
	}

	// 4. Without a provider session the silent request is refused by the
	// provider and the portal continues with its sign-in page (never a
	// password).
	idpControl(t, "/test/end-sessions")
	w = p.do("GET", "/oauth/mongodb/ent/start?return=%2F&silent=1", nil, nil)
	for _, c := range w.Result().Cookies() {
		if strings.HasSuffix(c.Name, "_oauth") {
			state = c
		}
	}
	resp, err = browser(t).Get(w.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	cb, _ = url.Parse(resp.Header.Get("Location"))
	if cb.Query().Get("error") != "login_required" {
		t.Fatalf("provider answer without session: %s", cb)
	}
	w = p.do("GET", cb.Path+"?"+cb.RawQuery, []*http.Cookie{state}, nil)
	if loc := w.Header().Get("Location"); loc != "/oauth/mongodb/ent/start?return=%2F" {
		t.Fatalf("interactive continuation: %s", loc)
	}
}

// SCRAM keeps working on the same deployment during an OIDC migration.
func TestSCRAMAlongsideOIDC(t *testing.T) {
	p := newPortal(t, clientID)
	me := decode(p.do("GET", "/api/v1/me", nil, nil))
	pre := p.do("GET", "/api/v1/me", nil, nil).Result().Cookies()
	w := p.do("POST", "/api/v1/session", pre, strings.NewReader(`{"profile":"ent","username":"scramuser","password":"scram-pw"}`),
		"Content-Type", "application/json", "X-CSRF-Token", me["csrfToken"].(string))
	if m := decode(w); w.Code != 200 || m["mongoUser"] != "scramuser" || !strings.HasPrefix(m["mechanism"].(string), "SCRAM") {
		t.Fatalf("scram login: %d %s", w.Code, w.Body)
	}
}
