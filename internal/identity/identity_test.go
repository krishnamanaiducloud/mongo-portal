package identity

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/krishnamanaiducloud/mongo-portal/internal/config"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

var testKey = []byte("0123456789abcdef0123456789abcdef")

// fakeOpenShift is an API server and OAuth server in one TLS endpoint.
type fakeOpenShift struct {
	srv        *httptest.Server
	caFile     string
	tokenFile  string
	discovery  atomic.Int32 // HTTP status for discovery (0 = 200)
	basicFails atomic.Bool  // reject client credentials sent with HTTP Basic
	users      map[string]string
	groups     map[string][]string
	exchanges  atomic.Int32
}

func newFakeOpenShift(t *testing.T) *fakeOpenShift {
	t.Helper()
	f := &fakeOpenShift{
		users:  map[string]string{"tok-alice": "alice", "tok-bob": "bob"},
		groups: map[string][]string{"alice": {"sres", "system:authenticated", "unrelated"}, "bob": {"devs"}},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		if s := f.discovery.Load(); s != 0 {
			w.WriteHeader(int(s))
			return
		}
		u := f.srv.URL
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": u, "authorization_endpoint": u + "/oauth/authorize", "token_endpoint": u + "/oauth/token",
			"code_challenge_methods_supported": []string{"plain", "S256"},
		})
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") })
	mux.HandleFunc("POST /oauth/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		id, secret, basic := r.BasicAuth()
		if basic {
			if f.basicFails.Load() {
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_client"})
				return
			}
			id, _ = url.QueryUnescape(id)
			secret, _ = url.QueryUnescape(secret)
		} else {
			id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
		}
		if id != "system:serviceaccount:ns1:mongo-portal" || secret == "" {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_client"})
			return
		}
		f.exchanges.Add(1)
		if r.PostForm.Get("code") != "good-code" || r.PostForm.Get("code_verifier") != "verifier" {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "tok-alice", "token_type": "Bearer", "expires_in": 3600})
	})
	mux.HandleFunc("GET /apis/user.openshift.io/v1/users/~", func(w http.ResponseWriter, r *http.Request) {
		user, ok := f.users[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"metadata": map[string]string{"name": user}, "groups": f.groups[user]})
	})
	f.srv = httptest.NewTLSServer(mux)
	t.Cleanup(f.srv.Close)

	dir := t.TempDir()
	f.caFile = filepath.Join(dir, "ca.crt")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.srv.Certificate().Raw})
	if err := os.WriteFile(f.caFile, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	f.tokenFile = filepath.Join(dir, "token")
	claims, _ := json.Marshal(map[string]string{"sub": "system:serviceaccount:ns1:mongo-portal"})
	jwt := "eyJhbGciOiJSUzI1NiJ9." + base64.RawURLEncoding.EncodeToString(claims) + ".sig"
	if err := os.WriteFile(f.tokenFile, []byte(jwt), 0o600); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *fakeOpenShift) config(enabled string) config.OpenShiftConfig {
	return config.OpenShiftConfig{
		Enabled: enabled, APIURL: f.srv.URL, CAFile: f.caFile, ServiceAccountFile: f.tokenFile,
		Scopes: []string{"user:info"}, ProbeInterval: time.Minute, RevalidateInterval: 5 * time.Minute,
		MaxStale: time.Hour, RequestTimeout: 10 * time.Second, // generous: the race detector on a busy machine
	}
}

func TestOpenShiftLoginFlow(t *testing.T) {
	f := newFakeOpenShift(t)
	o := NewOpenShift(f.config(config.EnabledAuto), quiet)
	if st := o.Probe(context.Background()); st.State != StateAvailable {
		t.Fatalf("probe: %+v", st)
	}
	u, err := o.AuthCodeURL("st", "challenge", "https://portal.example/oauth/callback")
	if err != nil {
		t.Fatal(err)
	}
	q, _ := url.ParseQuery(u[strings.Index(u, "?")+1:])
	if q.Get("client_id") != "system:serviceaccount:ns1:mongo-portal" || q.Get("code_challenge_method") != "S256" ||
		q.Get("state") != "st" || q.Get("scope") != "user:info" || q.Get("redirect_uri") != "https://portal.example/oauth/callback" {
		t.Fatalf("authorize url: %s", u)
	}

	tok, ttl, err := o.Exchange(context.Background(), "good-code", "verifier", "https://portal.example/oauth/callback")
	if err != nil || tok != "tok-alice" || ttl != time.Hour {
		t.Fatalf("exchange: %q %v %v", tok, ttl, err)
	}
	if _, _, err := o.Exchange(context.Background(), "bad-code", "verifier", "x"); err != ErrUnauthenticated {
		t.Fatalf("bad code: %v", err)
	}
	// Servers that reject Basic client credentials get them in the body.
	f.basicFails.Store(true)
	if tok, _, err := o.Exchange(context.Background(), "good-code", "verifier", "x"); err != nil || tok != "tok-alice" {
		t.Fatalf("fallback to body credentials: %q %v", tok, err)
	}

	user, groups, err := o.Review(context.Background(), "tok-alice")
	if err != nil || user != "alice" || len(groups) != 3 {
		t.Fatalf("review: %q %v %v", user, groups, err)
	}
	if _, _, err := o.Review(context.Background(), "tok-unknown"); err != ErrUnauthenticated {
		t.Fatalf("unknown token: %v", err)
	}
}

// Passive behaviour: every unavailable situation is a status, never an error.
func TestOpenShiftPassiveStates(t *testing.T) {
	f := newFakeOpenShift(t)

	cfg := f.config(config.EnabledAuto)
	cfg.ServiceAccountFile = filepath.Join(t.TempDir(), "missing")
	if st := NewOpenShift(cfg, quiet).Probe(context.Background()); st.State != StateDisabled {
		t.Errorf("no token (auto): %+v", st)
	}
	cfg.Enabled = config.EnabledTrue
	if st := NewOpenShift(cfg, quiet).Probe(context.Background()); st.State != StateUnavailable {
		t.Errorf("no token (true): %+v", st)
	}

	f.discovery.Store(http.StatusNotFound)
	if st := NewOpenShift(f.config(config.EnabledAuto), quiet).Probe(context.Background()); st.State != StateDisabled {
		t.Errorf("plain Kubernetes: %+v", st)
	}
	f.discovery.Store(http.StatusServiceUnavailable)
	if st := NewOpenShift(f.config(config.EnabledAuto), quiet).Probe(context.Background()); st.State != StateUnavailable {
		t.Errorf("discovery failing: %+v", st)
	}
	f.discovery.Store(0)

	cfg = f.config(config.EnabledAuto)
	cfg.APIURL = "https://127.0.0.1:1"
	o := NewOpenShift(cfg, quiet)
	if st := o.Probe(context.Background()); st.State != StateUnavailable || st.Reason == "" {
		t.Errorf("unreachable API: %+v", st)
	}
	if _, err := o.AuthCodeURL("s", "c", "r"); err != ErrUnavailable {
		t.Errorf("login while unavailable: %v", err)
	}

	cfg = f.config(config.EnabledAuto)
	cfg.CAFile = filepath.Join(t.TempDir(), "missing-ca") // untrusted server certificate
	if st := NewOpenShift(cfg, quiet).Probe(context.Background()); st.State != StateUnavailable {
		t.Errorf("untrusted certificate must not be accepted: %+v", st)
	}

	if st := NewOpenShift(f.config(config.EnabledFalse), quiet).Probe(context.Background()); st.State != StateDisabled {
		t.Errorf("disabled: %+v", st)
	}
}

func newTestResolver(t *testing.T, f *fakeOpenShift, mutate func(*config.IdentityConfig)) *Resolver {
	t.Helper()
	ic := config.IdentityConfig{TrustedProxyCIDRs: []string{"127.0.0.1/32"}, OpenShift: f.config(config.EnabledAuto)}
	ic.Header.UserHeader, ic.Header.GroupsHeader = "X-Forwarded-User", "X-Forwarded-Groups"
	if mutate != nil {
		mutate(&ic)
	}
	r, err := NewResolver(Options{Config: ic, Key: testKey, SecureCookie: true, MaxAge: 8 * time.Hour,
		KeepGroup: func(g string) bool { return g == "sres" || g == "devs" }, Logger: quiet})
	if err != nil {
		t.Fatal(err)
	}
	r.OpenShift.Probe(context.Background())
	return r
}

func cookieFrom(t *testing.T, w *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, c := range w.Result().Cookies() {
		if c.Name == SSOCookieName {
			return c
		}
	}
	return nil
}

func TestResolverSSOCookieLifecycle(t *testing.T) {
	f := newFakeOpenShift(t)
	r := newTestResolver(t, f, nil)
	clock := time.Now()
	r.now = func() time.Time { return clock }

	w := httptest.NewRecorder()
	r.SignIn(w, "alice", []string{"sres", "unrelated", "system:authenticated"}, "tok-alice", time.Hour)
	c := cookieFrom(t, w)
	if c == nil || !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteStrictMode {
		t.Fatalf("cookie attributes: %+v", c)
	}
	if strings.Contains(c.Value, "tok-alice") || strings.Contains(c.Value, "alice") {
		t.Fatal("sso cookie must be encrypted")
	}

	req := httptest.NewRequest("GET", "/api/v1/me", nil)
	req.AddCookie(c)
	p := r.Resolve(httptest.NewRecorder(), req)
	if p == nil || p.User != "alice" || p.Source != SourceOpenShift || len(p.Groups) != 1 || p.Groups[0] != "sres" {
		t.Fatalf("principal: %+v", p)
	}

	// Revalidation picks up group changes.
	f.groups["alice"] = []string{"devs"}
	clock = clock.Add(6 * time.Minute)
	rw := httptest.NewRecorder()
	p = r.Resolve(rw, req)
	if p == nil || len(p.Groups) != 1 || p.Groups[0] != "devs" || cookieFrom(t, rw) == nil {
		t.Fatalf("revalidated principal: %+v", p)
	}

	// API unreachable: keep the sign-in until MaxStale, then drop it.
	req2 := httptest.NewRequest("GET", "/", nil)
	req2.AddCookie(cookieFrom(t, rw))
	f.srv.Close()
	clock = clock.Add(10 * time.Minute)
	r.cache = map[[32]byte]reviewEntry{}
	if p := r.Resolve(httptest.NewRecorder(), req2); p == nil {
		t.Fatal("transient API outage must not sign users out")
	}
	clock = clock.Add(2 * time.Hour)
	if p := r.Resolve(httptest.NewRecorder(), req2); p != nil {
		t.Fatal("sign-in must expire after maxStale without revalidation")
	}
}

func TestResolverRevokedToken(t *testing.T) {
	f := newFakeOpenShift(t)
	r := newTestResolver(t, f, nil)
	clock := time.Now()
	r.now = func() time.Time { return clock }
	w := httptest.NewRecorder()
	r.SignIn(w, "alice", []string{"sres"}, "tok-alice", time.Hour)
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(cookieFrom(t, w))
	delete(f.users, "tok-alice")
	clock = clock.Add(6 * time.Minute)
	rw := httptest.NewRecorder()
	if p := r.Resolve(rw, req); p != nil {
		t.Fatal("revoked token must sign the user out")
	}
	if c := cookieFrom(t, rw); c == nil || c.MaxAge >= 0 {
		t.Fatal("revoked sign-in must clear the cookie")
	}
}

func TestResolverRejectsTamperedCookie(t *testing.T) {
	f := newFakeOpenShift(t)
	r := newTestResolver(t, f, nil)
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: SSOCookieName, Value: "v1.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"})
	if p := r.Resolve(httptest.NewRecorder(), req); p != nil {
		t.Fatal("forged cookie accepted")
	}
	// A cookie sealed with another key is rejected too.
	other, _ := NewSealer([]byte("ffffffffffffffffffffffffffffffff"), "sso")
	v, _ := other.Seal(ssoClaims{User: "mallory", Token: "x", Validated: time.Now().Unix(), Expires: time.Now().Add(time.Hour).Unix()}, time.Now().Add(time.Hour))
	req = httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: SSOCookieName, Value: v})
	if p := r.Resolve(httptest.NewRecorder(), req); p != nil {
		t.Fatal("cookie from another key accepted")
	}
}

func TestHeaderSource(t *testing.T) {
	f := newFakeOpenShift(t)
	r := newTestResolver(t, f, func(c *config.IdentityConfig) { c.Header.Enabled = true })
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("X-Forwarded-User", "carol")
	req.Header.Set("X-Forwarded-Groups", "devs, sres,devs")
	p := r.Resolve(httptest.NewRecorder(), req)
	if p == nil || p.User != "carol" || p.Source != SourceHeader || len(p.Groups) != 2 {
		t.Fatalf("header principal: %+v", p)
	}
	req.RemoteAddr = "10.0.0.9:1234"
	if p := r.Resolve(httptest.NewRecorder(), req); p != nil {
		t.Fatal("headers from an untrusted peer must be ignored")
	}
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("X-Forwarded-User", "bad\nname")
	if p := r.Resolve(httptest.NewRecorder(), req); p != nil {
		t.Fatal("invalid user name accepted")
	}
}

func TestPrincipalSubjectsAndKeys(t *testing.T) {
	sso := &Principal{User: "alice", Groups: []string{"sres"}, Source: SourceOpenShift}
	mdb := MongoDBPrincipal("alice", "admin")
	if sso.Key() == mdb.Key() {
		t.Fatal("SSO and MongoDB principals of the same name must not share sessions")
	}
	got := strings.Join(sso.Subjects(), ",")
	if got != "alice,user:alice,sres,group:sres" {
		t.Fatalf("sso subjects: %s", got)
	}
	if got := strings.Join(mdb.Subjects(), ","); got != "mongodb:alice@admin,mongodb:alice" {
		t.Fatalf("mongodb subjects: %s", got)
	}
	if mdb.SSO() || !sso.SSO() {
		t.Fatal("SSO flag")
	}
}

func TestSealer(t *testing.T) {
	s, err := NewSealer(testKey, "a")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	v, _ := s.Seal(map[string]string{"k": "v"}, now.Add(time.Minute))
	var out map[string]string
	if err := s.Open(v, &out, now); err != nil || out["k"] != "v" {
		t.Fatalf("open: %v %v", out, err)
	}
	if err := s.Open(v, &out, now.Add(2*time.Minute)); err == nil {
		t.Fatal("expired value accepted")
	}
	other, _ := NewSealer(testKey, "b")
	if err := other.Open(v, &out, now); err == nil {
		t.Fatal("value sealed for another purpose accepted")
	}
	if _, err := NewSealer([]byte("short"), "a"); err == nil {
		t.Fatal("short key accepted")
	}
}
