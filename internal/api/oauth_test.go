package api

import (
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/krishnamanaiducloud/mongo-portal/internal/config"
	"github.com/krishnamanaiducloud/mongo-portal/internal/identity"
	"github.com/krishnamanaiducloud/mongo-portal/internal/rbac"
)

// fakeCluster is a minimal OpenShift API + OAuth server.
func fakeCluster(t *testing.T) (*httptest.Server, string, string) {
	t.Helper()
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": srv.URL, "authorization_endpoint": srv.URL + "/oauth/authorize", "token_endpoint": srv.URL + "/oauth/token",
			"code_challenge_methods_supported": []string{"S256"},
		})
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") })
	mux.HandleFunc("POST /oauth/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.PostForm.Get("code") != "good" || r.PostForm.Get("code_verifier") == "" || !strings.HasSuffix(r.PostForm.Get("redirect_uri"), "/oauth/callback") {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "sha256~alice", "expires_in": 86400})
	})
	mux.HandleFunc("GET /apis/user.openshift.io/v1/users/~", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer sha256~alice" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"metadata": map[string]string{"name": "alice"}, "groups": []string{"sres", "system:authenticated"}})
	})
	srv = httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.crt")
	_ = os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600)
	tok := filepath.Join(dir, "token")
	claims, _ := json.Marshal(map[string]string{"sub": "system:serviceaccount:portal:mongo-portal"})
	_ = os.WriteFile(tok, []byte("e30."+base64.RawURLEncoding.EncodeToString(claims)+".x"), 0o600)
	return srv, ca, tok
}

func cookieNamed(w *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range w.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func TestOpenShiftOAuthFlow(t *testing.T) {
	srv, ca, tok := fakeCluster(t)
	h := newHarness(t, func(c *config.Config) {
		c.Identity.Header.Enabled = false
		c.Identity.OpenShift = config.OpenShiftConfig{Enabled: config.EnabledTrue, APIURL: srv.URL, CAFile: ca, ServiceAccountFile: tok,
			Scopes: []string{"user:info"}, ProbeInterval: c.Identity.OpenShift.ProbeInterval, RevalidateInterval: c.Identity.OpenShift.RevalidateInterval,
			MaxStale: c.Identity.OpenShift.MaxStale, RequestTimeout: c.Identity.OpenShift.RequestTimeout}
		c.Server.PublicOrigin = "https://portal.apps.example.com"
	})
	if st := h.srv.Identity.OpenShift.Status(); st.State != identity.StateAvailable {
		t.Fatalf("openshift not available: %+v", st)
	}
	me := decode(t, h.do("GET", "/api/v1/me", nil))
	auth := me["auth"].(map[string]any)
	if auth["openshift"].(map[string]any)["state"] != "available" || auth["openshiftURL"] != "/oauth/start" {
		t.Fatalf("auth options: %v", auth)
	}

	start := func(ret string) (*http.Cookie, url.Values) {
		t.Helper()
		w := h.do("GET", "/oauth/start?return="+url.QueryEscape(ret), nil)
		if w.Code != http.StatusFound {
			t.Fatalf("start: %d %s", w.Code, w.Body)
		}
		loc, _ := url.Parse(w.Header().Get("Location"))
		if !strings.HasPrefix(loc.String(), srv.URL+"/oauth/authorize?") {
			t.Fatalf("authorize redirect: %s", loc)
		}
		q := loc.Query()
		if q.Get("client_id") != "system:serviceaccount:portal:mongo-portal" || q.Get("redirect_uri") != "https://portal.apps.example.com/oauth/callback" ||
			q.Get("code_challenge_method") != "S256" || q.Get("state") == "" {
			t.Fatalf("authorize params: %v", q)
		}
		c := cookieNamed(w, "__Host-mongo_portal_oauth")
		if c == nil || !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteLaxMode {
			t.Fatalf("state cookie: %+v", c)
		}
		return c, q
	}

	// Happy path.
	sc, q := start("/db/app/orders")
	w := h.do("GET", "/oauth/callback?code=good&state="+url.QueryEscape(q.Get("state")), nil, withCookie(sc))
	if w.Code != http.StatusFound || w.Header().Get("Location") != "/db/app/orders" {
		t.Fatalf("callback: %d %s", w.Code, w.Header().Get("Location"))
	}
	sso := cookieNamed(w, identity.SSOCookieName)
	if sso == nil || !sso.HttpOnly || !sso.Secure || sso.SameSite != http.SameSiteStrictMode || strings.Contains(sso.Value, "sha256~") {
		t.Fatalf("sso cookie: %+v", sso)
	}
	me = decode(t, h.do("GET", "/api/v1/me", nil, withCookie(sso)))
	if me["user"] != "alice" || me["source"] != "openshift" || !slices.Contains(roles(me), rbac.RoleAdmin) {
		t.Fatalf("signed-in me: %v", me)
	}
	// Sign out clears the SSO cookie.
	tokCSRF := me["csrfToken"].(string)
	w = h.do("POST", "/api/v1/auth/logout", nil, withCookie(sso), withHeader("X-CSRF-Token", tokCSRF))
	if c := cookieNamed(w, identity.SSOCookieName); w.Code != 200 || c == nil || c.MaxAge >= 0 {
		t.Fatalf("sign out: %d %+v", w.Code, c)
	}

	// The state is single use and must match.
	sc, q = start("/")
	if w := h.do("GET", "/oauth/callback?code=good&state=wrong", nil, withCookie(sc)); w.Header().Get("Location") != "/login?sso=failed" {
		t.Fatalf("state mismatch: %s", w.Header().Get("Location"))
	}
	if w := h.do("GET", "/oauth/callback?code=good&state="+url.QueryEscape(q.Get("state")), nil); w.Header().Get("Location") != "/login?sso=expired" {
		t.Fatalf("missing state cookie: %s", w.Header().Get("Location"))
	}
	sc, q = start("/")
	if w := h.do("GET", "/oauth/callback?error=access_denied&state="+url.QueryEscape(q.Get("state")), nil, withCookie(sc)); w.Header().Get("Location") != "/login?sso=denied" {
		t.Fatalf("denied: %s", w.Header().Get("Location"))
	}
	sc, q = start("/")
	if w := h.do("GET", "/oauth/callback?code=bad&state="+url.QueryEscape(q.Get("state")), nil, withCookie(sc)); w.Header().Get("Location") != "/login?sso=failed" || cookieNamed(w, identity.SSOCookieName) != nil {
		t.Fatalf("bad code: %s", w.Header().Get("Location"))
	}
	// Open redirects are not possible through the return path.
	for _, ret := range []string{"//evil.example", "https://evil.example", "/\\evil.example"} {
		sc, q = start(ret)
		w := h.do("GET", "/oauth/callback?code=good&state="+url.QueryEscape(q.Get("state")), nil, withCookie(sc))
		if w.Header().Get("Location") != "/" {
			t.Errorf("return %q redirected to %q", ret, w.Header().Get("Location"))
		}
	}
}
