package api

import (
	"context"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/krishnamanaiducloud/mongo-portal/internal/config"
	"github.com/krishnamanaiducloud/mongo-portal/internal/identity"
	"github.com/krishnamanaiducloud/mongo-portal/internal/testidp"
)

// startIdP serves a test OpenID Connect provider over TLS and returns it
// with a CA file trusting its certificate.
func startIdP(t *testing.T) (*testidp.IdP, *httptest.Server, string) {
	t.Helper()
	srv := httptest.NewUnstartedServer(nil)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	idp := testidp.New(srv.URL, "portal-client")
	srv.Config.Handler = idp.Handler()
	ca := filepath.Join(t.TempDir(), "idp-ca.crt")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return idp, srv, ca
}

func oidcHarness(t *testing.T, issuer, ca string, mut func(*config.Config)) *harness {
	t.Helper()
	h := newHarness(t, func(c *config.Config) {
		c.Identity.Header.Enabled = false
		c.Identity.OIDC.Providers = []config.OIDCProvider{{
			Name: "corp", DisplayName: "Corporate SSO", Enabled: config.EnabledTrue, Issuer: issuer, ClientID: "portal-client",
			Scopes: []string{"openid", "profile", "email"}, UsernameClaim: "preferred_username", GroupsClaim: "groups",
			CAFile: ca, ProbeInterval: time.Minute, RequestTimeout: 5 * time.Second, LogoutRedirect: true,
		}}
		c.RBAC.Policy += "\ng, devs, role:editor\ng, idp:corp, role:readonly\n"
		c.Server.PublicOrigin = "https://portal.apps.example.com"
		if mut != nil {
			mut(c)
		}
	})
	h.srv.Identity.Provider("corp").Probe(context.Background())
	return h
}

// oidcSignIn runs start -> provider -> callback and returns the callback
// response.
func oidcSignIn(t *testing.T, h *harness, client *http.Client) *httptest.ResponseRecorder {
	t.Helper()
	w := h.do("GET", "/oauth/oidc/corp/start?return="+url.QueryEscape("/db/app"), nil)
	if w.Code != http.StatusFound {
		t.Fatalf("start: %d %s", w.Code, w.Header().Get("Location"))
	}
	state := cookieNamed(w, "__Host-mongo_portal_oauth")
	authURL, _ := url.Parse(w.Header().Get("Location"))
	q := authURL.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("nonce") == "" || q.Get("redirect_uri") != "https://portal.apps.example.com/oauth/oidc/corp/callback" ||
		!strings.Contains(q.Get("scope"), "openid") {
		t.Fatalf("authorize params: %v", q)
	}
	// The provider answers with a redirect to the callback.
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Get(authURL.String())
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	cb, _ := url.Parse(resp.Header.Get("Location"))
	return h.do("GET", cb.Path+"?"+cb.RawQuery, nil, withCookie(state))
}

func TestOIDCSignIn(t *testing.T) {
	idp, srv, ca := startIdP(t)
	h := oidcHarness(t, srv.URL, ca, nil)

	me := decode(t, h.do("GET", "/api/v1/me", nil))
	opts := me["auth"].(map[string]any)["oidc"].([]any)
	if len(opts) != 1 || opts[0].(map[string]any)["state"] != "available" || opts[0].(map[string]any)["url"] != "/oauth/oidc/corp/start" {
		t.Fatalf("oidc options: %v", opts)
	}

	w := oidcSignIn(t, h, srv.Client())
	if w.Code != http.StatusFound || w.Header().Get("Location") != "/db/app" {
		t.Fatalf("callback: %d %s", w.Code, w.Header().Get("Location"))
	}
	sso := cookieNamed(w, identity.SSOCookieName)
	if sso == nil || !sso.HttpOnly || !sso.Secure || sso.SameSite != http.SameSiteStrictMode {
		t.Fatalf("sso cookie: %+v", sso)
	}
	me = decode(t, h.do("GET", "/api/v1/me", nil, withCookie(sso)))
	if me["user"] != "alice" || me["source"] != "oidc" || !slices.Contains(roles(me), "role:editor") {
		t.Fatalf("signed-in me: %v", me)
	}
	if g := me["groups"].([]any); len(g) != 1 || g[0] != "devs" {
		t.Fatalf("groups: %v", g)
	}

	// Sign-out offers the provider's end-session URL.
	out := decode(t, h.do("POST", "/api/v1/auth/logout", nil, withCookie(sso), withHeader("X-CSRF-Token", me["csrfToken"].(string))))
	if u, _ := out["ssoLogoutURL"].(string); !strings.HasPrefix(u, srv.URL+"/logout?") || !strings.Contains(u, "client_id=portal-client") {
		t.Fatalf("logout url: %v", out)
	}

	// A user without mapped groups gets the idp:corp mapping only.
	idp.User = testidp.User{Subject: "u-2", Name: "bob", Groups: nil}
	sso = cookieNamed(oidcSignIn(t, h, srv.Client()), identity.SSOCookieName)
	me = decode(t, h.do("GET", "/api/v1/me", nil, withCookie(sso)))
	if r := roles(me); me["user"] != "bob" || !slices.Equal(r, []string{"role:readonly"}) {
		t.Fatalf("idp mapping: %v %v", me["user"], r)
	}
}

// Every token validation failure is refused with an actionable reason and
// never creates a sign-in.
func TestOIDCRejectsInvalidTokens(t *testing.T) {
	idp, srv, ca := startIdP(t)
	h := oidcHarness(t, srv.URL, ca, func(c *config.Config) {
		c.Identity.OIDC.Providers[0].RequiredGroups = []string{"devs"}
	})
	cases := []struct {
		name   string
		mut    func()
		reason string
	}{
		{"audience", func() { idp.IDAudience = "other-client" }, "audience_mismatch"},
		{"expired", func() { idp.ExpireIDToken = true }, "token_expired"},
		{"nonce", func() { idp.BadNonce = true }, "failed"},
		{"signature", func() { idp.WrongKey = true }, "failed"},
		{"group", func() { idp.User.Groups = []string{"strangers"} }, "not_in_group"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			user := idp.User
			defer func() {
				idp.IDAudience, idp.ExpireIDToken, idp.BadNonce, idp.WrongKey, idp.User = "", false, false, false, user
			}()
			c.mut()
			w := oidcSignIn(t, h, srv.Client())
			if w.Header().Get("Location") != "/login?sso="+c.reason || cookieNamed(w, identity.SSOCookieName) != nil {
				t.Fatalf("got %s, want reason %s", w.Header().Get("Location"), c.reason)
			}
		})
	}
	// A forged or replayed state is refused.
	w := h.do("GET", "/oauth/oidc/corp/callback?code=x&state=forged", nil)
	if w.Header().Get("Location") != "/login?sso=expired" {
		t.Fatalf("forged state: %s", w.Header().Get("Location"))
	}
}

// A wrong issuer or an unreachable provider makes the provider unavailable
// with a reason; nothing else fails.
func TestOIDCProviderPassive(t *testing.T) {
	idp, srv, ca := startIdP(t)
	idp.IssuerClaim = "https://somewhere.else.example"
	h := oidcHarness(t, srv.URL, ca, nil)
	st := h.srv.Identity.Provider("corp").Status()
	if st.State != identity.StateUnavailable || !strings.Contains(st.Reason, "different issuer") {
		t.Fatalf("issuer mismatch status: %+v", st)
	}
	if w := h.do("GET", "/oauth/oidc/corp/start", nil); w.Header().Get("Location") != "/login?sso=unavailable" {
		t.Fatalf("start while unavailable: %s", w.Header().Get("Location"))
	}
	srv.Close()
	h2 := oidcHarness(t, srv.URL, ca, nil)
	if st := h2.srv.Identity.Provider("corp").Status(); st.State != identity.StateUnavailable {
		t.Fatalf("outage status: %+v", st)
	}
	if w := h2.do("GET", "/api/v1/me", nil); w.Code != http.StatusOK {
		t.Fatalf("me during outage: %d", w.Code)
	}
	if w := h2.do("GET", "/api/v1/profiles", nil); w.Code != http.StatusOK {
		t.Fatalf("MongoDB login must stay available: %d", w.Code)
	}
	if w := h2.do("GET", "/oauth/oidc/nope/start", nil); w.Header().Get("Location") != "/login?sso=unknown_provider" {
		t.Fatalf("unknown provider: %s", w.Header().Get("Location"))
	}
}

// With requireSSO, an OIDC provider is a valid SSO source and MongoDB-only
// login is refused.
func TestOIDCRequireSSO(t *testing.T) {
	_, srv, ca := startIdP(t)
	h := oidcHarness(t, srv.URL, ca, func(c *config.Config) { c.Identity.RequireSSO = true })
	if w := h.do("GET", "/api/v1/profiles", nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("profiles without SSO: %d", w.Code)
	}
	sso := cookieNamed(oidcSignIn(t, h, srv.Client()), identity.SSOCookieName)
	if w := h.do("GET", "/api/v1/profiles", nil, withCookie(sso)); w.Code != http.StatusOK {
		t.Fatalf("profiles after OIDC sign-in: %d", w.Code)
	}
}
