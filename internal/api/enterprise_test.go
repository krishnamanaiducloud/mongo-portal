package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/krishnamanaiducloud/mongo-portal/internal/audit"
	"github.com/krishnamanaiducloud/mongo-portal/internal/config"
	"github.com/krishnamanaiducloud/mongo-portal/internal/mongoconn"
	"github.com/krishnamanaiducloud/mongo-portal/internal/testidp"
)

// mongoOIDCHarness configures the "primary" profile for MONGODB-OIDC with a
// test identity provider. The fake Connect behaves like the driver: it asks
// the OIDC callback for a token, passing the server's IdP info.
func mongoOIDCHarness(t *testing.T, serverIssuer *string) (*harness, *testidp.IdP, func() *http.Client) {
	t.Helper()
	idp, srv, ca := startIdP(t)
	idp.ClientID, idp.AccessAudience = "mongo-client", "mongodb-audience"
	h := newHarness(t, func(c *config.Config) {
		p := &c.Profiles[0]
		p.AuthMechanisms = append(p.AuthMechanisms, config.MechanismOIDC)
		p.OIDC = &config.MongoOIDCConfig{Issuer: srv.URL, ClientID: "mongo-client", Scopes: []string{"openid", "offline_access"},
			CAFile: ca, AllowedHosts: []string{"127.0.0.1"}, RequestTimeout: 5 * time.Second, DisplayName: "Corporate IdP"}
		c.Server.PublicOrigin = "https://portal.apps.example.com"
	})
	h.srv.Connect = func(ctx context.Context, p *config.Profile, c mongoconn.Credentials, hk mongoconn.PoolHooks) (*mongoconn.ConnectResult, error) {
		h.calls++
		if c.Mechanism != config.MechanismOIDC || c.OIDC == nil || c.Password != "" {
			return nil, &mongoconn.Error{Kind: mongoconn.KindAuthFailed, Msg: "Authentication failed"}
		}
		iss := srv.URL
		if serverIssuer != nil {
			iss = *serverIssuer
		}
		cred, err := c.OIDC.Callback(ctx, &options.OIDCArgs{Version: 1, IDPInfo: &options.IDPInfo{Issuer: iss, ClientID: "mongo-client"}})
		if err != nil {
			return nil, err
		}
		if cred.AccessToken == "" {
			return nil, &mongoconn.Error{Kind: mongoconn.KindAuthFailed, Msg: "no token"}
		}
		client, err := mongo.Connect(options.Client().ApplyURI(p.URI).SetServerSelectionTimeout(200 * time.Millisecond))
		if err != nil {
			return nil, err
		}
		st := &mongoconn.ConnectionStatus{}
		st.AuthInfo.AuthenticatedUsers = []mongoconn.UserRef{{User: "testidp/" + idp.User.Subject, DB: "$external"}}
		return &mongoconn.ConnectResult{Client: client, Status: st, Mechanism: config.MechanismOIDC, User: "testidp/" + idp.User.Subject, AuthSource: "$external"}, nil
	}
	return h, idp, srv.Client
}

func mongoOIDCConnect(t *testing.T, h *harness, client func() *http.Client, opts ...reqOpt) *http.Response {
	t.Helper()
	w := h.do("GET", "/oauth/mongodb/primary/start?return=%2Fshell", nil, opts...)
	if w.Code != http.StatusFound {
		t.Fatalf("start: %d %s", w.Code, w.Header().Get("Location"))
	}
	auth, _ := url.Parse(w.Header().Get("Location"))
	q := auth.Query()
	if q.Get("client_id") != "mongo-client" || q.Get("code_challenge_method") != "S256" || q.Get("redirect_uri") != "https://portal.apps.example.com/oauth/mongodb/callback" ||
		!strings.Contains(q.Get("scope"), "offline_access") {
		t.Fatalf("authorize params: %v", q)
	}
	state := cookieNamed(w, "__Host-mongo_portal_oauth")
	c := client()
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := c.Get(auth.String())
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	cb, _ := url.Parse(resp.Header.Get("Location"))
	out := h.do("GET", cb.Path+"?"+cb.RawQuery, nil, append(opts, withCookie(state))...)
	return out.Result()
}

func TestMongoDBOIDCConnect(t *testing.T) {
	h, idp, client := mongoOIDCHarness(t, nil)

	prof := decode(t, h.do("GET", "/api/v1/profiles", nil))["profiles"].([]any)[0].(map[string]any)
	if o, _ := prof["oidc"].(map[string]any); o == nil || o["url"] != "/oauth/mongodb/primary/start" || o["displayName"] != "Corporate IdP" {
		t.Fatalf("profile oidc: %v", prof)
	}

	// An SSO user connects to MongoDB with the token of the MongoDB IdP;
	// no password is involved.
	res := mongoOIDCConnect(t, h, client, as("dana", "devs"))
	if res.StatusCode != http.StatusFound || res.Header.Get("Location") != "/shell" {
		t.Fatalf("callback: %d %s", res.StatusCode, res.Header.Get("Location"))
	}
	var sc *http.Cookie
	for _, c := range res.Cookies() {
		if c.Name == "__Host-mongo_portal_session" {
			sc = c
		}
	}
	if sc == nil {
		t.Fatal("no session cookie")
	}
	sess := decode(t, h.do("GET", "/api/v1/session", nil, as("dana", "devs"), withCookie(sc)))
	if sess["mechanism"] != config.MechanismOIDC || sess["mongoUser"] != "testidp/u-1001" || sess["authSource"] != "$external" {
		t.Fatalf("session: %v", sess)
	}
	if !slices.Contains(roles(map[string]any{"roles": sess["portalRoles"]}), "role:readonly") {
		t.Fatalf("the SSO principal keeps its portal roles: %v", sess["portalRoles"])
	}

	// The driver asks for a refresh (MongoDB rejected the token): the
	// refresh token is used.
	h.srv.Store.All()[0].OIDC.Callback(context.Background(), &options.OIDCArgs{Version: 1, RefreshToken: new(string)})
	if idp.Refreshed != 1 {
		t.Fatalf("refreshes: %d", idp.Refreshed)
	}

	// Without SSO the MongoDB user named by the server is the principal.
	res = mongoOIDCConnect(t, h, client)
	if res.StatusCode != http.StatusFound {
		t.Fatalf("anonymous callback: %d", res.StatusCode)
	}

	// The password endpoint does not accept MONGODB-OIDC.
	tok := h.preauth("dana", "devs")
	w := h.do("POST", "/api/v1/session", map[string]string{"profile": "primary", "mechanism": config.MechanismOIDC},
		as("dana", "devs"), withHeader("X-CSRF-Token", tok))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("password endpoint with OIDC: %d", w.Code)
	}
}

// A deployment that trusts another identity provider is reported clearly
// and never receives the token.
func TestMongoDBOIDCProviderMismatch(t *testing.T) {
	other := "https://other-idp.example.com"
	h, _, client := mongoOIDCHarness(t, &other)
	res := mongoOIDCConnect(t, h, client, as("dana", "devs"))
	if loc := res.Header.Get("Location"); res.StatusCode != http.StatusFound || !strings.HasPrefix(loc, "/login?mongo=mongo_oidc_failed") {
		t.Fatalf("mismatch: %d %s", res.StatusCode, loc)
	}
	if h.srv.Store.Count() != 0 {
		t.Fatal("no session may be created")
	}
	ev := h.srv.Audit.Local(audit.Filter{Action: "mongodb_login", Outcome: audit.Failure})
	if len(ev) == 0 || ev[0].Method != "mongodb-oidc" || ev[0].ErrorClass != string(mongoconn.KindOIDC) {
		t.Fatalf("audit: %+v", ev)
	}
	// A profile without OIDC refuses to start.
	if w := h.do("GET", "/oauth/mongodb/nope/start", nil); !strings.HasPrefix(w.Header().Get("Location"), "/login?mongo=oidc_not_offered") {
		t.Fatalf("unknown profile: %s", w.Header().Get("Location"))
	}
}

func TestAuditSearchExportAndScope(t *testing.T) {
	h := newHarness(t, func(c *config.Config) { c.RBAC.Policy += "\ng, auditors, role:auditor\n" })
	h.login("dana", "devs")
	tok := h.preauth("eve", "devs")
	h.do("POST", "/api/v1/session", map[string]string{"profile": "primary", "username": "eve", "password": "bad"}, as("eve", "devs"), withHeader("X-CSRF-Token", tok))

	// Own events only by default.
	m := decode(t, h.do("GET", "/api/v1/audit?action=mongodb_login", nil, as("dana", "devs")))
	ev := m["events"].([]any)
	if len(ev) != 1 || ev[0].(map[string]any)["outcome"] != "success" || m["durable"] != false {
		t.Fatalf("own events: %v", m)
	}
	e0 := ev[0].(map[string]any)
	if e0["id"] == "" || e0["hash"] == "" || e0["method"] != "mongodb" || e0["client"] == "" {
		t.Fatalf("event fields: %v", e0)
	}
	// Everyone's events need audit get all.
	if w := h.do("GET", "/api/v1/audit?scope=all", nil, as("dana", "devs")); w.Code != http.StatusForbidden {
		t.Fatalf("scope=all for a developer: %d", w.Code)
	}
	m = decode(t, h.do("GET", "/api/v1/audit?scope=all&outcome=failure&user=eve", nil, as("aud", "auditors")))
	if ev := m["events"].([]any); len(ev) != 1 || ev[0].(map[string]any)["mongoUser"] != "eve@admin" {
		t.Fatalf("auditor filter: %v", m)
	}
	// Paging with limit.
	m = decode(t, h.do("GET", "/api/v1/audit?scope=all&limit=1", nil, as("aud", "auditors")))
	if m["next"] == nil {
		t.Fatalf("expected a next page: %v", m)
	}
	// CSV export is formula-safe and itself audited.
	w := h.do("GET", "/api/v1/audit?scope=all&format=csv", nil, as("aud", "auditors"))
	body := w.Body.String()
	if w.Code != 200 || !strings.HasPrefix(body, "time,id,outcome,action") || !strings.Contains(w.Header().Get("Content-Disposition"), "attachment") {
		t.Fatalf("csv: %d %s", w.Code, body)
	}
	if got := csvSafe("=cmd|' /C calc'!A0"); !strings.HasPrefix(got, "'") {
		t.Fatalf("csvSafe: %q", got)
	}
	if ev := h.srv.Audit.Local(audit.Filter{Action: "audit_export"}); len(ev) != 1 {
		t.Fatalf("export not audited: %v", ev)
	}
	if w := h.do("GET", "/api/v1/audit?from=yesterday", nil, as("dana", "devs")); w.Code != http.StatusBadRequest {
		t.Fatalf("bad time: %d", w.Code)
	}
	// The local chain is intact.
	local := h.srv.Audit.Local(audit.Filter{Limit: 1000})
	slices.Reverse(local)
	if i := audit.VerifyChain(local); i >= 0 {
		t.Fatalf("chain broken at %d", i)
	}
	local[1].Reason = "tampered"
	if i := audit.VerifyChain(local); i != 1 {
		t.Fatalf("tampering not detected: %d", i)
	}
}

func TestAdminSessionsAndSettings(t *testing.T) {
	h := newHarness(t, func(c *config.Config) { c.RBAC.Policy += "\ng, platform, role:platform-admin\n" })
	h.login("dana", "devs")
	h.login("sam", "sres")

	if w := h.do("GET", "/api/v1/admin/sessions", nil, as("dana", "devs")); w.Code != http.StatusForbidden {
		t.Fatalf("developer admin sessions: %d", w.Code)
	}
	m := decode(t, h.do("GET", "/api/v1/admin/sessions?user=dana", nil, as("pat", "platform")))
	rows := m["sessions"].([]any)
	if len(rows) != 1 || m["source"] != "local" || m["canRevoke"] != true {
		t.Fatalf("admin list: %v", m)
	}
	owner := rows[0].(map[string]any)["owner"].(string)
	tok := h.preauth("pat", "platform")
	body, _ := json.Marshal(map[string]string{"owner": owner})
	w := h.do("POST", "/api/v1/admin/sessions/revoke", string(body), as("pat", "platform"), withHeader("X-CSRF-Token", tok), withHeader("Content-Type", "application/json"))
	if w.Code != 200 || decode(t, w)["revoked"].(float64) != 1 {
		t.Fatalf("revoke: %d %s", w.Code, w.Body)
	}
	time.Sleep(50 * time.Millisecond)
	if n := len(h.srv.Store.All()); n != 1 {
		t.Fatalf("sessions after revoke: %d", n)
	}
	if ev := h.srv.Audit.Local(audit.Filter{Action: "session_revoke"}); len(ev) != 1 || ev[0].Count != 1 {
		t.Fatalf("revoke audit: %v", ev)
	}

	if w := h.do("GET", "/api/v1/settings", nil, as("dana", "devs")); w.Code != http.StatusForbidden {
		t.Fatalf("developer settings: %d", w.Code)
	}
	w = h.do("GET", "/api/v1/settings", nil, as("pat", "platform"))
	s := w.Body.String()
	if w.Code != 200 || !strings.Contains(s, `"profiles"`) || strings.Contains(strings.ToLower(s), "password") {
		t.Fatalf("settings: %d %s", w.Code, s)
	}
}
