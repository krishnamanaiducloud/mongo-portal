package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
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

// followMongoOIDC runs a MONGODB-OIDC connection from startPath through
// the provider (with the browser's cookie jar) until the portal answers
// with something other than another sign-in step.
func followMongoOIDC(t *testing.T, h *harness, c *http.Client, startPath string, opts ...reqOpt) (*httptest.ResponseRecorder, []url.Values) {
	t.Helper()
	var asked []url.Values
	next := startPath
	for range 4 {
		w := h.do("GET", next, nil, opts...)
		auth, _ := url.Parse(w.Header().Get("Location"))
		if w.Code != http.StatusFound || auth.Host == "" {
			return w, asked
		}
		asked = append(asked, auth.Query())
		state := cookieNamed(w, "__Host-mongo_portal_oauth")
		resp, err := c.Get(auth.String())
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		cb, _ := url.Parse(resp.Header.Get("Location"))
		w = h.do("GET", cb.Path+"?"+cb.RawQuery, nil, append(slices.Clone(opts), withCookie(state))...)
		if loc := w.Header().Get("Location"); w.Code == http.StatusFound && strings.HasPrefix(loc, "/oauth/mongodb/") {
			next = loc
			continue
		}
		return w, asked
	}
	t.Fatal("too many sign-in steps")
	return nil, nil
}

// After single sign-on the portal connects to MongoDB without a password
// and, when the provider already has a browser session, without any
// interaction (prompt=none). Without a session it continues with the
// provider's sign-in page, or explains why when that is turned off.
func TestMongoDBOIDCSilentConnect(t *testing.T) {
	h, idp, client := mongoOIDCHarness(t, nil)
	po := h.srv.Config.Profiles[0].OIDC
	po.AutoConnect = true
	c := client()
	c.Jar, _ = cookiejar.New(nil)
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	prof := decode(t, h.do("GET", "/api/v1/profiles", nil))["profiles"].([]any)[0].(map[string]any)
	if o := prof["oidc"].(map[string]any); o["autoConnect"] != true {
		t.Fatalf("autoConnect not exposed: %v", o)
	}

	// No provider session yet: prompt=none is answered with login_required
	// and the portal continues interactively (one sign-in at the provider).
	w, asked := followMongoOIDC(t, h, c, "/oauth/mongodb/primary/start?return=%2Fshell&silent=1", as("dana", "devs"))
	if w.Code != http.StatusFound || w.Header().Get("Location") != "/shell" || cookieNamed(w, "__Host-mongo_portal_session") == nil {
		t.Fatalf("fallback connect: %d %s", w.Code, w.Header().Get("Location"))
	}
	if len(asked) != 2 || asked[0].Get("prompt") != "none" || asked[1].Get("prompt") != "" || idp.Interactive != 1 {
		t.Fatalf("expected a silent then an interactive request: %v (interactive %d)", asked, idp.Interactive)
	}

	// The browser now has a provider session (as after an OpenShift login
	// federated to the same provider): the next connection needs no
	// interaction at all.
	w, asked = followMongoOIDC(t, h, c, "/oauth/mongodb/primary/start?return=%2F&silent=1", as("erin", "devs"))
	if w.Header().Get("Location") != "/" || len(asked) != 1 || idp.Interactive != 1 {
		t.Fatalf("silent connect: %s, %d requests, interactive %d", w.Header().Get("Location"), len(asked), idp.Interactive)
	}
	if ev := h.srv.Audit.Local(audit.Filter{Action: "mongodb_login", Outcome: audit.Success}); len(ev) < 2 || ev[0].Method != "mongodb-oidc" {
		t.Fatalf("audit: %+v", ev)
	}

	// Interactive fallback turned off: the user is told why.
	f := false
	po.InteractiveFallback = &f
	idp.EndSessions()
	w, _ = followMongoOIDC(t, h, c, "/oauth/mongodb/primary/start?silent=1", as("dana", "devs"))
	if !strings.HasPrefix(w.Header().Get("Location"), "/login?mongo=login_required") {
		t.Fatalf("no fallback: %s", w.Header().Get("Location"))
	}

	// silent is only honoured after single sign-on.
	w = h.do("GET", "/oauth/mongodb/primary/start?silent=1", nil)
	if auth, _ := url.Parse(w.Header().Get("Location")); auth.Query().Get("prompt") != "" {
		t.Fatalf("anonymous silent request: %s", auth)
	}

	// Extra authorization parameters reach the provider.
	po.AuthParams = map[string]string{"audience": "mongodb-audience"}
	w = h.do("GET", "/oauth/mongodb/primary/start", nil, as("dana", "devs"))
	if auth, _ := url.Parse(w.Header().Get("Location")); auth.Query().Get("audience") != "mongodb-audience" {
		t.Fatalf("authParams: %s", auth)
	}
}

// A token for another audience never reaches MongoDB, and the reason is
// precise.
func TestMongoDBOIDCTokenChecks(t *testing.T) {
	h, _, client := mongoOIDCHarness(t, nil)
	h.srv.Config.Profiles[0].OIDC.Audience = "another-audience"
	res := mongoOIDCConnect(t, h, client, as("dana", "devs"))
	if loc := res.Header.Get("Location"); !strings.HasPrefix(loc, "/login?mongo=token_audience_mismatch") || h.calls != 0 {
		t.Fatalf("audience mismatch: %s (connect calls %d)", loc, h.calls)
	}
	ev := h.srv.Audit.Local(audit.Filter{Action: "mongodb_login", Outcome: audit.Failure})
	if len(ev) == 0 || ev[0].ErrorClass != "token_audience_mismatch" || !strings.Contains(ev[0].Reason, "another-audience") {
		t.Fatalf("audit: %+v", ev)
	}

	for name, c := range map[string]struct{ tok, iss, aud, want string }{
		"opaque":          {"opaque-reference-token", "https://idp", "", "token_not_jwt"},
		"wrong issuer":    {jwtWith(`{"iss":"https://sts.example/v1","aud":"m"}`), "https://idp", "", "token_issuer_mismatch"},
		"wrong audience":  {jwtWith(`{"iss":"https://idp/","aud":["a","b"]}`), "https://idp", "m", "token_audience_mismatch"},
		"audience listed": {jwtWith(`{"iss":"https://idp","aud":["a","m"]}`), "https://idp", "m", ""},
		"no audience set": {jwtWith(`{"iss":"https://idp","aud":"x"}`), "https://idp", "", ""},
	} {
		got := mongoconn.CheckAccessToken(c.tok, c.iss, c.aud)
		if (got == nil) != (c.want == "") || (got != nil && got.Code != c.want) {
			t.Errorf("%s: %+v, want %q", name, got, c.want)
		}
	}
}

func TestCacheManagement(t *testing.T) {
	h := newHarness(t, func(c *config.Config) { c.RBAC.Policy += "\ng, platform, role:platform-admin\n" })
	if w := h.do("GET", "/api/v1/admin/caches", nil, as("dana", "devs")); w.Code != http.StatusForbidden {
		t.Fatalf("readonly user listing caches: %d", w.Code)
	}
	m := decode(t, h.do("GET", "/api/v1/admin/caches", nil, as("pat", "platform")))
	caches, _ := m["caches"].([]any)
	if len(caches) != 5 || m["canInvalidate"] != true || m["shared"] != false {
		t.Fatalf("cache listing: %v", m)
	}
	tok := h.preauth("pat", "platform")
	body := map[string]any{"caches": []string{"rbac-policy", "mongodb-oidc-providers", "identities"}, "confirm": "nope"}
	if w := h.do("POST", "/api/v1/admin/caches/invalidate", body, as("pat", "platform"), withHeader("X-CSRF-Token", tok)); w.Code != http.StatusPreconditionRequired {
		t.Fatalf("unconfirmed: %d", w.Code)
	}
	body["confirm"], body["caches"] = "invalidate", []string{"wiredtiger"}
	if w := h.do("POST", "/api/v1/admin/caches/invalidate", body, as("pat", "platform"), withHeader("X-CSRF-Token", tok)); w.Code != http.StatusBadRequest {
		t.Fatalf("unknown cache: %d", w.Code)
	}
	h.srv.midp.m = map[string]*mongoIdP{"primary": {at: time.Now()}}
	body["caches"] = []string{"rbac-policy", "mongodb-oidc-providers", "identities"}
	w := h.do("POST", "/api/v1/admin/caches/invalidate", body, as("pat", "platform"), withHeader("X-CSRF-Token", tok))
	m = decode(t, w)
	if w.Code != 200 || len(m["results"].([]any)) != 3 || !strings.Contains(m["note"].(string), "this replica only") || h.srv.midp.m != nil {
		t.Fatalf("invalidate: %d %v", w.Code, m)
	}
	if _, at := h.srv.Identity.ReviewCacheStats(); at.IsZero() {
		t.Fatal("identity revalidation not requested")
	}
	ev := h.srv.Audit.Local(audit.Filter{Action: "cache_invalidate"})
	if len(ev) != 1 || ev[0].SSOUser != "pat" || !strings.Contains(ev[0].Target, "rbac-policy") {
		t.Fatalf("audit: %+v", ev)
	}
}

// Under role:mongodb, cache management follows MongoDB: users whose MongoDB
// account administers the deployment get it, others do not; a user mapped
// to another role does not; an explicit deny wins.
func TestCacheFollowsMongoDBClusterAdmin(t *testing.T) {
	for _, tc := range []struct {
		name, user, groups, policy string
		clusterAdmin, want         bool
	}{
		{"cluster admin on role:mongodb", "olive", "others", "", true, true},
		{"data admin only", "pete", "others", "", false, false},
		{"cluster admin mapped to readonly", "dana", "devs", "", true, false},
		{"explicit deny", "olive", "others", "p, role:mongodb, cache, *, *, deny\n", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, func(c *config.Config) { c.RBAC.Policy += "\n" + tc.policy })
			connect := h.srv.Connect
			h.srv.Connect = func(ctx context.Context, p *config.Profile, c mongoconn.Credentials, hk mongoconn.PoolHooks) (*mongoconn.ConnectResult, error) {
				res, err := connect(ctx, p, c, hk)
				if err == nil {
					any := ""
					actions := []string{"listDatabases", "serverStatus"}
					if tc.clusterAdmin {
						actions = append(actions, "replSetConfigure")
					}
					res.Status.AuthInfo.Privileges = []mongoconn.Privilege{
						{Resource: mongoconn.Resource{Cluster: true}, Actions: actions},
						{Resource: mongoconn.Resource{DB: &any, Collection: &any}, Actions: []string{"find", "insert", "createIndex", "dropDatabase"}},
					}
				}
				return res, err
			}
			if decode(t, h.do("GET", "/api/v1/me", nil, as(tc.user, tc.groups)))["permissions"].(map[string]any)["cache:get"] != false {
				t.Fatal("without a MongoDB session there is no MongoDB privilege to follow")
			}
			sc, csrf := h.login(tc.user, tc.groups)
			perms := decode(t, h.do("GET", "/api/v1/me", nil, as(tc.user, tc.groups), withCookie(sc)))["permissions"].(map[string]any)
			if perms["cache:get"] != tc.want || perms["cache:delete"] != tc.want {
				t.Fatalf("permission hints: %v", perms)
			}
			want := http.StatusForbidden
			if tc.want {
				want = http.StatusOK
			}
			if w := h.do("GET", "/api/v1/admin/caches", nil, as(tc.user, tc.groups), withCookie(sc)); w.Code != want {
				t.Fatalf("list caches: %d", w.Code)
			}
			w := h.do("POST", "/api/v1/admin/caches/invalidate", map[string]any{"caches": []string{"rbac-policy"}, "confirm": "invalidate"},
				as(tc.user, tc.groups), withCookie(sc), withHeader("X-CSRF-Token", csrf))
			if w.Code != want {
				t.Fatalf("invalidate: %d %s", w.Code, w.Body)
			}
		})
	}
}

// Import and export need MongoDB write privileges on the collection
// (transfer.requireWritePrivilege, default on); the setting can be turned off.
func TestTransferNeedsWritePrivilege(t *testing.T) {
	for _, tc := range []struct {
		name          string
		requireWrite  *bool
		mongoActions  []string
		wantBlocked   bool
		wantPermsHint bool
	}{
		{"read-only MongoDB user", nil, []string{"find", "listCollections"}, true, false},
		{"MongoDB user that writes", nil, []string{"find", "insert", "update", "remove"}, false, true},
		{"read-only, requirement turned off", new(false), []string{"find"}, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, func(c *config.Config) { c.Transfer.RequireWritePrivilege = tc.requireWrite })
			connect := h.srv.Connect
			h.srv.Connect = func(ctx context.Context, p *config.Profile, c mongoconn.Credentials, hk mongoconn.PoolHooks) (*mongoconn.ConnectResult, error) {
				res, err := connect(ctx, p, c, hk)
				if err == nil {
					db, coll := "app", ""
					res.Status.AuthInfo.Privileges = []mongoconn.Privilege{{Resource: mongoconn.Resource{DB: &db, Collection: &coll}, Actions: tc.mongoActions}}
				}
				return res, err
			}
			sc, csrf := h.login("olive", "others") // role:mongodb (unmapped)
			perms := decode(t, h.do("GET", "/api/v1/me", nil, as("olive", "others"), withCookie(sc)))["permissions"].(map[string]any)
			if perms["export:create"] != tc.wantPermsHint || perms["import:create"] != tc.wantPermsHint {
				t.Fatalf("permission hints: export %v import %v", perms["export:create"], perms["import:create"])
			}
			blocked := func(w *httptest.ResponseRecorder) bool {
				return w.Code == http.StatusForbidden && strings.Contains(w.Body.String(), "write_privilege_required")
			}
			for _, w := range []*httptest.ResponseRecorder{
				h.do("GET", "/api/v1/databases/app/collections/orders/export", nil, as("olive", "others"), withCookie(sc)),
				h.do("GET", "/api/v1/databases/app/export?format=ndjson", nil, as("olive", "others"), withCookie(sc)),
				h.do("POST", "/api/v1/databases/app/collections/orders/import?format=ndjson", map[string]any{"x": 1}, as("olive", "others"), withCookie(sc), withHeader("X-CSRF-Token", csrf)),
				h.do("POST", "/api/v1/databases/app/collections/orders/import/preview?format=ndjson", map[string]any{"x": 1}, as("olive", "others"), withCookie(sc), withHeader("X-CSRF-Token", csrf)),
			} {
				if blocked(w) != tc.wantBlocked {
					t.Fatalf("blocked=%v: %d %s", blocked(w), w.Code, w.Body)
				}
			}
			if tc.wantBlocked {
				if ev := h.srv.Audit.Local(audit.Filter{Action: "rbac_denied"}); len(ev) == 0 || !strings.Contains(ev[0].Reason, "write privileges") {
					t.Fatalf("denial not audited: %+v", ev)
				}
			}
		})
	}
}

func jwtWith(claims string) string {
	return "eyJhbGciOiJSUzI1NiJ9." + base64.RawURLEncoding.EncodeToString([]byte(claims)) + ".c2ln"
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
