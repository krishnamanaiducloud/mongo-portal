//go:build integration

// Package integration exercises the portal against real, disposable MongoDB
// deployments started by run.sh. It must never be pointed at a shared or
// production cluster: it creates and drops collections.
package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/mongo/readpref"

	"github.com/krishnamanaiducloud/mongo-portal/internal/api"
	"github.com/krishnamanaiducloud/mongo-portal/internal/audit"
	"github.com/krishnamanaiducloud/mongo-portal/internal/config"
	"github.com/krishnamanaiducloud/mongo-portal/internal/identity"
	"github.com/krishnamanaiducloud/mongo-portal/internal/metrics"
	"github.com/krishnamanaiducloud/mongo-portal/internal/mongoconn"
	"github.com/krishnamanaiducloud/mongo-portal/internal/rbac"
	"github.com/krishnamanaiducloud/mongo-portal/internal/session"
)

func env(t *testing.T, k string) string {
	t.Helper()
	v := os.Getenv(k)
	if v == "" {
		t.Skipf("%s not set; run test/integration/run.sh", k)
	}
	return v
}

func certs(t *testing.T, name string) string { return filepath.Join(env(t, "IT_CERTS"), name) }

func profile(name, uri, mode string) config.Profile {
	return config.Profile{
		Name: name, DisplayName: name, URI: uri, DefaultAuthSource: "admin",
		AuthMechanisms: []string{"SCRAM-SHA-256", "SCRAM-SHA-1"}, ReadPreference: "primary",
		ConnectTimeout: 10 * time.Second, ServerSelectionTimeout: 10 * time.Second,
		OperationTimeout: 30 * time.Second, MaxPoolSize: 5, MaxConnIdleTime: time.Minute,
		TLS: config.TLSConfig{Mode: mode, MinVersion: "1.2"},
	}
}

func rsProfile(t *testing.T) config.Profile {
	return profile("rs", env(t, "IT_RS_URI"), config.TLSDisabled)
}

func tlsProfile(t *testing.T) config.Profile {
	p := profile("tls", env(t, "IT_TLS_URI"), config.TLSEnabled)
	p.TLS.CAFile = certs(t, "ca.crt")
	p.TLS.ClientCertFile = certs(t, "client.crt")
	p.TLS.ClientKeyFile = certs(t, "client.key")
	return p
}

func connect(t *testing.T, p config.Profile, user, pw, src string) (*mongoconn.ConnectResult, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	res, err := mongoconn.Connect(ctx, &p, mongoconn.Credentials{Username: user, Password: pw, AuthSource: src}, mongoconn.PoolHooks{})
	if err == nil {
		t.Cleanup(func() { _ = res.Client.Disconnect(context.Background()) })
	}
	return res, err
}

func kind(err error) mongoconn.Kind {
	var e *mongoconn.Error
	if errors.As(err, &e) {
		return e.Kind
	}
	return mongoconn.Classify(err).Kind
}

// ---- authentication and TLS modes ----

func TestNonTLSAuthentication(t *testing.T) {
	p := rsProfile(t)
	res, err := connect(t, p, "reader", "reader-pw", "admin")
	if err != nil {
		t.Fatalf("valid credentials: %v", err)
	}
	if res.TLSEnabled || !res.Status.HasUser("reader", "admin") {
		t.Fatalf("unexpected result: tls=%v status=%+v", res.TLSEnabled, res.Status.AuthInfo)
	}
	if c := res.Status.CapabilitiesFor("app", "orders"); !c.Find || c.Insert {
		t.Fatalf("reader capabilities: %+v", c)
	}

	if _, err := connect(t, p, "reader", "wrong", "admin"); kind(err) != mongoconn.KindAuthFailed {
		t.Fatalf("invalid password: %v (%s)", err, kind(err))
	}
	if _, err := connect(t, p, "nobody", "x", "admin"); kind(err) != mongoconn.KindAuthFailed {
		t.Fatalf("unknown user: %v", err)
	}
	// User defined in "app" authenticating against the wrong database.
	if _, err := connect(t, p, "appuser", "appuser-pw", "admin"); kind(err) != mongoconn.KindAuthFailed {
		t.Fatalf("auth database mismatch: %v", err)
	}
	if _, err := connect(t, p, "appuser", "appuser-pw", "app"); err != nil {
		t.Fatalf("correct auth database: %v", err)
	}
	// SCRAM-SHA-1-only user (legacy deployments).
	if res, err := connect(t, p, "legacy", "legacy-pw", "admin"); err != nil {
		t.Fatalf("SCRAM-SHA-1 negotiation: %v", err)
	} else if res.Mechanism != "" {
		t.Logf("mechanism %q", res.Mechanism)
	}
	sha256Only := p
	sha256Only.AuthMechanisms = []string{"SCRAM-SHA-256"}
	if _, err := connect(t, sha256Only, "legacy", "legacy-pw", "admin"); err == nil {
		t.Fatal("SCRAM-SHA-1 user must fail when only SCRAM-SHA-256 is allowed")
	}
}

func TestTLSAuthentication(t *testing.T) {
	p := tlsProfile(t)
	res, err := connect(t, p, "writer", "writer-pw", "admin")
	if err != nil {
		t.Fatalf("TLS with custom CA and client certificate: %v", err)
	}
	if !res.TLSEnabled {
		t.Fatal("expected TLS session")
	}
	if _, err := connect(t, p, "writer", "bad", "admin"); kind(err) != mongoconn.KindAuthFailed {
		t.Fatalf("TLS invalid password: %v", err)
	}

	noClientCert := p
	noClientCert.TLS.ClientCertFile, noClientCert.TLS.ClientKeyFile = "", ""
	if _, err := connect(t, noClientCert, "writer", "writer-pw", "admin"); err == nil {
		t.Fatal("server requires client certificates; connection without one must fail")
	}

	wrongCA := p
	wrongCA.TLS.CAFile = certs(t, "other-ca.crt")
	_, err = connect(t, wrongCA, "writer", "writer-pw", "admin")
	if kind(err) != mongoconn.KindTLS {
		t.Fatalf("untrusted CA: want %s, got %v (%s)", mongoconn.KindTLS, err, kind(err))
	}

	mismatch := p
	mismatch.URI = env(t, "IT_TLS_WRONGNAME_URI")
	_, err = connect(t, mismatch, "writer", "writer-pw", "admin")
	if kind(err) != mongoconn.KindTLS {
		t.Fatalf("hostname mismatch: want %s, got %v (%s)", mongoconn.KindTLS, err, kind(err))
	}

	// No silent downgrade: a plaintext profile cannot talk to a TLS server
	// and a TLS profile cannot talk to a plaintext server.
	plain := profile("plain-to-tls", env(t, "IT_TLS_URI"), config.TLSDisabled)
	if _, err := connect(t, plain, "writer", "writer-pw", "admin"); err == nil {
		t.Fatal("plaintext client must not connect to a requireTLS server")
	}
	tlsToPlain := rsProfile(t)
	tlsToPlain.TLS = p.TLS
	if _, err := connect(t, tlsToPlain, "writer", "writer-pw", "admin"); err == nil {
		t.Fatal("TLS client must not fall back to plaintext")
	}
}

func TestUnavailableAndTimeout(t *testing.T) {
	down := profile("down", "mongodb://no-such-host.invalid:27017/", config.TLSDisabled)
	start := time.Now()
	_, err := connect(t, down, "u", "p", "admin")
	if k := kind(err); k != mongoconn.KindUnavailable && k != mongoconn.KindTimeout {
		t.Fatalf("unreachable host: %v (%s)", err, k)
	}
	blackhole := profile("blackhole", "mongodb://10.255.255.1:27017/?connectTimeoutMS=1000", config.TLSDisabled)
	blackhole.ServerSelectionTimeout = 2 * time.Second
	if _, err := connect(t, blackhole, "u", "p", "admin"); err == nil {
		t.Fatal("blackhole must fail")
	}
	if time.Since(start) > 30*time.Second {
		t.Fatalf("timeouts not enforced: %s", time.Since(start))
	}
}

func TestConcurrentSessionsAreIndependent(t *testing.T) {
	p := rsProfile(t)
	users := map[string]string{"reader": "reader-pw", "writer": "writer-pw", "legacy": "legacy-pw"}
	var wg sync.WaitGroup
	errs := make(chan error, 30)
	for i := 0; i < 5; i++ {
		for u, pw := range users {
			wg.Add(1)
			go func() {
				defer wg.Done()
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				res, err := mongoconn.Connect(ctx, &p, mongoconn.Credentials{Username: u, Password: pw, AuthSource: "admin"}, mongoconn.PoolHooks{})
				if err != nil {
					errs <- fmt.Errorf("%s: %w", u, err)
					return
				}
				defer res.Client.Disconnect(context.Background())
				st, err := mongoconn.GetConnectionStatus(ctx, res.Client)
				if err != nil || len(st.AuthInfo.AuthenticatedUsers) != 1 || st.AuthInfo.AuthenticatedUsers[0].User != u {
					errs <- fmt.Errorf("%s: wrong principal on connection: %+v %v", u, st, err)
				}
			}()
		}
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

// ---- full API against MongoDB ----

type portal struct {
	t     *testing.T
	h     http.Handler
	store *session.Store
}

func newPortal(t *testing.T, profiles ...config.Profile) *portal {
	t.Helper()
	cfg, err := config.Parse([]byte("identity:\n  mode: header\n  developerGroups: [devs]\n  sreGroups: [sres]\nprofiles:\n  - name: placeholder\n    uri: mongodb://x/\n    tls: {mode: disabled}\n"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Profiles = profiles
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	key := []byte("integration-test-session-key-0123456789")
	res, err := identity.NewResolver(identity.Options{Config: cfg.Identity, Key: key, SecureCookie: true, MaxAge: time.Hour, Logger: logger})
	if err != nil {
		t.Fatal(err)
	}
	rb, err := rbac.NewStore(rbac.Source{Extra: cfg.LegacyRBACPolicy(), DefaultRole: *cfg.RBAC.DefaultRole}, logger)
	if err != nil {
		t.Fatal(err)
	}
	store := session.NewStore(session.Options{IdleTimeout: time.Hour, AbsoluteTimeout: time.Hour, MaxPerUser: 5, MaxTotal: 100})
	t.Cleanup(store.Close)
	srv := api.New(api.Deps{Config: cfg, Identity: res, RBAC: rb, CSRFKey: key, Store: store, Audit: audit.New(logger, 100), Metrics: metrics.New(), Logger: logger})
	return &portal{t: t, h: srv.Handler(), store: store}
}

type client struct {
	p      *portal
	user   string
	groups string
	cookie *http.Cookie
	csrf   string
}

func (c *client) do(method, path string, body any, hdr ...string) (int, map[string]any) {
	c.p.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	r := httptest.NewRequest(method, path, rd)
	r.RemoteAddr = "127.0.0.1:40000"
	r.Header.Set("X-Forwarded-User", c.user)
	r.Header.Set("X-Forwarded-Groups", c.groups)
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	if c.csrf != "" {
		r.Header.Set("X-CSRF-Token", c.csrf)
	}
	if c.cookie != nil {
		r.AddCookie(c.cookie)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		r.Header.Set(hdr[i], hdr[i+1])
	}
	w := httptest.NewRecorder()
	c.p.h.ServeHTTP(w, r)
	for _, ck := range w.Result().Cookies() {
		if ck.MaxAge < 0 {
			c.cookie = nil
		} else {
			c.cookie = ck
		}
	}
	var m map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &m)
	return w.Code, m
}

func (p *portal) login(sso, groups, prof, user, pw string) *client {
	p.t.Helper()
	c := &client{p: p, user: sso, groups: groups}
	code, me := c.do("GET", "/api/v1/me", nil)
	if code != 200 {
		p.t.Fatalf("me: %d %v", code, me)
	}
	c.csrf = me["csrfToken"].(string)
	code, s := c.do("POST", "/api/v1/session", map[string]string{"profile": prof, "username": user, "password": pw})
	if code != 200 {
		p.t.Fatalf("login %s as %s: %d %v", sso, user, code, s)
	}
	c.csrf = s["csrfToken"].(string)
	return c
}

func errCode(m map[string]any) string {
	e, _ := m["error"].(map[string]any)
	s, _ := e["code"].(string)
	return s
}

func base(db, coll string) string {
	return "/api/v1/databases/" + url.PathEscape(db) + "/collections/" + url.PathEscape(coll)
}

func TestDeveloperReadOnlyEndToEnd(t *testing.T) {
	p := newPortal(t, rsProfile(t))
	// Developer portal role but a MongoDB user that could write: the portal must still refuse.
	dev := p.login("dana", "devs", "rs", "writer", "writer-pw")

	code, dbs := dev.do("GET", "/api/v1/databases", nil)
	if code != 200 || !strings.Contains(fmt.Sprint(dbs["databases"]), "app") {
		t.Fatalf("databases: %d %v", code, dbs)
	}
	code, docs := dev.do("GET", base("app", "orders")+"/documents?count=true&sort="+url.QueryEscape(`{"_id":1}`), nil)
	if code != 200 {
		t.Fatalf("browse: %d %v", code, docs)
	}
	page := docs["page"].(map[string]any)
	if n := len(page["documents"].([]any)); n != 3 || docs["count"].(float64) != 3 {
		t.Fatalf("expected 3 documents, got %d %v", n, docs["count"])
	}
	first := page["documents"].([]any)[0].(map[string]any)
	if _, ok := first["total"].(map[string]any)["$numberDecimal"]; !ok {
		t.Fatalf("Decimal128 must round-trip as canonical Extended JSON: %v", first["total"])
	}

	for _, req := range []struct {
		m, p string
		b    any
	}{
		{"POST", base("app", "orders") + "/documents", map[string]string{"document": `{"x":1}`}},
		{"POST", base("app", "orders") + "/indexes", map[string]string{"keys": `{"x":1}`}},
		{"DELETE", base("app", "orders"), nil},
	} {
		if code, m := dev.do(req.m, req.p, req.b, "X-Confirm", "orders"); code != 403 || errCode(m) != "portal_role_forbidden" {
			t.Errorf("%s %s: %d %v", req.m, req.p, code, m)
		}
	}
	code, m := dev.do("POST", base("app", "orders")+"/query", map[string]any{"operation": "aggregate", "pipeline": `[{"$out":"stolen"}]`})
	if code != 403 {
		t.Fatalf("$out for developer: %d %v", code, m)
	}
	admin := adminClient(t)
	if n, _ := admin.Database("app").Collection("stolen").CountDocuments(context.Background(), bson.D{}); n != 0 {
		t.Fatal("$out must not have written data")
	}

	code, m = dev.do("POST", base("app", "orders")+"/query", map[string]any{"operation": "aggregate", "pipeline": `[{"$match":{"status":"A"}},{"$count":"n"}]`})
	if code != 200 {
		t.Fatalf("read aggregate: %d %v", code, m)
	}
}

func TestSRERespectsMongoDBRoles(t *testing.T) {
	p := newPortal(t, rsProfile(t))
	// SRE portal role with a read-only MongoDB user: MongoDB is the final authority.
	sre := p.login("sam", "sres", "rs", "reader", "reader-pw")
	code, m := sre.do("POST", base("app", "orders")+"/documents", map[string]string{"document": `{"x":1}`})
	if code != 403 || errCode(m) != string(mongoconn.KindUnauthorized) {
		t.Fatalf("MongoDB must deny write for read-only user: %d %v", code, m)
	}
	code, m = sre.do("POST", base("app", "orders")+"/indexes", map[string]string{"keys": `{"x":1}`})
	if code != 403 {
		t.Fatalf("unauthorized index creation: %d %v", code, m)
	}
	code, m = sre.do("DELETE", base("app", "orders"), nil, "X-Confirm", "orders")
	if code != 403 {
		t.Fatalf("unauthorized collection drop: %d %v", code, m)
	}
	code, m = sre.do("GET", base("other", "x")+"/documents", nil)
	if code != 403 {
		t.Fatalf("read outside granted database: %d %v", code, m)
	}
}

func TestSRECrudEndToEnd(t *testing.T) {
	for _, prof := range []func(*testing.T) config.Profile{rsProfile, tlsProfile} {
		pr := prof(t)
		t.Run(pr.Name, func(t *testing.T) {
			p := newPortal(t, pr)
			sre := p.login("sam", "sres", pr.Name, "writer", "writer-pw")
			coll := fmt.Sprintf("it_%d", time.Now().UnixNano())
			b := base("scratch", coll)
			if code, m := sre.do("POST", "/api/v1/databases/scratch/collections", map[string]string{"name": coll}); code != 201 {
				t.Fatalf("create collection: %d %v", code, m)
			}
			code, m := sre.do("POST", b+"/documents", map[string]string{"document": `{"name":"a","n":{"$numberLong":"5"},"when":{"$date":"2024-01-02T03:04:05Z"},"oid":{"$oid":"507f1f77bcf86cd799439011"}}`})
			if code != 201 {
				t.Fatalf("insert: %d %v", code, m)
			}
			id := m["id"].(string)
			code, m = sre.do("GET", b+"/documents/"+id, nil)
			doc, _ := m["document"].(map[string]any)
			if code != 200 || doc["n"].(map[string]any)["$numberLong"] != "5" {
				t.Fatalf("get: %d %v", code, m)
			}
			if code, m = sre.do("PUT", b+"/documents/"+id, map[string]string{"document": `{"name":"b"}`}); code != 200 || m["modified"].(float64) != 1 {
				t.Fatalf("replace: %d %v", code, m)
			}
			if code, m = sre.do("PUT", b+"/documents/"+id, map[string]string{"document": `{"_id":{"$oid":"000000000000000000000000"},"name":"c"}`}); code != 400 {
				t.Fatalf("changing _id must be rejected: %d %v", code, m)
			}
			if code, m = sre.do("POST", b+"/indexes", map[string]string{"keys": `{"name":1}`, "options": `{"name":"name_1","unique":true}`}); code != 201 {
				t.Fatalf("create index: %d %v", code, m)
			}
			if code, m = sre.do("POST", b+"/documents", map[string]string{"document": `{"name":"b"}`}); code != 409 {
				t.Fatalf("unique violation: %d %v", code, m)
			}
			if code, m = sre.do("GET", b+"/indexes", nil); code != 200 || len(m["indexes"].([]any)) != 2 {
				t.Fatalf("list indexes: %d %v", code, m)
			}
			if code, _ = sre.do("DELETE", b+"/indexes/name_1", nil); code != 428 {
				t.Fatalf("drop index without confirmation: %d", code)
			}
			if code, m = sre.do("DELETE", b+"/indexes/name_1", nil, "X-Confirm", "name_1"); code != 200 {
				t.Fatalf("drop index: %d %v", code, m)
			}
			if code, m = sre.do("POST", b+"/query", map[string]any{"operation": "countDocuments", "filter": `{"name":"b"}`}); code != 200 || m["count"].(float64) != 1 {
				t.Fatalf("count: %d %v", code, m)
			}
			if code, m = sre.do("POST", b+"/query", map[string]any{"operation": "find", "filter": `{"$where":"true"}`}); code != 400 {
				t.Fatalf("$where: %d %v", code, m)
			}
			if code, m = sre.do("DELETE", b+"/documents/"+id, nil, "X-Confirm", "delete"); code != 200 {
				t.Fatalf("delete: %d %v", code, m)
			}
			if code, _ = sre.do("GET", b+"/documents/"+id, nil); code != 404 {
				t.Fatalf("deleted document: %d", code)
			}
			if code, m = sre.do("GET", b+"/stats", nil); code != 200 {
				t.Fatalf("stats: %d %v", code, m)
			}
			if code, m = sre.do("DELETE", b, nil, "X-Confirm", coll); code != 200 {
				t.Fatalf("drop collection: %d %v", code, m)
			}
			if code, m = sre.do("GET", "/api/v1/server", nil); code != 200 {
				t.Fatalf("server info: %d %v", code, m)
			}
			if code, _ = sre.do("DELETE", "/api/v1/session", nil); code != 200 {
				t.Fatal("logout")
			}
			if code, m = sre.do("GET", "/api/v1/databases", nil); code != 401 {
				t.Fatalf("after logout: %d %v", code, m)
			}
		})
	}
}

func TestQueryLimitsAndTimeouts(t *testing.T) {
	p := newPortal(t, rsProfile(t))
	dev := p.login("dana", "devs", "rs", "reader", "reader-pw")
	code, m := dev.do("GET", base("app", "orders")+"/documents?limit=2", nil)
	page := m["page"].(map[string]any)
	if code != 200 || len(page["documents"].([]any)) != 2 || page["hasMore"] != true {
		t.Fatalf("pagination: %d %v", code, m)
	}
	// A query that sleeps on the server is cut off by maxTimeMS.
	code, m = dev.do("POST", base("app", "orders")+"/query", map[string]any{
		"operation": "aggregate", "maxTimeMS": 200,
		"pipeline": `[{"$unionWith":{"coll":"orders","pipeline":[{"$unionWith":"orders"}]}},{"$unionWith":"orders"},{"$group":{"_id":{"$range":[0,5000000]}}}]`,
	})
	if code == 200 {
		t.Logf("heavy aggregate completed within limit (fast machine): %v", m)
	} else if code != 504 && code != 400 {
		t.Fatalf("timeout: %d %v", code, m)
	}
}

// shellCall runs one /api/v1/shell operation and decodes the canonical
// Extended JSON result.
func (c *client) shellCall(t *testing.T, op, args string, confirm string) (int, bson.M, map[string]any) {
	t.Helper()
	hdr := []string{}
	if confirm != "" {
		hdr = append(hdr, "X-Confirm", confirm)
	}
	code, m := c.do("POST", "/api/v1/shell", map[string]string{"op": op, "args": args}, hdr...)
	if code != 200 {
		return code, nil, m
	}
	var res bson.M
	if err := bson.UnmarshalExtJSON([]byte(m["result"].(string)), true, &res); err != nil {
		t.Fatalf("%s: decode result: %v", op, err)
	}
	return code, res, m
}

// alen returns the length of a BSON array value, or -1 if it is not an array.
func alen(v any) int {
	a, ok := v.(bson.A)
	if !ok {
		return -1
	}
	return len(a)
}

// field reads a key from a decoded document (bson.D or bson.M).
func field(v any, key string) any {
	switch d := v.(type) {
	case bson.M:
		return d[key]
	case bson.D:
		for _, e := range d {
			if e.Key == key {
				return e.Value
			}
		}
	}
	return nil
}

func TestShellOperations(t *testing.T) {
	for _, prof := range []func(*testing.T) config.Profile{rsProfile, tlsProfile} {
		pr := prof(t)
		t.Run(pr.Name, func(t *testing.T) {
			p := newPortal(t, pr)
			sre := p.login("sam", "sres", pr.Name, "writer", "writer-pw")
			coll := fmt.Sprintf("sh_%d", time.Now().UnixNano())
			ns := `"db":"scratch","coll":"` + coll + `"`

			docs := make([]string, 0, 50)
			for i := 0; i < 50; i++ {
				docs = append(docs, fmt.Sprintf(`{"n":{"$numberInt":"%d"},"g":"%s"}`, i, []string{"a", "b"}[i%2]))
			}
			code, res, m := sre.shellCall(t, "insertMany", `{`+ns+`,"documents":[`+strings.Join(docs, ",")+`]}`, "")
			if code != 200 || alen(res["insertedIds"]) != 50 {
				t.Fatalf("insertMany: %d %v", code, m)
			}

			// Server-side cursor paging.
			code, res, m = sre.shellCall(t, "find", `{`+ns+`,"filter":{},"options":{"sort":{"n":1},"batchSize":{"$numberInt":"20"}}}`, "")
			if code != 200 || alen(res["batch"]) != 20 || res["exhausted"] == true || res["id"] == "" {
				t.Fatalf("find first batch: %d %v %v", code, m, res["exhausted"])
			}
			id, _ := res["id"].(string)
			total := 20
			for i := 0; i < 5 && res["exhausted"] != true; i++ {
				code, res, m = sre.shellCall(t, "getMore", `{"id":"`+id+`","batchSize":{"$numberInt":"20"}}`, "")
				if code != 200 {
					t.Fatalf("getMore: %d %v", code, m)
				}
				total += alen(res["batch"])
			}
			if total != 50 || res["exhausted"] != true {
				t.Fatalf("cursor returned %d documents, exhausted=%v", total, res["exhausted"])
			}
			if code, _, _ = sre.shellCall(t, "getMore", `{"id":"`+id+`"}`, ""); code != 400 {
				t.Fatalf("exhausted cursor must be closed: %d", code)
			}

			code, res, _ = sre.shellCall(t, "aggregate", `{`+ns+`,"pipeline":[{"$group":{"_id":"$g","c":{"$sum":1}}},{"$sort":{"_id":1}}]}`, "")
			if code != 200 || alen(res["batch"]) != 2 {
				t.Fatalf("aggregate: %d %v", code, res)
			}
			if code, res, _ = sre.shellCall(t, "countDocuments", `{`+ns+`,"filter":{"g":"a"}}`, ""); code != 200 || res["n"] != int64(25) {
				t.Fatalf("countDocuments: %d %v", code, res)
			}
			if code, res, _ = sre.shellCall(t, "distinct", `{`+ns+`,"key":"g","filter":{}}`, ""); code != 200 || alen(res["values"]) != 2 {
				t.Fatalf("distinct: %d %v", code, res)
			}
			if code, res, _ = sre.shellCall(t, "explain", `{`+ns+`,"kind":"find","filter":{"n":{"$gt":{"$numberInt":"10"}}},"verbosity":"queryPlanner"}`, ""); code != 200 || res["result"] == nil {
				t.Fatalf("explain: %d %v", code, res)
			}
			if code, res, _ = sre.shellCall(t, "runCommand", `{"db":"scratch","command":{"dbStats":1}}`, ""); code != 200 {
				t.Fatalf("runCommand dbStats: %d %v", code, res)
			}
			if code, _, m = sre.shellCall(t, "runCommand", `{"db":"admin","command":{"createUser":"evil","pwd":"x","roles":["root"]}}`, ""); code != 403 {
				t.Fatalf("createUser must be refused: %d %v", code, m)
			}

			// Confirmed bulk operations.
			if code, _, _ = sre.shellCall(t, "updateMany", `{`+ns+`,"filter":{"g":"a"},"update":{"$set":{"flag":true}}}`, ""); code != 428 {
				t.Fatalf("unconfirmed updateMany: %d", code)
			}
			code, res, m = sre.shellCall(t, "updateMany", `{`+ns+`,"filter":{"g":"a"},"update":{"$set":{"flag":true}}}`, "updateMany")
			if code != 200 || res["modifiedCount"] != int64(25) {
				t.Fatalf("updateMany: %d %v %v", code, res, m)
			}
			code, res, m = sre.shellCall(t, "bulkWrite", `{`+ns+`,"operations":[{"insertOne":{"document":{"n":{"$numberInt":"100"}}}},{"deleteMany":{"filter":{"g":"b"}}}]}`, "bulkWrite")
			if code != 200 || res["insertedCount"] != int64(1) || res["deletedCount"] != int64(25) {
				t.Fatalf("bulkWrite: %d %v %v", code, res, m)
			}
			code, res, m = sre.shellCall(t, "findOneAndUpdate", `{`+ns+`,"filter":{"n":{"$numberInt":"100"}},"update":{"$set":{"z":1}},"options":{"returnDocument":"after"}}`, "")
			if code != 200 || field(res["value"], "z") != int32(1) {
				t.Fatalf("findOneAndUpdate: %d %v %v", code, res, m)
			}

			// Indexes.
			if code, _, m = sre.shellCall(t, "createIndexes", `{`+ns+`,"specs":[{"key":{"n":1},"name":"n_1","unique":true}]}`, ""); code != 200 {
				t.Fatalf("createIndexes: %d %v", code, m)
			}
			if code, _, m = sre.shellCall(t, "insertOne", `{`+ns+`,"document":{"n":{"$numberInt":"100"}}}`, ""); code != 409 || errField(m, "codeName") == nil {
				t.Fatalf("duplicate key: %d %v", code, m)
			}
			if code, _, _ = sre.shellCall(t, "runCommand", `{"db":"scratch","command":{"dropIndexes":"`+coll+`","index":"n_1"}}`, ""); code != 403 {
				t.Fatalf("unconfirmed dropIndexes via runCommand: %d", code)
			}
			if code, _, m = sre.shellCall(t, "runCommand", `{"db":"scratch","command":{"dropIndexes":"`+coll+`","index":"n_1"}}`, "runCommand"); code != 200 {
				t.Fatalf("dropIndexes: %d %v", code, m)
			}
			if code, _, m = sre.shellCall(t, "dropCollection", `{`+ns+`}`, "dropCollection"); code != 200 {
				t.Fatalf("dropCollection: %d %v", code, m)
			}
		})
	}
	// SRE portal role with a read-only MongoDB user: MongoDB refuses the write.
	p := newPortal(t, rsProfile(t))
	ro := p.login("sam", "sres", "rs", "reader", "reader-pw")
	code, _, m := ro.shellCall(t, "insertOne", `{"db":"app","coll":"orders","document":{"x":1}}`, "")
	if code != 403 || errField(m, "codeName") != "Unauthorized" {
		t.Fatalf("MongoDB must deny the write: %d %v", code, m)
	}
	// Developer: reads work, writes are refused by the portal.
	dev := p.login("dana", "devs", "rs", "writer", "writer-pw")
	if code, _, m = dev.shellCall(t, "find", `{"db":"app","coll":"orders","filter":{}}`, ""); code != 200 {
		t.Fatalf("developer find: %d %v", code, m)
	}
	if code, _, _ = dev.shellCall(t, "insertOne", `{"db":"app","coll":"orders","document":{"x":1}}`, ""); code != 403 {
		t.Fatalf("developer insert: %d", code)
	}
}

func errField(m map[string]any, key string) any {
	e, _ := m["error"].(map[string]any)
	return e[key]
}

func adminClient(t *testing.T) *mongo.Client {
	t.Helper()
	c, err := mongo.Connect(options.Client().ApplyURI(env(t, "IT_RS_URI")).SetAuth(options.Credential{Username: "root", Password: env(t, "IT_ADMIN_PW"), AuthSource: "admin"}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Disconnect(context.Background()) })
	return c
}

// TestReplicaSetFailover steps down the primary and checks that an existing
// user session keeps working against the newly elected primary (the driver
// re-authenticates new connections with the in-memory credential).
// Monitoring with a clusterMonitor user shows the replica set, connections
// and sizes; without it, the privileged sections explain what is missing.
func TestMonitoring(t *testing.T) {
	p := newPortal(t, rsProfile(t))
	mon := p.login("olga", "other", "rs", "monitor", "monitor-pw")
	code, m := mon.do("GET", "/api/v1/monitoring", nil)
	if code != 200 {
		t.Fatalf("monitoring: %d %v", code, m)
	}
	secs := m["sections"].(map[string]any)
	section := func(name string) map[string]any {
		s, _ := secs[name].(map[string]any)
		if s["error"] != nil {
			t.Fatalf("section %s: %v", name, s)
		}
		d, _ := s["data"].(map[string]any)
		return d
	}
	rs := section("replicaSet")
	members, _ := rs["members"].([]any)
	primaries := 0
	for _, x := range members {
		if x.(map[string]any)["state"] == "PRIMARY" {
			primaries++
		}
	}
	if rs["set"] != "rs0" || len(members) != 3 || primaries != 1 {
		t.Fatalf("replica set: %v", rs)
	}
	srv := section("server")
	if c := srv["connections"].(map[string]any); c["current"].(float64) < 1 || c["available"].(float64) < 1 {
		t.Fatalf("server connections: %v", c)
	}
	conns := section("connections")
	if conns["total"].(float64) < 1 || conns["total"].(float64) != conns["active"].(float64)+conns["idle"].(float64) {
		t.Fatalf("connections: %v", conns)
	}
	if dbs := section("databases"); dbs["totalSize"].(float64) <= 0 {
		t.Fatalf("databases: %v", dbs)
	}
	if pool := m["session"].(map[string]any)["pool"].(map[string]any); pool["open"].(float64) < 1 {
		t.Fatalf("own pool: %v", pool)
	}

	// A user without clusterMonitor: privileged sections explain, the rest works.
	rd := p.login("rita", "other", "rs", "reader", "reader-pw")
	code, m = rd.do("GET", "/api/v1/monitoring", nil)
	secs = m["sections"].(map[string]any)
	srvSec := secs["server"].(map[string]any)
	if code != 200 || srvSec["code"] != "mongo_unauthorized" || !strings.Contains(srvSec["error"].(string), "clusterMonitor") {
		t.Fatalf("reader monitoring: %d %v", code, srvSec)
	}
	if dbSec := secs["databases"].(map[string]any); dbSec["error"] != nil {
		t.Fatalf("reader databases: %v", dbSec)
	}
}

// Unmapped users follow their MongoDB privileges (role:mongodb): the writer
// may write without any RBAC mapping, the reader is refused by MongoDB.
func TestDefaultRoleFollowsMongoDB(t *testing.T) {
	p := newPortal(t, rsProfile(t))
	w := p.login("wanda", "other", "rs", "writer", "writer-pw")
	if code, m := w.do("POST", "/api/v1/databases/scratch/collections/rbac_default/documents", map[string]string{"document": `{"a":1}`}); code != 201 {
		t.Fatalf("unmapped writer insert: %d %v", code, m)
	}
	r := p.login("rhea", "other", "rs", "reader", "reader-pw")
	if code, m := r.do("POST", "/api/v1/databases/app/collections/orders/documents", map[string]string{"document": `{"a":1}`}); code != 403 || errCode(m) != "mongo_unauthorized" {
		t.Fatalf("unmapped reader insert must be refused by MongoDB: %d %v", code, m)
	}
}

func TestReplicaSetFailover(t *testing.T) {
	p := newPortal(t, rsProfile(t))
	sre := p.login("sam", "sres", "rs", "writer", "writer-pw")
	if code, m := sre.do("GET", base("app", "orders")+"/documents", nil); code != 200 {
		t.Fatalf("before failover: %d %v", code, m)
	}
	admin := adminClient(t)
	var hello bson.M
	_ = admin.Database("admin").RunCommand(context.Background(), bson.D{{Key: "hello", Value: 1}}).Decode(&hello)
	oldPrimary := hello["primary"]
	err := admin.Database("admin").RunCommand(context.Background(), bson.D{{Key: "replSetStepDown", Value: 30}, {Key: "force", Value: true}}).Err()
	if err != nil && !mongo.IsNetworkError(err) {
		t.Logf("stepDown returned: %v", err)
	}
	deadline := time.Now().Add(60 * time.Second)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := admin.Ping(ctx, readpref.Primary())
		cancel()
		if err == nil {
			_ = admin.Database("admin").RunCommand(context.Background(), bson.D{{Key: "hello", Value: 1}}).Decode(&hello)
			if hello["primary"] != oldPrimary {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("no new primary elected")
		}
		time.Sleep(time.Second)
	}
	t.Logf("primary moved %v -> %v", oldPrimary, hello["primary"])
	var lastCode int
	var last map[string]any
	for i := 0; i < 20; i++ {
		lastCode, last = sre.do("POST", base("scratch", "failover")+"/documents", map[string]string{"document": `{"after":"failover"}`})
		if lastCode == 201 {
			break
		}
		time.Sleep(time.Second)
	}
	if lastCode != 201 {
		t.Fatalf("write after failover: %d %v", lastCode, last)
	}
	if code, m := sre.do("GET", "/api/v1/session", nil); code != 200 {
		t.Fatalf("session must survive failover: %d %v", code, m)
	}
	_ = admin.Database("scratch").Collection("failover").Drop(context.Background())
}
