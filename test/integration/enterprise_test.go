//go:build integration

package integration

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/krishnamanaiducloud/mongo-portal/internal/api"
	"github.com/krishnamanaiducloud/mongo-portal/internal/audit"
	"github.com/krishnamanaiducloud/mongo-portal/internal/config"
	"github.com/krishnamanaiducloud/mongo-portal/internal/identity"
	"github.com/krishnamanaiducloud/mongo-portal/internal/metrics"
	"github.com/krishnamanaiducloud/mongo-portal/internal/rbac"
	"github.com/krishnamanaiducloud/mongo-portal/internal/session"
	"github.com/krishnamanaiducloud/mongo-portal/internal/store"
)

// raw performs a request and returns the status and raw body.
func (c *client) raw(method, path string, body io.Reader, hdr ...string) (int, []byte, http.Header) {
	c.p.t.Helper()
	r := httptest.NewRequest(method, path, body)
	r.RemoteAddr = "127.0.0.1:40000"
	r.Header.Set("X-Forwarded-User", c.user)
	r.Header.Set("X-Forwarded-Groups", c.groups)
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
	return w.Code, w.Body.Bytes(), w.Header()
}

// importFile uploads data and waits for the job to finish.
func (c *client) importFile(t *testing.T, db, coll string, data []byte, params string) map[string]any {
	t.Helper()
	code, body, _ := c.raw("POST", base(db, coll)+"/import?"+params, bytes.NewReader(data), "Content-Type", "application/octet-stream")
	if code != http.StatusAccepted {
		t.Fatalf("import: %d %s", code, body)
	}
	var job map[string]any
	_ = json.Unmarshal(body, &job)
	id := job["id"].(string)
	for range 300 {
		_, job = c.do("GET", "/api/v1/jobs/"+id, nil)
		if s := job["state"]; s != "queued" && s != "running" {
			return job
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("job did not finish: %v", job)
	return nil
}

func seedDocs(t *testing.T, db, coll string, n int) []bson.Raw {
	t.Helper()
	c := adminClient(t).Database(db).Collection(coll)
	_ = c.Drop(context.Background())
	dec, _ := bson.ParseDecimal128("12.34")
	var docs []any
	for i := range n {
		docs = append(docs, bson.D{{Key: "_id", Value: int32(i)}, {Key: "name", Value: "item " + string(rune('a'+i%26))}, {Key: "price", Value: dec},
			{Key: "big", Value: int64(i) << 33}, {Key: "at", Value: bson.NewDateTimeFromTime(time.Unix(int64(i)*3600, 0))},
			{Key: "oid", Value: bson.NewObjectID()}, {Key: "tags", Value: bson.A{"x", int32(i)}}, {Key: "sub", Value: bson.D{{Key: "k", Value: i % 3}}}})
	}
	if _, err := c.InsertMany(context.Background(), docs); err != nil {
		t.Fatal(err)
	}
	return allDocs(t, db, coll)
}

func allDocs(t *testing.T, db, coll string) []bson.Raw {
	t.Helper()
	cur, err := adminClient(t).Database(db).Collection(coll).Find(context.Background(), bson.D{}, options.Find().SetSort(bson.D{{Key: "_id", Value: 1}}))
	if err != nil {
		t.Fatal(err)
	}
	var out []bson.Raw
	if err := cur.All(context.Background(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func sameDocs(t *testing.T, got, want []bson.Raw) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d documents, want %d", len(got), len(want))
	}
	for i := range want {
		if !bytes.Equal(got[i], want[i]) {
			t.Fatalf("document %d differs:\n got %s\nwant %s", i, got[i], want[i])
		}
	}
}

// Export and re-import keep every document byte for byte in the exact
// formats, and the database archive's manifest matches its files.
func TestExportImportRoundTrip(t *testing.T) {
	p := newPortal(t, rsProfile(t))
	w := p.login("sam", "sres", "rs", "writer", "writer-pw")
	want := seedDocs(t, "scratch", "src", 750)

	for _, c := range []struct{ name, export, imp string }{
		{"ndjson canonical", "format=ndjson&ejson=canonical", "format=ndjson"},
		{"json array gzip", "format=json&ejson=canonical&gzip=true", "format=json"},
		{"bson", "format=bson", "format=bson"},
	} {
		t.Run(c.name, func(t *testing.T) {
			code, data, hdr := w.raw("GET", base("scratch", "src")+"/export?"+c.export, nil)
			if code != 200 || !strings.Contains(hdr.Get("Content-Disposition"), "attachment") {
				t.Fatalf("export: %d %s", code, data[:min(len(data), 200)])
			}
			_ = adminClient(t).Database("scratch").Collection("dst").Drop(context.Background())
			job := w.importFile(t, "scratch", "dst", data, c.imp+"&fileName=x")
			if job["state"] != "succeeded" || job["inserted"].(float64) != 750 || job["failed"].(float64) != 0 {
				t.Fatalf("job: %v", job)
			}
			sum := sha256.Sum256(data)
			if job["sha256"] != hex.EncodeToString(sum[:]) {
				t.Fatalf("checksum: %v", job["sha256"])
			}
			sameDocs(t, allDocs(t, "scratch", "dst"), want)
		})
	}

	// A filtered, projected CSV export.
	code, data, _ := w.raw("GET", base("scratch", "src")+"/export?format=csv&filter="+url.QueryEscape(`{"sub.k":1}`)+"&projection="+url.QueryEscape(`{"name":1,"big":1}`)+"&sort="+url.QueryEscape(`{"_id":1}`)+"&limit=3", nil)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if code != 200 || len(lines) != 4 || lines[0] != "_id,name,big" || lines[1] != "1,item b,8589934592" {
		t.Fatalf("csv export: %d %q", code, lines)
	}
	// CSV import with mapping, gzip-compressed.
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = io.WriteString(zw, "code,amount,when\nA-1,1.25,2026-01-02\nA-2,x,2026-01-03\n")
	_ = zw.Close()
	_ = adminClient(t).Database("scratch").Collection("csvdst").Drop(context.Background())
	mapping := `[{"column":"code","field":"_id"},{"column":"amount","type":"double"},{"column":"when","field":"meta.when","type":"date"}]`
	job := w.importFile(t, "scratch", "csvdst", gz.Bytes(), "format=csv&mapping="+url.QueryEscape(mapping))
	if job["state"] != "succeeded" || job["inserted"].(float64) != 1 || job["failed"].(float64) != 1 || job["gzip"] != true {
		t.Fatalf("csv job: %v", job)
	}
	got := allDocs(t, "scratch", "csvdst")
	if len(got) != 1 || got[0].Lookup("meta", "when").Type != bson.TypeDateTime || got[0].Lookup("amount").Double() != 1.25 {
		t.Fatalf("csv doc: %v", got)
	}

	// Database archive.
	code, data, _ = w.raw("GET", "/api/v1/databases/scratch/export?format=ndjson", nil)
	if code != 200 {
		t.Fatalf("db export: %d", code)
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{}
	for _, f := range zr.File {
		rc, _ := f.Open()
		b, _ := io.ReadAll(rc)
		rc.Close()
		files[f.Name] = b
	}
	var man struct {
		Files []struct {
			File      string `json:"file"`
			Documents int64  `json:"documents"`
			SHA256    string `json:"sha256"`
			Complete  bool   `json:"complete"`
		} `json:"files"`
		Consistency string `json:"consistency"`
	}
	if err := json.Unmarshal(files["manifest.json"], &man); err != nil || len(man.Files) < 3 || !strings.Contains(man.Consistency, "not a point-in-time") {
		t.Fatalf("manifest: %v %s", err, files["manifest.json"])
	}
	for _, f := range man.Files {
		sum := sha256.Sum256(files[f.File])
		if hex.EncodeToString(sum[:]) != f.SHA256 || !f.Complete {
			t.Fatalf("file %s checksum or completeness mismatch", f.File)
		}
		if f.File == "src.json" && f.Documents != 750 {
			t.Fatalf("src documents: %d", f.Documents)
		}
	}
	if _, ok := files["src.metadata.json"]; !ok {
		t.Fatal("collection metadata missing")
	}
}

// Validators, upserts, dry runs and both authorization boundaries.
func TestImportRulesAndAuthorization(t *testing.T) {
	ctx := context.Background()
	admin := adminClient(t).Database("scratch")
	_ = admin.Collection("validated").Drop(ctx)
	if err := admin.CreateCollection(ctx, "validated", options.CreateCollection().SetValidator(bson.D{{Key: "$jsonSchema", Value: bson.D{
		{Key: "required", Value: bson.A{"name"}}}}})); err != nil {
		t.Fatal(err)
	}
	p := newPortal(t, rsProfile(t))
	w := p.login("sam", "sres", "rs", "writer", "writer-pw")
	data := []byte(`{"_id":1,"name":"a"}` + "\n" + `{"_id":2}` + "\n" + `{"_id":3,"name":"c"}` + "\n" + `{"_id":1,"name":"dup"}` + "\n")
	job := w.importFile(t, "scratch", "validated", data, "format=ndjson")
	errs := job["errors"].([]any)
	codes := map[float64]bool{}
	for _, e := range errs {
		codes[e.(map[string]any)["code"].(float64)] = true
	}
	if job["state"] != "succeeded" || job["inserted"].(float64) != 2 || job["failed"].(float64) != 2 || !codes[121] || !codes[11000] {
		t.Fatalf("validated import: %v", job)
	}
	// Upsert replaces by _id.
	job = w.importFile(t, "scratch", "validated", []byte(`{"_id":1,"name":"replaced"}`+"\n"+`{"_id":9,"name":"new"}`), "format=ndjson&mode=upsert")
	if job["upserted"].(float64) != 1 || job["matched"].(float64) != 1 {
		t.Fatalf("upsert: %v", job)
	}
	var one bson.M
	_ = admin.Collection("validated").FindOne(ctx, bson.D{{Key: "_id", Value: 1}}).Decode(&one)
	if one["name"] != "replaced" {
		t.Fatalf("upsert result: %v", one)
	}
	// Dry run parses everything and writes nothing.
	before, _ := admin.Collection("validated").CountDocuments(ctx, bson.D{})
	job = w.importFile(t, "scratch", "validated", []byte(`{"name":"x"}`+"\nnot json\n"), "format=ndjson&dryRun=true")
	after, _ := admin.Collection("validated").CountDocuments(ctx, bson.D{})
	if job["state"] != "succeeded" || job["read"].(float64) != 2 || job["failed"].(float64) != 1 || before != after {
		t.Fatalf("dry run: %v (%d -> %d)", job, before, after)
	}

	// Portal RBAC: developers (role:readonly) may neither import nor export,
	// even with a MongoDB user that could write.
	dev := p.login("dana", "devs", "rs", "writer", "writer-pw")
	code, body, _ := dev.raw("POST", base("scratch", "validated")+"/import?format=ndjson", strings.NewReader(`{"a":1}`))
	if code != http.StatusForbidden || !strings.Contains(string(body), "portal_role_forbidden") {
		t.Fatalf("developer import: %d %s", code, body)
	}
	if code, body, _ := dev.raw("GET", base("scratch", "validated")+"/export", nil); code != http.StatusForbidden || !strings.Contains(string(body), "portal_role_forbidden") {
		t.Fatalf("developer export: %d %s", code, body)
	}
	// MongoDB privileges (transfer.requireWritePrivilege, the default): a
	// role:mongodb user whose MongoDB user only reads gets neither, and the
	// UI does not offer them.
	rd := p.login("rita", "other", "rs", "reader", "reader-pw")
	for _, path := range []string{base("app", "orders") + "/export", "/api/v1/databases/app/export?format=ndjson"} {
		if code, body, _ := rd.raw("GET", path, nil); code != http.StatusForbidden || !strings.Contains(string(body), "write_privilege_required") {
			t.Fatalf("reader export %s: %d %s", path, code, body)
		}
	}
	if code, body, _ := rd.raw("POST", base("app", "orders")+"/import?format=ndjson", strings.NewReader(`{"x":1}`)); code != http.StatusForbidden || !strings.Contains(string(body), "write_privilege_required") {
		t.Fatalf("reader import: %d %s", code, body)
	}
	_, me := rd.do("GET", "/api/v1/me", nil)
	if perms := me["permissions"].(map[string]any); perms["export:create"] != false || perms["import:create"] != false {
		t.Fatalf("reader permission hints: %v", perms)
	}
	_, cl := rd.do("GET", "/api/v1/databases/app/collections", nil)
	for _, c := range cl["collections"].([]any) {
		portal := c.(map[string]any)["access"].(map[string]any)["portal"].(map[string]any)
		if portal["export"] != false || portal["import"] != false {
			t.Fatalf("reader collection access: %v", portal)
		}
	}
	// A role:mongodb user with write privileges may export and import.
	wm := p.login("wendy", "other", "rs", "writer", "writer-pw")
	if code, _, _ := wm.raw("GET", base("scratch", "validated")+"/export", nil); code != 200 {
		t.Fatalf("writer export: %d", code)
	}
	_, cl = wm.do("GET", "/api/v1/databases/scratch/collections", nil)
	for _, c := range cl["collections"].([]any) {
		portal := c.(map[string]any)["access"].(map[string]any)["portal"].(map[string]any)
		if c.(map[string]any)["name"] == "validated" && (portal["export"] != true || portal["import"] != true) {
			t.Fatalf("writer collection access: %v", portal)
		}
	}
	// System collections are refused.
	if code, _, _ := w.raw("POST", base("scratch", "system.views")+"/import?format=ndjson", strings.NewReader(`{}`)); code != http.StatusForbidden {
		t.Fatalf("system collection import: %d", code)
	}
}

// killOp needs MongoDB's killop privilege; the portal refuses internal and
// finished operations and requires confirmation.
func TestOperationsAndKill(t *testing.T) {
	ctx := context.Background()
	seedDocs(t, "scratch", "sleepy", 400)
	slowClient, err := mongo.Connect(options.Client().ApplyURI(env(t, "IT_RS_URI")).SetAppName("it-sleeper").
		SetAuth(options.Credential{Username: "root", Password: env(t, "IT_ADMIN_PW"), AuthSource: "admin"}))
	if err != nil {
		t.Fatal(err)
	}
	defer slowClient.Disconnect(ctx)
	done := make(chan error, 1)
	go func() {
		// One operation (no getMore): the first batch covers every document.
		cur, err := slowClient.Database("scratch").Collection("sleepy").Find(ctx, bson.D{{Key: "$where", Value: "sleep(100); return true"}},
			options.Find().SetBatchSize(1000))
		if err == nil {
			for cur.Next(ctx) {
			}
			err = cur.Err()
		}
		done <- err
	}()

	p := newPortal(t, rsProfile(t))
	mon := p.login("olga", "other", "rs", "monitor", "monitor-pw")
	var op map[string]any
	for range 50 {
		// The client's awaitable hello heartbeats are operations too; pick the query.
		_, m := mon.do("GET", "/api/v1/operations?app=it-sleeper&ns=scratch.sleepy", nil)
		if ops, _ := m["operations"].([]any); len(ops) > 0 {
			op = ops[0].(map[string]any)
			if m["allUsers"] != true {
				t.Fatalf("clusterMonitor should see all users: %v", m)
			}
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if op == nil {
		t.Fatal("the slow operation is not listed")
	}
	opid := op["opid"]
	idText := strings.Trim(jsonString(opid), `"`)
	// Confirmation required.
	if code, m := mon.do("POST", "/api/v1/operations/kill", map[string]any{"opid": opid, "confirm": "nope"}); code != http.StatusPreconditionRequired {
		t.Fatalf("unconfirmed kill: %d %v", code, m)
	}
	// clusterMonitor has no killop: MongoDB refuses.
	if code, m := mon.do("POST", "/api/v1/operations/kill", map[string]any{"opid": opid, "confirm": idText}); code != http.StatusForbidden || !strings.Contains(errField(m, "message").(string), "killop") {
		t.Fatalf("kill without privilege: %d %v", code, m)
	}
	ops := p.login("oscar", "other", "rs", "opsadmin", "opsadmin-pw")
	if code, m := ops.do("POST", "/api/v1/operations/kill", map[string]any{"opid": opid, "confirm": idText}); code != 200 || m["killed"] != true {
		t.Fatalf("kill: %d %v", code, m)
	}
	select {
	case err := <-done:
		if err == nil || !strings.Contains(strings.ToLower(err.Error()), "interrupt") {
			t.Fatalf("the killed operation finished with %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the operation was not ended")
	}
	// It is gone now: a second kill is refused by the portal.
	if code, _ := ops.do("POST", "/api/v1/operations/kill", map[string]any{"opid": opid, "confirm": idText}); code != http.StatusConflict {
		t.Fatalf("second kill: %d", code)
	}
	// Idle connections are listed separately and are never operations to kill.
	_, m := ops.do("GET", "/api/v1/operations?state=idle&limit=5", nil)
	if m["total"].(float64) < 1 || len(m["operations"].([]any)) > 5 {
		t.Fatalf("idle listing: %v", m)
	}
}

func jsonString(v any) string { b, _ := json.Marshal(v); return string(b) }

// sharedPortal is one replica of a portal deployment with the shared store.
type sharedPortal struct {
	*portal
	srv *api.Server
	log *audit.Log
}

func newSharedPortal(t *testing.T, pod string) *sharedPortal {
	t.Helper()
	cfg, err := config.Parse([]byte("identity:\n  mode: header\n  developerGroups: [devs]\n  sreGroups: [sres]\nprofiles:\n  - name: placeholder\n    uri: mongodb://x/\n    tls: {mode: disabled}\n"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Profiles = []config.Profile{rsProfile(t)}
	dir := t.TempDir()
	write := func(name, v string) string {
		f := dir + "/" + name
		if err := os.WriteFile(f, []byte(v), 0o600); err != nil {
			t.Fatal(err)
		}
		return f
	}
	cfg.Store = config.StoreConfig{Enabled: true, Profile: "rs", Database: "mongo_portal", Mechanism: "SCRAM-SHA-256", AuthSource: "admin",
		UsernameFile: write("u", "portalstore"), PasswordFile: write("p", "portalstore-pw")}
	cfg.Audit.Persist, cfg.Audit.Retention, cfg.Session.Registry = true, 24*time.Hour, true
	cfg.RBAC.Policy = "g, platform, role:platform-admin\n"
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	st := store.New(cfg, logger)
	if err := st.Connect(context.Background()); err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { st.Close(context.Background()) })
	key := []byte("integration-test-session-key-0123456789")
	res, _ := identity.NewResolver(identity.Options{Config: cfg.Identity, Key: key, SecureCookie: true, MaxAge: time.Hour, Logger: logger})
	rb, _ := rbac.NewStore(rbac.Source{Inline: cfg.RBAC.Policy, Extra: cfg.LegacyRBACPolicy(), DefaultRole: *cfg.RBAC.DefaultRole}, logger)
	ss := session.NewStore(session.Options{IdleTimeout: time.Hour, AbsoluteTimeout: time.Hour, MaxPerUser: 5, MaxTotal: 100})
	t.Cleanup(ss.Close)
	alog := audit.NewWithOptions(logger, audit.Options{Capacity: 100, Pod: pod, Sink: st.Audit()})
	srv := api.New(api.Deps{Config: cfg, Identity: res, RBAC: rb, CSRFKey: key, Store: ss, Audit: alog, Metrics: metrics.New(), Logger: logger,
		Pod: pod, Registry: st.Sessions(), AuditChain: st.Audit().Chain, Invalidations: st.Invalidations(),
		StoreStatus: func() map[string]any { return map[string]any{"state": st.Status().State} }})
	return &sharedPortal{portal: &portal{t: t, h: srv.Handler(), store: ss}, srv: srv, log: alog}
}

// A cache invalidation requested on one replica is applied by the others
// and every replica's result is recorded.
func TestCacheInvalidationAcrossReplicas(t *testing.T) {
	ctx := context.Background()
	_ = adminClient(t).Database("mongo_portal").Collection("cache_invalidations").Drop(ctx)
	since := time.Now().UTC().Add(-time.Minute)
	a, b := newSharedPortal(t, "portal-a"), newSharedPortal(t, "portal-b")
	admin := &client{p: a.portal, user: "pat", groups: "platform"}
	_, me := admin.do("GET", "/api/v1/me", nil)
	admin.csrf = me["csrfToken"].(string)
	code, m := admin.do("POST", "/api/v1/admin/caches/invalidate", map[string]any{"caches": []string{"rbac-policy", "identities"}, "scope": "all", "confirm": "invalidate"})
	if code != 200 || m["id"] == nil {
		t.Fatalf("invalidate on a: %d %v", code, m)
	}
	if n := b.srv.SyncCaches(ctx, since); n != 1 {
		t.Fatalf("b applied %d invalidations", n)
	}
	if n := b.srv.SyncCaches(ctx, since); n != 0 {
		t.Fatalf("an invalidation must be applied once, got %d", n)
	}
	if n := a.srv.SyncCaches(ctx, since); n != 0 {
		t.Fatalf("the origin must not apply its own invalidation again, got %d", n)
	}
	viewer := &client{p: b.portal, user: "pat", groups: "platform"}
	_, m = viewer.do("GET", "/api/v1/admin/caches", nil)
	recent, _ := m["recent"].([]any)
	if len(recent) != 1 {
		t.Fatalf("recent invalidations on b: %v", m)
	}
	applied := recent[0].(map[string]any)["applied"].([]any)
	if len(applied) != 2 {
		t.Fatalf("both replicas must have applied it: %v", applied)
	}
}

// Two replicas share the audit trail and the session registry: an
// administrator on one replica sees and revokes a session held by the other.
func TestSharedStoreAuditAndRegistry(t *testing.T) {
	ctx := context.Background()
	_ = adminClient(t).Database("mongo_portal").Drop(ctx)
	a, b := newSharedPortal(t, "portal-a"), newSharedPortal(t, "portal-b")

	u := a.login("dana", "devs", "rs", "reader", "reader-pw")
	a.srv.SyncRegistry(ctx)
	admin := &client{p: b.portal, user: "pat", groups: "platform"}
	_, me := admin.do("GET", "/api/v1/me", nil)
	admin.csrf = me["csrfToken"].(string)
	_, m := admin.do("GET", "/api/v1/admin/sessions?user=dana", nil)
	rows, _ := m["sessions"].([]any)
	if m["source"] != "registry" || len(rows) != 1 || rows[0].(map[string]any)["pod"] != "portal-a" {
		t.Fatalf("registry listing on b: %v", m)
	}
	owner := rows[0].(map[string]any)["owner"].(string)
	if code, m := admin.do("POST", "/api/v1/admin/sessions/revoke", map[string]string{"owner": owner}); code != 200 || m["revoked"].(float64) < 1 {
		t.Fatalf("revoke on b: %d %v", code, m)
	}
	a.srv.SyncRegistry(ctx)
	if code, _ := u.do("GET", "/api/v1/session", nil); code != http.StatusUnauthorized {
		t.Fatalf("revoked session still works on a: %d", code)
	}

	// Audit events of a are searchable on b (the writer flushes every second).
	for range 50 {
		_, m = admin.do("GET", "/api/v1/audit?scope=all&action=mongodb_login&user=dana", nil)
		if ev, _ := m["events"].([]any); len(ev) == 1 {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if m["durable"] != true || len(m["events"].([]any)) != 1 {
		t.Fatalf("durable audit on b: %v", m)
	}
	if _, m = admin.do("GET", "/api/v1/audit/verify?pod=portal-a", nil); m["intact"] != true || m["checked"].(float64) < 1 {
		t.Fatalf("chain verification: %v", m)
	}
	// Altering a stored event breaks the chain.
	if _, err := adminClient(t).Database("mongo_portal").Collection("audit_events").UpdateOne(ctx,
		bson.D{{Key: "pod", Value: "portal-a"}, {Key: "seq", Value: 1}}, bson.D{{Key: "$set", Value: bson.D{{Key: "outcome", Value: "denied"}}}}); err != nil {
		t.Fatal(err)
	}
	if _, m = admin.do("GET", "/api/v1/audit/verify?pod=portal-a", nil); m["intact"] != false || m["brokenAtSeq"].(float64) != 1 {
		t.Fatalf("tampering not detected: %v", m)
	}
	// The TTL index for retention exists.
	specs, _ := adminClient(t).Database("mongo_portal").Collection("audit_events").Indexes().ListSpecifications(ctx)
	ttl := false
	for _, s := range specs {
		if s.Name == "time_ttl" && s.ExpireAfterSeconds != nil && *s.ExpireAfterSeconds == 86400 {
			ttl = true
		}
	}
	if !ttl {
		t.Fatalf("retention index missing: %+v", specs)
	}
}
