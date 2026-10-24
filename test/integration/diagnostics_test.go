//go:build integration

package integration

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/krishnamanaiducloud/mongo-portal/internal/config"
	"github.com/krishnamanaiducloud/mongo-portal/internal/preflight"
)

// Operations that wait by design (a change stream waiting for events) are
// shown as expected waits, never as slow; a long query still is slow.
func TestExpectedWaitsAreNotSlow(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	seedDocs(t, "scratch", "watched", 200)
	watcher, err := mongo.Connect(options.Client().ApplyURI(env(t, "IT_RS_URI")).SetAppName("it-watcher").
		SetAuth(options.Credential{Username: "root", Password: env(t, "IT_ADMIN_PW"), AuthSource: "admin"}))
	if err != nil {
		t.Fatal(err)
	}
	defer watcher.Disconnect(context.Background())
	go func() {
		cs, err := watcher.Database("scratch").Collection("watched").Watch(ctx, mongo.Pipeline{}, options.ChangeStream().SetMaxAwaitTime(20*time.Second))
		if err == nil {
			cs.Next(ctx)
		}
	}()
	go func() {
		cur, err := watcher.Database("scratch").Collection("watched").Find(ctx, bson.D{{Key: "$where", Value: "sleep(100); return true"}}, options.Find().SetBatchSize(1000))
		if err == nil {
			for cur.Next(ctx) {
			}
		}
	}()

	p := newPortal(t, rsProfile(t))
	mon := p.login("olga", "other", "rs", "monitor", "monitor-pw")
	var stream, query map[string]any
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) && (stream == nil || query == nil || query["slow"] != true) {
		_, m := mon.do("GET", "/api/v1/operations?app=it-watcher&ns=scratch.watched", nil)
		ops, _ := m["operations"].([]any)
		for _, o := range ops {
			op := o.(map[string]any)
			if op["expectedWait"] != nil {
				stream = op
			} else if op["op"] == "query" {
				query = op
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	if stream == nil || stream["slow"] != false || !strings.Contains(stream["expectedWait"].(string), "change stream") {
		t.Fatalf("change stream wait: %v", stream)
	}
	if query == nil || query["slow"] != true {
		t.Fatalf("a long query must still be slow: %v", query)
	}
	cancel()
}

// The read-only preflight against real deployments: topology, version, TLS
// verification and a precise reason for a host name mismatch.
func TestPreflightAgainstDeployments(t *testing.T) {
	ctx := context.Background()
	good, wrong := tlsProfile(t), tlsProfile(t)
	wrong.Name, wrong.URI = "wrongname", env(t, "IT_TLS_WRONGNAME_URI")
	rs := rsProfile(t)
	rs.ReplicaSet = ""
	cfg := &config.Config{Profiles: []config.Profile{rs, good, wrong}}
	o := preflight.Options{Timeout: 5 * time.Second}

	rep := preflight.ProfileReport(ctx, cfg, "rs", o)
	if r := result(rep, "MongoDB topology"); r == nil || r.Status != preflight.Pass || !strings.Contains(r.Detail, "replica set") {
		t.Fatalf("topology: %+v", rep.Results)
	}
	if r := result(rep, "MongoDB version"); r == nil || r.Status != preflight.Pass {
		t.Fatalf("version: %+v", rep.Results)
	}
	// The test PKI is short-lived, so certificate checks may warn about the
	// expiry; verification itself must succeed.
	rep = preflight.ProfileReport(ctx, cfg, "tls", o)
	if r := result(rep, "TLS"); r == nil || r.Status == preflight.Fail || !strings.Contains(r.Detail, "verified") || rep.Failed() {
		t.Fatalf("tls: %+v", rep.Results)
	}
	rep = preflight.ProfileReport(ctx, cfg, "wrongname", o)
	if r := result(rep, "TLS"); r == nil || r.Status != preflight.Fail || !strings.Contains(r.Detail, "host name") {
		t.Fatalf("host name mismatch: %+v", rep.Results)
	}
	// A configured replica set name that differs is a failure.
	rs.ReplicaSet = "not-the-set"
	cfg.Profiles[0] = rs
	if r := result(preflight.ProfileReport(ctx, cfg, "rs", o), "MongoDB topology"); r == nil || r.Status != preflight.Fail {
		t.Fatalf("replica set mismatch: %+v", r)
	}

	// The same checks through the API, for signed-in users only.
	p := newPortal(t, rsProfile(t))
	c := &client{p: p, user: "dana", groups: "devs"}
	if code, m := c.do("GET", "/api/v1/profiles/rs/diagnostics", nil); code != http.StatusOK || m["summary"] == nil {
		t.Fatalf("diagnostics api: %d %v", code, m)
	}
	anon := &client{p: p}
	if code, _ := anon.do("GET", "/api/v1/profiles/rs/diagnostics", nil); code != http.StatusUnauthorized {
		t.Fatalf("anonymous diagnostics: %d", code)
	}
}

func result(rep preflight.Report, check string) *preflight.Result {
	for i := range rep.Results {
		if rep.Results[i].Check == check {
			return &rep.Results[i]
		}
	}
	return nil
}
