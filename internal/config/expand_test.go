package config

import (
	"slices"
	"strings"
	"testing"
	"time"
)

const placeholderConfig = `
environment: ${PORTAL_ENVIRONMENT:-test}
server:
  publicOrigin: ${PORTAL_PUBLIC_URL}
identity:
  header:
    enabled: ${HEADER_ENABLED:-true}
session:
  idleTimeout: ${SESSION_IDLE_TIMEOUT:-20m}
  cookieName: "${COOKIE_NAME:-__Host-mongo_portal_session}"
profiles:
  - name: ${MONGODB_PROFILE_ID}
    displayName: "Price $${not-a-variable}"
    uri: mongodb://${MONGODB_HOSTS}/?replicaSet=${MONGODB_REPLICA_SET}
    maxPoolSize: ${MONGODB_POOL:-7}
    tls:
      mode: ${MONGODB_TLS_MODE:-enabled}
`

func TestPlaceholdersExpand(t *testing.T) {
	t.Setenv("PORTAL_PUBLIC_URL", "https://portal.example.test")
	t.Setenv("MONGODB_PROFILE_ID", "orders")
	t.Setenv("MONGODB_HOSTS", "db-0.example.test:27017,db-1.example.test:27017")
	t.Setenv("MONGODB_REPLICA_SET", "rs-orders")
	t.Setenv("SESSION_IDLE_TIMEOUT", "")
	c, err := Parse([]byte(placeholderConfig))
	if err != nil {
		t.Fatal(err)
	}
	p, ok := c.Profile("orders")
	switch {
	case !ok:
		t.Fatalf("profile name not expanded: %+v", c.Profiles)
	case c.Environment != "test" || c.Server.PublicOrigin != "https://portal.example.test":
		t.Fatalf("server values: %q %q", c.Environment, c.Server.PublicOrigin)
	case p.URI != "mongodb://db-0.example.test:27017,db-1.example.test:27017/?replicaSet=rs-orders":
		t.Fatalf("uri: %q", p.URI)
	case p.MaxPoolSize != 7 || !c.Identity.Header.Enabled || c.Session.IdleTimeout != 20*time.Minute:
		t.Fatalf("typed defaults: pool=%d header=%v idle=%v", p.MaxPoolSize, c.Identity.Header.Enabled, c.Session.IdleTimeout)
	case p.TLS.Mode != TLSEnabled || c.Session.CookieName != "__Host-mongo_portal_session":
		t.Fatalf("string defaults: %q %q", p.TLS.Mode, c.Session.CookieName)
	case p.DisplayName != "Price ${not-a-variable}":
		t.Fatalf("escape: %q", p.DisplayName)
	}
	if got := Placeholders([]byte(placeholderConfig)); !slices.Contains(got, "MONGODB_HOSTS") || slices.Contains(got, "not-a-variable") {
		t.Fatalf("placeholders: %v", got)
	}
}

func TestMongoOIDCOptions(t *testing.T) {
	oidc := strings.Replace(valid, "      mode: disabled", "      mode: disabled\n    authMechanisms: [MONGODB-OIDC]\n"+
		"    oidc: {issuer: https://idp.example.test, clientID: c, autoConnect: true, authParams: {audience: api://mongodb}}", 1)
	c, err := Parse([]byte(oidc))
	if err != nil {
		t.Fatal(err)
	}
	if o := c.Profiles[0].OIDC; !o.AutoConnect || !o.Interactive() || o.AuthParams["audience"] != "api://mongodb" {
		t.Fatalf("oidc options: %+v", o)
	}
	reserved := strings.Replace(oidc, "{audience: api://mongodb}", "{prompt: login}", 1)
	if _, err := Parse([]byte(reserved)); err == nil || !strings.Contains(err.Error(), `must not set "prompt"`) {
		t.Fatalf("reserved authParams must be rejected: %v", err)
	}
}

func TestPlaceholdersMissingAndInjection(t *testing.T) {
	t.Setenv("PORTAL_PUBLIC_URL", "https://portal.example.test")
	t.Setenv("MONGODB_REPLICA_SET", "rs0")
	_, err := Parse([]byte(placeholderConfig))
	if err == nil || !strings.Contains(err.Error(), "MONGODB_PROFILE_ID") || !strings.Contains(err.Error(), "MONGODB_HOSTS") {
		t.Fatalf("missing variables must be reported by name: %v", err)
	}
	// A value can never add YAML structure.
	t.Setenv("MONGODB_PROFILE_ID", "x\n    plaintextApproved: true")
	t.Setenv("MONGODB_HOSTS", "db:27017")
	if _, err := Parse([]byte(placeholderConfig)); err == nil || !strings.Contains(err.Error(), "DNS-label") {
		t.Fatalf("a value with YAML syntax must stay one value: %v", err)
	}
}
