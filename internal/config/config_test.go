package config

import (
	"strings"
	"testing"
)

const valid = `
environment: test
identity:
  mode: header
  developerGroups: [devs]
  sreGroups: [sres]
profiles:
  - name: primary
    uri: mongodb://mongo-0.mongo:27017,mongo-1.mongo:27017/?replicaSet=rs0
    tls:
      mode: disabled
`

func TestParseValidAndDefaults(t *testing.T) {
	c, err := Parse([]byte(valid))
	if err != nil {
		t.Fatal(err)
	}
	if c.Server.ListenAddress != "127.0.0.1:8080" || c.Session.IdleTimeout == 0 || !*c.Session.SecureCookie {
		t.Fatalf("defaults not applied: %+v", c.Server)
	}
	p, ok := c.Profile("primary")
	if !ok || p.DefaultAuthSource != "admin" || len(p.AuthMechanisms) != 2 {
		t.Fatalf("profile defaults: %+v", p)
	}
}

func TestRejectsUnsafeConfig(t *testing.T) {
	cases := map[string]string{
		"missing tls mode":         strings.Replace(valid, "mode: disabled", "caFile: /x", 1),
		"credentials in uri":       strings.Replace(valid, "mongodb://mongo-0", "mongodb://root:pw@mongo-0", 1),
		"tlsInsecure in uri":       strings.Replace(valid, "replicaSet=rs0", "replicaSet=rs0&tlsInsecure=true", 1),
		"tls option in uri":        strings.Replace(valid, "replicaSet=rs0", "replicaSet=rs0&tls=true", 1),
		"verification disabled":    strings.Replace(valid, "mode: disabled", "mode: enabled\n      verifyServerCertificate: false", 1),
		"unknown field":            valid + "\nbogus: 1\n",
		"bad identity mode":        strings.Replace(valid, "mode: header", "mode: none", 1),
		"bad openshift enabled":    strings.Replace(valid, "mode: header", "openshift:\n    enabled: sometimes", 1),
		"http api url":             strings.Replace(valid, "mode: header", "openshift:\n    apiURL: http://kubernetes", 1),
		"group with comma":         strings.Replace(valid, "[devs]", "[\"a,b\"]", 1),
		"bad default role":         valid + "rbac:\n  defaultRole: readonly\n",
		"tls cert without key":     valid + "server:\n  tls:\n    certFile: /tls.crt\n",
		"require sso without src":  strings.Replace(valid, "mode: header", "requireSSO: true\n  openshift:\n    enabled: \"false\"", 1),
		"plaintext in production":  strings.Replace(valid, "environment: test", "environment: production", 1),
		"cert files with disabled": strings.Replace(valid, "mode: disabled", "mode: disabled\n      caFile: /ca.pem", 1),
		"bad mechanism":            strings.Replace(valid, "tls:", "authMechanisms: [PLAIN]\n    tls:", 1),
	}
	for name, raw := range cases {
		if _, err := Parse([]byte(raw)); err == nil {
			t.Errorf("%s: expected validation error", name)
		}
	}
}

func TestProductionPlaintextRequiresApproval(t *testing.T) {
	raw := strings.Replace(valid, "environment: test", "environment: production", 1)
	raw = strings.Replace(raw, "mode: disabled", "mode: disabled\n    plaintextApproved: true\n    securityExceptionRef: SEC-1", 1)
	// plaintextApproved belongs to the profile, not tls: fix indentation.
	raw = strings.Replace(raw, "      mode: disabled\n    plaintextApproved", "      mode: disabled\n    plaintextApproved", 1)
	if _, err := Parse([]byte(raw)); err != nil {
		t.Fatalf("approved plaintext should be accepted: %v", err)
	}
}

func TestIdentityDefaultsArePassive(t *testing.T) {
	c, err := Parse([]byte("profiles:\n  - name: p\n    uri: mongodb://a/\n    tls: {mode: disabled}\n"))
	if err != nil {
		t.Fatalf("a configuration without any SSO settings must be valid: %v", err)
	}
	if c.Identity.OpenShift.Enabled != EnabledAuto || c.Identity.RequireSSO || c.Identity.Header.Enabled {
		t.Fatalf("identity defaults: %+v", c.Identity)
	}
	if *c.RBAC.DefaultRole != "role:mongodb" || c.RBAC.PolicyDir == "" {
		t.Fatalf("rbac defaults: %+v", c.RBAC)
	}
	// Deprecated mode: header maps onto the header source and disables auto OpenShift.
	c, err = Parse([]byte(valid))
	if err != nil {
		t.Fatal(err)
	}
	if !c.Identity.Header.Enabled || c.Identity.OpenShift.Enabled != EnabledFalse {
		t.Fatalf("legacy mode mapping: %+v", c.Identity)
	}
	if got := c.LegacyRBACPolicy(); got != "g, devs, role:readonly\ng, sres, role:admin\n" {
		t.Fatalf("legacy policy: %q", got)
	}
	// An explicit default role of "" grants nothing.
	c, err = Parse([]byte(valid + "rbac:\n  defaultRole: \"\"\n"))
	if err != nil || *c.RBAC.DefaultRole != "" {
		t.Fatalf("empty default role: %v %v", err, c)
	}
}

func TestDevModeGate(t *testing.T) {
	raw := strings.Replace(valid, "mode: header", "mode: dev\n  dev:\n    user: me\n    groups: [devs]", 1)
	if _, err := Parse([]byte(raw)); err == nil {
		t.Fatal("dev mode without gate must be rejected")
	}
	t.Setenv(DevIdentityGateEnv, "true")
	if _, err := Parse([]byte(raw)); err != nil {
		t.Fatalf("dev mode with gate: %v", err)
	}
}

// TestCommittedConfigs validates every configuration file in the repository.
// The production overlay must refuse to start until the MongoDB TLS decision
// is recorded (TLS enabled or plaintext exception approved).
func TestCommittedConfigs(t *testing.T) {
	t.Setenv(DevIdentityGateEnv, "true")
	if _, err := Load("../../config/dev.example.yaml"); err != nil {
		t.Errorf("dev.example.yaml: %v", err)
	}
	const dir = "../../examples/kustomize/"
	for _, env := range []string{"dev", "test"} {
		if _, err := Load(dir + "overlays/" + env + "/config.yaml"); err != nil {
			t.Errorf("overlay %s: %v", env, err)
		}
	}
	if _, err := Load(dir + "base/config.yaml"); err != nil {
		t.Errorf("base: %v", err)
	}
	_, err := Load(dir + "overlays/prod/config.yaml")
	if err == nil || !strings.Contains(err.Error(), "plaintextApproved") {
		t.Errorf("prod overlay must require an explicit plaintext decision, got %v", err)
	}
}

func TestValidateProfileURI(t *testing.T) {
	for _, ok := range []string{"mongodb://a:27017", "mongodb://a,b,c/?replicaSet=rs0&readPreference=secondary", "mongodb+srv://cluster.example.com/"} {
		if err := ValidateProfileURI(ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "http://a", "mongodb://", "mongodb://u@a", "mongodb://a/?authSource=admin", "mongodb://a/?TLSAllowInvalidCertificates=true"} {
		if err := ValidateProfileURI(bad); err == nil {
			t.Errorf("%s: expected error", bad)
		}
	}
}
