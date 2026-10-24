package preflight

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/krishnamanaiducloud/mongo-portal/internal/config"
	"github.com/krishnamanaiducloud/mongo-portal/internal/testidp"
)

func find(rep Report, check string) *Result {
	for i := range rep.Results {
		if rep.Results[i].Check == check {
			return &rep.Results[i]
		}
	}
	return nil
}

func TestHostPorts(t *testing.T) {
	got, srv := hostPorts("mongodb://a.example.test,b.example.test:27018/?replicaSet=rs0")
	if srv || len(got) != 2 || got[0] != "a.example.test:27017" || got[1] != "b.example.test:27018" {
		t.Fatalf("hosts: %v %v", got, srv)
	}
	if got, srv := hostPorts("mongodb+srv://cluster.example.test/"); !srv || got[0] != "cluster.example.test" {
		t.Fatalf("srv: %v %v", got, srv)
	}
}

// A profile pointing at a TLS server with a certificate from an unknown CA
// fails the TLS check with a precise reason, and a refused port fails TCP;
// nothing is written or authenticated.
func TestProfileTLSAndReachability(t *testing.T) {
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(srv.Close)
	addr := strings.TrimPrefix(srv.URL, "https://")
	dir := t.TempDir()
	otherCA := filepath.Join(dir, "other-ca.pem")
	_ = os.WriteFile(otherCA, selfSignedCA(t), 0o600)
	goodCA := filepath.Join(dir, "ca.pem")
	_ = os.WriteFile(goodCA, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600)

	l, _ := net.Listen("tcp", "127.0.0.1:0")
	closed := l.Addr().String()
	l.Close()

	cfg := &config.Config{Profiles: []config.Profile{
		{Name: "untrusted", URI: "mongodb://" + addr + "/", TLS: config.TLSConfig{Mode: config.TLSEnabled, CAFile: otherCA, MinVersion: "1.2"}, ReadPreference: "primary"},
		{Name: "trusted", URI: "mongodb://" + addr + "/", TLS: config.TLSConfig{Mode: config.TLSEnabled, CAFile: goodCA, MinVersion: "1.2"}, ReadPreference: "primary",
			ServerSelectionTimeout: time.Second, ConnectTimeout: time.Second, OperationTimeout: time.Second, MaxPoolSize: 1},
		{Name: "closed", URI: "mongodb://" + closed + "/", TLS: config.TLSConfig{Mode: config.TLSDisabled}, ReadPreference: "primary"},
	}}
	ctx := context.Background()
	rep := ProfileReport(ctx, cfg, "untrusted", Options{Timeout: 2 * time.Second})
	if r := find(rep, "TLS"); r == nil || r.Status != Fail || !strings.Contains(r.Detail, "not signed by a trusted CA") {
		t.Fatalf("untrusted CA: %+v", rep.Results)
	}
	rep = ProfileReport(ctx, cfg, "trusted", Options{Timeout: 2 * time.Second})
	if r := find(rep, "TLS"); r == nil || r.Status != Pass || !strings.Contains(r.Detail, "verified") {
		t.Fatalf("trusted CA: %+v", rep.Results)
	}
	// The server is HTTPS, not MongoDB: hello fails, it is reported, not raised.
	if r := find(rep, "MongoDB hello"); r == nil || r.Status != Fail {
		t.Fatalf("hello against a non-MongoDB server: %+v", rep.Results)
	}
	rep = ProfileReport(ctx, cfg, "closed", Options{Timeout: time.Second})
	if r := find(rep, "TCP"); r == nil || r.Status != Fail || !rep.Failed() {
		t.Fatalf("closed port: %+v", rep.Results)
	}
	if r := find(rep, "transport"); r == nil || r.Status != Warn {
		t.Fatalf("plaintext without approval must warn: %+v", rep.Results)
	}
}

func selfSignedCA(t *testing.T) []byte {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "unrelated test CA"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestDiscoveryChecks(t *testing.T) {
	srv := httptest.NewTLSServer(nil)
	idp := testidp.New(srv.URL, "c")
	srv.Config.Handler = idp.Handler()
	t.Cleanup(srv.Close)
	if d, err := discover(context.Background(), srv.Client(), srv.URL); err != nil || !strings.Contains(d, "1 signing keys") {
		t.Fatalf("discovery: %q %v", d, err)
	}
	idp.IssuerClaim = "https://elsewhere.example.test"
	if _, err := discover(context.Background(), srv.Client(), srv.URL); err == nil || !strings.Contains(err.Error(), "announces issuer") {
		t.Fatalf("issuer mismatch: %v", err)
	}
}

func TestPortalChecksNeverPrintSecrets(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "session-key")
	_ = os.WriteFile(key, []byte("short-secret-value"), 0o600)
	cfg, err := config.Parse([]byte("identity: {openshift: {enabled: \"false\"}}\nsession: {keyFile: " + key + "}\ntransfer: {tempDir: " + dir +
		"}\nprofiles:\n  - name: p\n    uri: mongodb://127.0.0.1:1/\n    tls: {mode: disabled}\n"))
	if err != nil {
		t.Fatal(err)
	}
	rep := Run(context.Background(), cfg, Options{Timeout: time.Second, Profiles: []string{"none"}})
	r := find(rep, "session key")
	if r == nil || r.Status != Fail || strings.Contains(r.Detail, "short-secret") {
		t.Fatalf("session key: %+v", r)
	}
	if r := find(rep, "transfer directory"); r == nil || r.Status != Pass {
		t.Fatalf("transfer dir: %+v", r)
	}
	if r := find(rep, "OpenShift OAuth"); r == nil || r.Status != Skip {
		t.Fatalf("openshift disabled: %+v", r)
	}
	if r := find(rep, "shared store"); r == nil || r.Status != Skip {
		t.Fatalf("store disabled: %+v", r)
	}
}
