package mongoconn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/krishnamanaiducloud/mongo-portal/internal/config"
)

func ptr(s string) *string { return &s }

func TestCapabilities(t *testing.T) {
	st := &ConnectionStatus{}
	st.AuthInfo.Privileges = []Privilege{
		{Resource: Resource{DB: ptr("app"), Collection: ptr("")}, Actions: []string{"find", "listCollections", "listIndexes", "dbStats", "collStats"}},
		{Resource: Resource{DB: ptr("app"), Collection: ptr("orders")}, Actions: []string{"find", "insert", "update", "remove"}},
		{Resource: Resource{Cluster: true}, Actions: []string{"listDatabases"}},
	}
	db := st.CapabilitiesFor("app", "")
	if !db.ListCollections || db.Insert {
		t.Fatalf("db caps wrong: %+v", db)
	}
	users := st.CapabilitiesFor("app", "users")
	if !users.Find || users.Insert || users.Remove {
		t.Fatalf("users caps wrong: %+v", users)
	}
	orders := st.CapabilitiesFor("app", "orders")
	if !orders.Find || !orders.Insert || !orders.Update || !orders.Remove || orders.DropCollection {
		t.Fatalf("orders caps wrong: %+v", orders)
	}
	other := st.CapabilitiesFor("other", "x")
	if other.Find {
		t.Fatalf("other db should have no caps: %+v", other)
	}
	if got := st.Databases(); len(got) != 1 || got[0] != "app" {
		t.Fatalf("databases: %v", got)
	}

	root := &ConnectionStatus{}
	root.AuthInfo.Privileges = []Privilege{{Resource: Resource{AnyResource: true}, Actions: []string{"anyAction", "find", "insert"}}}
	if c := root.CapabilitiesFor("x", "y"); !c.Find || !c.Insert {
		t.Fatalf("anyResource caps: %+v", c)
	}
	anyDB := &ConnectionStatus{}
	anyDB.AuthInfo.Privileges = []Privilege{{Resource: Resource{DB: ptr(""), Collection: ptr("")}, Actions: []string{"find"}}}
	if c := anyDB.CapabilitiesFor("whatever", "c"); !c.Find {
		t.Fatalf("wildcard db: %+v", c)
	}
}

func TestHasUser(t *testing.T) {
	st := &ConnectionStatus{}
	st.AuthInfo.AuthenticatedUsers = []UserRef{{User: "alice", DB: "admin"}}
	if !st.HasUser("alice", "admin") || st.HasUser("alice", "test") || st.HasUser("bob", "admin") {
		t.Fatal("HasUser mismatch")
	}
}

func baseProfile(mode string) *config.Profile {
	return &config.Profile{
		Name: "p", URI: "mongodb://db-0.db:27017,db-1.db:27017/?replicaSet=rs0",
		DefaultAuthSource: "admin", AuthMechanisms: []string{"SCRAM-SHA-256"},
		ReadPreference: "primary", ConnectTimeout: time.Second, ServerSelectionTimeout: time.Second,
		OperationTimeout: time.Minute, MaxPoolSize: 5, MaxConnIdleTime: time.Minute,
		TLS: config.TLSConfig{Mode: mode, MinVersion: "1.2"},
	}
}

func TestClientOptionsTLSModes(t *testing.T) {
	opts, err := ClientOptions(baseProfile(config.TLSDisabled), PoolHooks{})
	if err != nil {
		t.Fatal(err)
	}
	if opts.TLSConfig != nil {
		t.Fatal("disabled mode must not configure TLS")
	}

	dir := t.TempDir()
	caFile, certFile, keyFile := writeTestPKI(t, dir)
	p := baseProfile(config.TLSEnabled)
	p.TLS.CAFile = caFile
	p.TLS.ClientCertFile, p.TLS.ClientKeyFile = certFile, keyFile
	p.TLS.MinVersion = "1.3"
	opts, err = ClientOptions(p, PoolHooks{})
	if err != nil {
		t.Fatal(err)
	}
	tc := opts.TLSConfig
	if tc == nil || tc.InsecureSkipVerify || tc.RootCAs == nil || tc.MinVersion != tls.VersionTLS13 || tc.GetClientCertificate == nil {
		t.Fatalf("unexpected TLS config: %+v", tc)
	}
	if c, err := tc.GetClientCertificate(nil); err != nil || c == nil {
		t.Fatalf("client cert: %v", err)
	}

	f := false
	p.TLS.VerifyServerCertificate = &f
	if _, err := ClientOptions(p, PoolHooks{}); err == nil {
		t.Fatal("verifyServerCertificate=false must be rejected")
	}

	bad := baseProfile(config.TLSEnabled)
	bad.TLS.CAFile = filepath.Join(dir, "missing.pem")
	if _, err := ClientOptions(bad, PoolHooks{}); err == nil {
		t.Fatal("missing CA must fail")
	}
}

func TestClientOptionsRejectsUnsafeURI(t *testing.T) {
	for _, uri := range []string{
		"mongodb://user:pw@h:27017/",
		"mongodb://h:27017/?tlsInsecure=true",
		"mongodb://h:27017/?tls=false",
		"mongodb://h:27017/?authSource=admin",
		"http://h/",
	} {
		p := baseProfile(config.TLSDisabled)
		p.URI = uri
		if _, err := ClientOptions(p, PoolHooks{}); err == nil {
			t.Errorf("uri %q should be rejected", uri)
		}
	}
}

func TestCredentialsValidate(t *testing.T) {
	p := baseProfile(config.TLSDisabled)
	ok := Credentials{Username: "u", Password: "p", AuthSource: "admin"}
	if err := ok.Validate(p); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]Credentials{
		"no user":       {Password: "p", AuthSource: "admin"},
		"no password":   {Username: "u", AuthSource: "admin"},
		"bad source":    {Username: "u", Password: "p", AuthSource: "a.b"},
		"bad mechanism": {Username: "u", Password: "p", AuthSource: "admin", Mechanism: "SCRAM-SHA-1"},
		"newline":       {Username: "u\n", Password: "p", AuthSource: "admin"},
	} {
		if err := c.Validate(p); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestClassify(t *testing.T) {
	if k := Classify(errors.New("connection() error occurred during connection handshake: auth error: sasl conversation error: unable to authenticate using mechanism \"SCRAM-SHA-256\": (AuthenticationFailed) Authentication failed.")).Kind; k != KindAuthFailed {
		t.Errorf("auth: %s", k)
	}
	// Timeouts during the SASL handshake are not credential failures (they
	// must not count towards lockout).
	for _, msg := range []string{
		`connection() error occurred during connection handshake: auth error: unable to authenticate using mechanism "SCRAM-SHA-256": connection(rs3:27017[-310]) incomplete read of message header: context deadline exceeded: client timed out waiting for server response: read tcp 1.2.3.4:1->1.2.3.5:27017: i/o timeout`,
		`connection() error occurred during connection handshake: auth error: unable to authenticate using mechanism "SCRAM-SHA-256": calculated server-side timeout (0 ms) is less than or equal to 0 (): operation not sent to server, as Timeout would be exceeded: context deadline exceeded`,
	} {
		if k := Classify(errors.New(msg)).Kind; k == KindAuthFailed {
			t.Errorf("timeout misclassified as auth failure: %s", msg)
		}
	}
	if k := Classify(x509.UnknownAuthorityError{}).Kind; k != KindTLS {
		t.Errorf("tls: %s", k)
	}
	if k := fromCode(13, "Unauthorized", "", nil).Kind; k != KindUnauthorized {
		t.Errorf("13: %s", k)
	}
	if s := (&Error{Kind: KindUnauthorized}).HTTPStatus(); s != 403 {
		t.Errorf("status %d", s)
	}
}

func TestKeyPairReload(t *testing.T) {
	dir := t.TempDir()
	_, certFile, keyFile := writeTestPKI(t, dir)
	kp := &keyPairLoader{certFile: certFile, keyFile: keyFile}
	c1, err := kp.get()
	if err != nil {
		t.Fatal(err)
	}
	// Rotate with a new pair and a later mtime.
	_, cert2, key2 := writeTestPKI(t, t.TempDir())
	copyFile(t, cert2, certFile)
	copyFile(t, key2, keyFile)
	later := time.Now().Add(time.Minute)
	_ = os.Chtimes(certFile, later, later)
	_ = os.Chtimes(keyFile, later, later)
	c2, err := kp.get()
	if err != nil {
		t.Fatal(err)
	}
	if string(c1.Certificate[0]) == string(c2.Certificate[0]) {
		t.Fatal("certificate was not reloaded after rotation")
	}
}

func copyFile(t *testing.T, from, to string) {
	t.Helper()
	b, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// writeTestPKI writes a CA and a client certificate signed by it.
func writeTestPKI(t *testing.T, dir string) (caFile, certFile, keyFile string) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "client"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, KeyUsage: x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	caFile = filepath.Join(dir, "ca.crt")
	certFile = filepath.Join(dir, "client.crt")
	keyFile = filepath.Join(dir, "client.key")
	mustWrite(t, caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))
	mustWrite(t, certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	mustWrite(t, keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	return
}

func mustWrite(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}
