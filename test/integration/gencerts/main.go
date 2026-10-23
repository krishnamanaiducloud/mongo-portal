// Command gencerts writes a throwaway PKI for integration tests: a CA, a
// MongoDB server certificate, a client certificate and an unrelated CA.
// Never use these files outside disposable test environments.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	out := flag.String("out", "certs", "output directory")
	hosts := flag.String("hosts", "mongotls,localhost", "comma separated server DNS names")
	flag.Parse()
	if err := os.MkdirAll(*out, 0o755); err != nil {
		log.Fatal(err)
	}

	caKey, caCert, caDER := newCA("portal-it-ca")
	_, _, otherDER := newCA("unrelated-ca")
	write(*out, "ca.crt", pemCert(caDER))
	write(*out, "other-ca.crt", pemCert(otherDER))

	srvKey, srvDER := leaf(caKey, caCert, "mongotls", strings.Split(*hosts, ","), x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth)
	write(*out, "server.pem", append(pemCert(srvDER), pemKey(srvKey)...))

	cliKey, cliDER := leaf(caKey, caCert, "portal-client", nil, x509.ExtKeyUsageClientAuth)
	write(*out, "client.crt", pemCert(cliDER))
	write(*out, "client.key", pemKey(cliKey))
	write(*out, "client.pem", append(pemCert(cliDER), pemKey(cliKey)...))
	log.Printf("wrote test PKI to %s", *out)
}

func newCA(cn string) (*ecdsa.PrivateKey, *x509.Certificate, []byte) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: serial(), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		log.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return key, c, der
}

func leaf(caKey *ecdsa.PrivateKey, ca *x509.Certificate, cn string, dns []string, eku ...x509.ExtKeyUsage) (*ecdsa.PrivateKey, []byte) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: serial(), Subject: pkix.Name{CommonName: cn, Organization: []string{"portal-it"}},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour),
		DNSNames: dns, ExtKeyUsage: eku, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca, &key.PublicKey, caKey)
	if err != nil {
		log.Fatal(err)
	}
	return key, der
}

func serial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	return n
}

func pemCert(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func pemKey(k *ecdsa.PrivateKey) []byte {
	b, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		log.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: b})
}

func write(dir, name string, b []byte) {
	// World-readable so the mongod container user can read its test key.
	if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil { // #nosec G306 -- disposable test PKI
		log.Fatal(err)
	}
}
