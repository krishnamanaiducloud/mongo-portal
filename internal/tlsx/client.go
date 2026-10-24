// Package tlsx builds verifying TLS configurations and HTTP clients for
// calls to identity providers and collectors. Certificate verification is
// never disabled; extra CA files are added to the system roots.
package tlsx

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io/fs"
	"net/http"
	"os"
	"time"
)

// Pool returns the system roots plus the PEM certificates of caFiles.
// Missing files are skipped (optional mounts); unreadable or empty files
// are reported.
func Pool(caFiles ...string) (*x509.CertPool, error) {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	var errs []error
	for _, f := range caFiles {
		if f == "" {
			continue
		}
		pem, err := os.ReadFile(f) // #nosec G304 -- operator supplied CA path
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				errs = append(errs, err)
			}
			continue
		}
		if !pool.AppendCertsFromPEM(pem) {
			errs = append(errs, errors.New(f+": no PEM certificates"))
		}
	}
	return pool, errors.Join(errs...)
}

// HTTPClient returns a client that verifies servers against Pool(caFiles),
// uses the proxy environment variables and never follows redirects (so
// credentials are never forwarded to another host).
func HTTPClient(timeout time.Duration, caFiles ...string) (*http.Client, error) {
	pool, err := Pool(caFiles...)
	tr := &http.Transport{
		TLSClientConfig:     &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		MaxIdleConns:        10,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: timeout,
		Proxy:               http.ProxyFromEnvironment,
	}
	return &http.Client{
		Transport:     tr,
		Timeout:       timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, err
}
