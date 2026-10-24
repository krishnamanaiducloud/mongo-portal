package preflight

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
)

// discover reads an issuer's OpenID Connect discovery document and checks
// what MONGODB-OIDC needs from it: matching issuer, authorization and token
// endpoints, PKCE S256 and a reachable key set.
func discover(ctx context.Context, client *http.Client, issuer string) (string, error) {
	var doc struct {
		Issuer        string   `json:"issuer"`
		Authorization string   `json:"authorization_endpoint"`
		Token         string   `json:"token_endpoint"`
		JWKS          string   `json:"jwks_uri"`
		PKCE          []string `json:"code_challenge_methods_supported"`
	}
	if err := getJSON(ctx, client, strings.TrimSuffix(issuer, "/")+"/.well-known/openid-configuration", &doc); err != nil {
		return "", fmt.Errorf("discovery: %s", err.Error())
	}
	switch {
	case strings.TrimSuffix(doc.Issuer, "/") != strings.TrimSuffix(issuer, "/"):
		return "", fmt.Errorf("the provider announces issuer %q, configured %q", doc.Issuer, issuer)
	case doc.Authorization == "" || doc.Token == "" || doc.JWKS == "":
		return "", fmt.Errorf("discovery lacks authorization, token or jwks endpoints")
	}
	var keys struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := getJSON(ctx, client, doc.JWKS, &keys); err != nil {
		return "", fmt.Errorf("key set: %s", err.Error())
	}
	detail := fmt.Sprintf("discovery ok, %d signing keys", len(keys.Keys))
	if len(doc.PKCE) > 0 && !slices.Contains(doc.PKCE, "S256") {
		return "", fmt.Errorf("the provider does not support PKCE S256")
	}
	return detail, nil
}

func getJSON(ctx context.Context, client *http.Client, u string, into any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("%s", shortErr(err))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d from %s", resp.StatusCode, u)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(into)
}

func parsePEM(b []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for {
		var blk *pem.Block
		blk, b = pem.Decode(b)
		if blk == nil {
			return out, nil
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
}
