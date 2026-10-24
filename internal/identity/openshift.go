package identity

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/krishnamanaiducloud/mongo-portal/internal/config"
)

// OpenShift availability states.
const (
	StateAvailable   = "available"
	StateUnavailable = "unavailable"
	StateDisabled    = "disabled"
)

// Status describes whether OpenShift login can be offered right now.
type Status struct {
	State     string    `json:"state"`
	Reason    string    `json:"reason,omitempty"`
	CheckedAt time.Time `json:"checkedAt,omitzero"`
	Issuer    string    `json:"issuer,omitempty"`
}

type oauthMeta struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	CodeChallengeMethods  []string `json:"code_challenge_methods_supported"`
}

// OpenShift is the built-in OpenShift OAuth client. The portal's service
// account is the OAuth client (client id system:serviceaccount:<ns>:<sa>,
// client secret = the service account token), the mechanism OpenShift
// provides for service-account OAuth clients. The user's
// identity and groups are read from the OpenShift API with the user's own
// token (users/~), so the portal needs no cluster-wide permissions.
//
// It never fails hard: when the API or OAuth server is unreachable, or the
// portal does not run in OpenShift, Status reports why and OpenShift login
// is simply not offered.
type OpenShift struct {
	cfg config.OpenShiftConfig
	log *slog.Logger
	now func() time.Time

	mu     sync.RWMutex
	status Status
	meta   *oauthMeta
	client *http.Client
}

// NewOpenShift creates the client. It performs no I/O; call Run or Probe.
func NewOpenShift(cfg config.OpenShiftConfig, log *slog.Logger) *OpenShift {
	o := &OpenShift{cfg: cfg, log: log, now: time.Now}
	o.status = Status{State: StateUnavailable, Reason: "not checked yet"}
	if cfg.Enabled == config.EnabledFalse {
		o.status = Status{State: StateDisabled, Reason: "OpenShift login is turned off in the configuration"}
	}
	return o
}

// Status returns the last probe result.
func (o *OpenShift) Status() Status {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.status
}

// Available reports whether OpenShift login can be offered.
func (o *OpenShift) Available() bool { return o.Status().State == StateAvailable }

// Run probes now and then periodically until ctx ends. Unavailable servers
// are re-checked every ProbeInterval, healthy ones five times less often.
func (o *OpenShift) Run(ctx context.Context) {
	if o.cfg.Enabled == config.EnabledFalse {
		return
	}
	for {
		st := o.Probe(ctx)
		wait := o.cfg.ProbeInterval
		switch st.State {
		case StateAvailable:
			wait *= 5
		case StateDisabled:
			// Not an OpenShift cluster (or no token): re-check rarely in case
			// a token is mounted later.
			wait *= 10
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

// Probe checks the OAuth server and records the result.
func (o *OpenShift) Probe(ctx context.Context) Status {
	if o.cfg.Enabled == config.EnabledFalse {
		return o.Status()
	}
	ctx, cancel := context.WithTimeout(ctx, 2*o.cfg.RequestTimeout)
	defer cancel()
	meta, client, st := o.probe(ctx)
	st.CheckedAt = o.now().UTC()

	o.mu.Lock()
	prev := o.status
	o.status = st
	if st.State == StateAvailable {
		o.meta, o.client = meta, client
	}
	o.mu.Unlock()

	if prev.State != st.State || prev.Reason != st.Reason {
		attrs := []any{"state", st.State, "reason", st.Reason, "issuer", st.Issuer}
		switch {
		case st.State == StateAvailable:
			o.log.Info("openshift login available", attrs...)
		case st.State == StateUnavailable && o.cfg.Enabled == config.EnabledTrue:
			o.log.Warn("openshift login unavailable; MongoDB login remains available", attrs...)
		default:
			o.log.Info("openshift login not offered", attrs...)
		}
	}
	return st
}

func (o *OpenShift) probe(ctx context.Context) (*oauthMeta, *http.Client, Status) {
	unavailable := func(format string, a ...any) (*oauthMeta, *http.Client, Status) {
		return nil, nil, Status{State: StateUnavailable, Reason: fmt.Sprintf(format, a...)}
	}
	notOffered := func(reason string) (*oauthMeta, *http.Client, Status) {
		if o.cfg.Enabled == config.EnabledTrue {
			return unavailable("%s", reason)
		}
		return nil, nil, Status{State: StateDisabled, Reason: reason}
	}
	if _, err := os.Stat(o.cfg.ServiceAccountFile); err != nil {
		return notOffered("no service account token is mounted (not running in an OpenShift pod)")
	}
	client := o.newClient()

	var meta oauthMeta
	status, err := o.getJSON(ctx, client, strings.TrimSuffix(o.cfg.APIURL, "/")+"/.well-known/oauth-authorization-server", "", &meta)
	switch {
	case err != nil:
		return unavailable("the Kubernetes API server is not reachable: %s", shortErr(err))
	case status == http.StatusNotFound:
		return notOffered("the cluster has no OpenShift OAuth server")
	case status != http.StatusOK:
		return unavailable("OAuth discovery returned HTTP %d", status)
	}
	for _, u := range []string{meta.Issuer, meta.AuthorizationEndpoint, meta.TokenEndpoint} {
		if pu, err := url.Parse(u); err != nil || pu.Scheme != "https" || pu.Host == "" {
			return unavailable("OAuth discovery returned an invalid endpoint")
		}
	}
	// The token endpoint is served by the OAuth server (usually through the
	// ingress router); check that this pod can reach it.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(meta.Issuer, "/")+"/healthz", nil)
	if err != nil {
		return unavailable("invalid OAuth issuer")
	}
	resp, err := client.Do(req)
	if err != nil {
		return unavailable("the OAuth server %s is not reachable from the portal: %s", hostOf(meta.Issuer), shortErr(err))
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	_ = resp.Body.Close()
	if resp.StatusCode >= 500 {
		return unavailable("the OAuth server returned HTTP %d", resp.StatusCode)
	}
	if _, _, err := o.clientCredentials(); err != nil {
		return unavailable("%s", err.Error())
	}
	return &meta, client, Status{State: StateAvailable, Issuer: meta.Issuer}
}

// newClient trusts the system roots, the service account CA bundle (which
// in OpenShift also covers the default ingress certificate) and any extra
// CA files. Missing files are skipped. Verification is never disabled.
func (o *OpenShift) newClient() *http.Client {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	for _, f := range append([]string{o.cfg.CAFile}, o.cfg.ExtraCAFiles...) {
		if f == "" {
			continue
		}
		pem, err := os.ReadFile(f) // #nosec G304 -- operator supplied CA path
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				o.log.Debug("cannot read CA file", "file", f, "error", err.Error())
			}
			continue
		}
		pool.AppendCertsFromPEM(pem)
	}
	tr := &http.Transport{
		TLSClientConfig:     &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		MaxIdleConns:        10,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: o.cfg.RequestTimeout,
		Proxy:               http.ProxyFromEnvironment,
	}
	return &http.Client{
		Transport: tr,
		Timeout:   o.cfg.RequestTimeout,
		// Never follow redirects with credentials attached.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func (o *OpenShift) current() (*oauthMeta, *http.Client, error) {
	o.mu.RLock()
	defer o.mu.RUnlock()
	if o.status.State != StateAvailable || o.meta == nil {
		return nil, nil, ErrUnavailable
	}
	return o.meta, o.client, nil
}

// clientCredentials returns the OAuth client id and secret. The token is
// re-read every time because projected service account tokens rotate.
func (o *OpenShift) clientCredentials() (string, string, error) {
	b, err := os.ReadFile(o.cfg.ServiceAccountFile)
	if err != nil {
		return "", "", errors.New("the service account token cannot be read")
	}
	secret := strings.TrimSpace(string(b))
	id := o.cfg.ClientID
	if id == "" {
		id = serviceAccountSubject(secret)
	}
	if !strings.HasPrefix(id, "system:serviceaccount:") {
		return "", "", errors.New("cannot determine the OAuth client id from the service account token; set identity.openshift.clientID")
	}
	return id, secret, nil
}

// serviceAccountSubject reads the "sub" claim of a service account token
// (system:serviceaccount:<namespace>:<name>). The token is the portal's own
// mounted token; it is only parsed, not trusted for authentication.
func serviceAccountSubject(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		Sub string `json:"sub"`
	}
	if json.Unmarshal(payload, &claims) != nil {
		return ""
	}
	return claims.Sub
}

// AuthCodeURL returns the authorization URL for a login attempt.
func (o *OpenShift) AuthCodeURL(state, challenge, redirectURI string) (string, error) {
	meta, _, err := o.current()
	if err != nil {
		return "", err
	}
	id, _, err := o.clientCredentials()
	if err != nil {
		return "", ErrUnavailable
	}
	q := url.Values{
		"client_id":     {id},
		"response_type": {"code"},
		"redirect_uri":  {redirectURI},
		"scope":         {strings.Join(o.cfg.Scopes, " ")},
		"state":         {state},
	}
	if challenge != "" && slices.Contains(meta.CodeChallengeMethods, "S256") {
		q.Set("code_challenge", challenge)
		q.Set("code_challenge_method", "S256")
	}
	sep := "?"
	if strings.Contains(meta.AuthorizationEndpoint, "?") {
		sep = "&"
	}
	return meta.AuthorizationEndpoint + sep + q.Encode(), nil
}

// Exchange redeems an authorization code for the user's access token.
func (o *OpenShift) Exchange(ctx context.Context, code, verifier, redirectURI string) (string, time.Duration, error) {
	meta, client, err := o.current()
	if err != nil {
		return "", 0, err
	}
	id, secret, err := o.clientCredentials()
	if err != nil {
		return "", 0, ErrUnavailable
	}
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirectURI}}
	if verifier != "" && slices.Contains(meta.CodeChallengeMethods, "S256") {
		form.Set("code_verifier", verifier)
	}
	// Client authentication as RFC 6749 2.3.1: HTTP Basic with form-encoded
	// credentials, falling back to body parameters if the server rejects the
	// client (the code is not consumed when client authentication fails).
	tok, status, err := o.tokenRequest(ctx, client, meta.TokenEndpoint, form, id, secret, true)
	if err == nil && (status == http.StatusUnauthorized || (status == http.StatusBadRequest && tok.Error == "invalid_client")) {
		tok, status, err = o.tokenRequest(ctx, client, meta.TokenEndpoint, form, id, secret, false)
	}
	switch {
	case err != nil:
		o.log.Warn("openshift token exchange failed", "error", shortErr(err))
		return "", 0, ErrUnavailable
	case status == http.StatusOK && tok.AccessToken != "":
	case status == http.StatusBadRequest || status == http.StatusUnauthorized:
		o.log.Warn("openshift token exchange rejected", "status", status, "oauth_error", tok.Error)
		return "", 0, ErrUnauthenticated
	default:
		o.log.Warn("openshift token exchange unexpected status", "status", status)
		return "", 0, ErrUnavailable
	}
	exp := time.Duration(tok.ExpiresIn) * time.Second
	if exp <= 0 {
		exp = 24 * time.Hour
	}
	return tok.AccessToken, exp, nil
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int64  `json:"expires_in"`
	Error       string `json:"error"`
}

func (o *OpenShift) tokenRequest(ctx context.Context, client *http.Client, endpoint string, form url.Values, id, secret string, basic bool) (tokenResponse, int, error) {
	var tok tokenResponse
	body := url.Values{}
	for k, v := range form {
		body[k] = v
	}
	if !basic {
		body.Set("client_id", id)
		body.Set("client_secret", secret)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(body.Encode()))
	if err != nil {
		return tok, 0, err
	}
	if basic {
		req.SetBasicAuth(url.QueryEscape(id), url.QueryEscape(secret))
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return tok, 0, err
	}
	defer resp.Body.Close()
	_ = json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&tok)
	return tok, resp.StatusCode, nil
}

// Review returns the user name and groups of a user's access token.
func (o *OpenShift) Review(ctx context.Context, token string) (string, []string, error) {
	_, client, err := o.current()
	if err != nil {
		// Revalidation must keep working briefly while discovery is
		// unhealthy; the API server may still be reachable.
		client = o.newClient()
	}
	var u struct {
		Metadata struct {
			Name string `json:"name"`
		} `json:"metadata"`
		Groups []string `json:"groups"`
	}
	status, err := o.getJSON(ctx, client, strings.TrimSuffix(o.cfg.APIURL, "/")+"/apis/user.openshift.io/v1/users/~", token, &u)
	switch {
	case err != nil:
		o.log.Warn("openshift user review failed", "error", shortErr(err))
		return "", nil, ErrUnavailable
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return "", nil, ErrUnauthenticated
	case status != http.StatusOK || !ValidUsername(u.Metadata.Name):
		o.log.Warn("openshift user review unexpected status", "status", status)
		return "", nil, ErrUnavailable
	}
	groups := make([]string, 0, len(u.Groups))
	for _, g := range u.Groups {
		if ValidUsername(g) && !slices.Contains(groups, g) {
			groups = append(groups, g)
		}
	}
	slices.Sort(groups)
	return u.Metadata.Name, groups, nil
}

func (o *OpenShift) getJSON(ctx context.Context, client *http.Client, u, bearer string, into any) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return 0, err
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	body := io.LimitReader(resp.Body, 4<<20)
	if resp.StatusCode == http.StatusOK {
		if err := json.NewDecoder(body).Decode(into); err != nil {
			return 0, fmt.Errorf("decode response: %w", err)
		}
	} else {
		_, _ = io.Copy(io.Discard, body)
	}
	return resp.StatusCode, nil
}

func hostOf(u string) string {
	if pu, err := url.Parse(u); err == nil {
		return pu.Host
	}
	return u
}

// shortErr keeps log and status messages short and free of URLs with
// query strings.
func shortErr(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	s := err.Error()
	if len(s) > 160 {
		s = s[:160]
	}
	return s
}
