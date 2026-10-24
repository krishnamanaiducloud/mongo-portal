package identity

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/krishnamanaiducloud/mongo-portal/internal/config"
	"github.com/krishnamanaiducloud/mongo-portal/internal/tlsx"
)

// OIDC sign-in failures with an actionable explanation for the login page.
var (
	ErrIssuerMismatch   = errors.New("the identity provider reports a different issuer than configured")
	ErrAudienceMismatch = errors.New("the ID token was issued for a different client (audience)")
	ErrTokenExpired     = errors.New("the ID token has expired; check the clocks of the portal and the identity provider")
	ErrBadSignature     = errors.New("the ID token signature could not be verified with the provider's keys")
	ErrNonceMismatch    = errors.New("the ID token does not belong to this sign-in (nonce mismatch)")
	ErrNotInGroup       = errors.New("the user is not in a group allowed to use the portal")
	ErrNoUsername       = errors.New("the ID token has no usable user name claim")
)

// OIDCIdentity is a verified sign-in.
type OIDCIdentity struct {
	User    string
	Subject string
	Groups  []string
	Expiry  time.Time
	// IDToken is kept only to build the RP-initiated logout URL.
	IDToken string
}

// OIDCProvider signs users in at an OpenID Connect provider with the
// authorization code flow, PKCE (S256), state and nonce. ID tokens are
// verified against the provider's JWKS: signature, issuer, audience (the
// client id), authorized party and expiry.
//
// Like OpenShift login it is passive: discovery failures make the provider
// unavailable (and the button disappears) instead of failing requests.
type OIDCProvider struct {
	cfg config.OIDCProvider
	log *slog.Logger
	now func() time.Time

	mu         sync.RWMutex
	status     Status
	provider   *oidc.Provider
	verifier   *oidc.IDTokenVerifier
	client     *http.Client
	endSession string
}

// NewOIDCProvider creates the provider. It performs no I/O; call Run or Probe.
func NewOIDCProvider(cfg config.OIDCProvider, log *slog.Logger) *OIDCProvider {
	p := &OIDCProvider{cfg: cfg, log: log, now: time.Now}
	p.status = Status{State: StateUnavailable, Reason: "not checked yet", Issuer: cfg.Issuer}
	if cfg.Enabled == config.EnabledFalse {
		p.status = Status{State: StateDisabled, Reason: "turned off in the configuration", Issuer: cfg.Issuer}
	}
	return p
}

// Name is the provider's configured name.
func (p *OIDCProvider) Name() string { return p.cfg.Name }

// DisplayName labels the sign-in button.
func (p *OIDCProvider) DisplayName() string { return p.cfg.DisplayName }

// Status returns the last discovery result.
func (p *OIDCProvider) Status() Status {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.status
}

// Available reports whether sign-in can be offered.
func (p *OIDCProvider) Available() bool { return p.Status().State == StateAvailable }

// SessionMaxAge caps sign-ins with this provider (0: the portal default).
func (p *OIDCProvider) SessionMaxAge() time.Duration { return p.cfg.SessionMaxAge }

// Run discovers now and then periodically until ctx ends.
func (p *OIDCProvider) Run(ctx context.Context) {
	if p.cfg.Enabled == config.EnabledFalse {
		return
	}
	for {
		st := p.Probe(ctx)
		wait := p.cfg.ProbeInterval
		if st.State == StateAvailable {
			wait *= 5
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

// Probe fetches the discovery document and records the result.
func (p *OIDCProvider) Probe(ctx context.Context) Status {
	if p.cfg.Enabled == config.EnabledFalse {
		return p.Status()
	}
	ctx, cancel := context.WithTimeout(ctx, 2*p.cfg.RequestTimeout)
	defer cancel()
	st := Status{State: StateAvailable, Issuer: p.cfg.Issuer}
	client, cerr := tlsx.HTTPClient(p.cfg.RequestTimeout, append([]string{p.cfg.CAFile}, p.cfg.ExtraCAFiles...)...)
	if cerr != nil {
		p.log.Warn("oidc provider CA files could not all be loaded", "provider", p.cfg.Name, "error", cerr.Error())
	}
	prov, err := oidc.NewProvider(oidc.ClientContext(ctx, client), p.cfg.Issuer)
	var endSession string
	switch {
	case err != nil:
		st = Status{State: StateUnavailable, Reason: discoveryReason(err), Issuer: p.cfg.Issuer}
	default:
		var meta struct {
			EndSession string   `json:"end_session_endpoint"`
			Challenge  []string `json:"code_challenge_methods_supported"`
		}
		_ = prov.Claims(&meta)
		if len(meta.Challenge) > 0 && !slices.Contains(meta.Challenge, "S256") {
			st = Status{State: StateUnavailable, Reason: "the provider does not support PKCE with S256", Issuer: p.cfg.Issuer}
		} else if p.cfg.ClientSecretFile != "" {
			if _, err := p.clientSecret(); err != nil {
				st = Status{State: StateUnavailable, Reason: err.Error(), Issuer: p.cfg.Issuer}
			}
		}
		endSession = meta.EndSession
	}
	st.CheckedAt = p.now().UTC()

	p.mu.Lock()
	prev := p.status
	p.status = st
	if st.State == StateAvailable {
		p.provider, p.client, p.endSession = prov, client, endSession
		p.verifier = prov.Verifier(&oidc.Config{ClientID: p.cfg.ClientID, Now: p.now})
	}
	p.mu.Unlock()
	if prev.State != st.State || prev.Reason != st.Reason {
		attrs := []any{"provider", p.cfg.Name, "state", st.State, "reason", st.Reason, "issuer", p.cfg.Issuer}
		switch {
		case st.State == StateAvailable:
			p.log.Info("oidc sign-in available", attrs...)
		case p.cfg.Enabled == config.EnabledTrue:
			p.log.Warn("oidc sign-in unavailable; other sign-in methods remain available", attrs...)
		default:
			p.log.Info("oidc sign-in not offered", attrs...)
		}
	}
	return st
}

func discoveryReason(err error) string {
	msg := err.Error()
	if strings.Contains(msg, "did not match the issuer") || strings.Contains(msg, "issuer did not match") {
		return ErrIssuerMismatch.Error() + ": " + shortErr(err)
	}
	return "the identity provider is not reachable or its discovery document is invalid: " + shortErr(err)
}

func (p *OIDCProvider) clientSecret() (string, error) {
	if p.cfg.ClientSecretFile == "" {
		return "", nil
	}
	b, err := os.ReadFile(p.cfg.ClientSecretFile) // #nosec G304 -- operator supplied secret mount
	if err != nil {
		return "", errors.New("the client secret file cannot be read")
	}
	s := strings.TrimSpace(string(b))
	if s == "" {
		return "", errors.New("the client secret file is empty")
	}
	return s, nil
}

func (p *OIDCProvider) current() (*oidc.Provider, *oidc.IDTokenVerifier, *http.Client, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.status.State != StateAvailable || p.provider == nil {
		return nil, nil, nil, ErrUnavailable
	}
	return p.provider, p.verifier, p.client, nil
}

func (p *OIDCProvider) oauth(prov *oidc.Provider, redirect string) (*oauth2.Config, error) {
	secret, err := p.clientSecret()
	if err != nil {
		return nil, err
	}
	return &oauth2.Config{ClientID: p.cfg.ClientID, ClientSecret: secret, Endpoint: prov.Endpoint(), RedirectURL: redirect, Scopes: p.cfg.Scopes}, nil
}

// AuthCodeURL returns the provider's authorization URL.
func (p *OIDCProvider) AuthCodeURL(state, nonce, verifier, redirect string) (string, error) {
	prov, _, _, err := p.current()
	if err != nil {
		return "", err
	}
	oc, err := p.oauth(prov, redirect)
	if err != nil {
		return "", err
	}
	return oc.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier), oidc.Nonce(nonce)), nil
}

// Exchange redeems the code and verifies the ID token.
func (p *OIDCProvider) Exchange(ctx context.Context, code, verifier, nonce, redirect string) (*OIDCIdentity, error) {
	prov, ver, client, err := p.current()
	if err != nil {
		return nil, err
	}
	oc, err := p.oauth(prov, redirect)
	if err != nil {
		return nil, err
	}
	ctx = oidc.ClientContext(ctx, client)
	tok, err := oc.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		var re *oauth2.RetrieveError
		if errors.As(err, &re) {
			return nil, fmt.Errorf("%w: the provider rejected the authorization code (%s)", ErrUnauthenticated, re.ErrorCode)
		}
		return nil, fmt.Errorf("%w: token request failed: %s", ErrUnavailable, shortErr(err))
	}
	raw, _ := tok.Extra("id_token").(string)
	if raw == "" {
		return nil, fmt.Errorf("%w: the provider returned no ID token (is the openid scope allowed?)", ErrUnauthenticated)
	}
	return p.verify(ctx, ver, raw, nonce)
}

func (p *OIDCProvider) verify(ctx context.Context, ver *oidc.IDTokenVerifier, raw, nonce string) (*OIDCIdentity, error) {
	idt, err := ver.Verify(ctx, raw)
	if err != nil {
		var expired *oidc.TokenExpiredError
		msg := err.Error()
		switch {
		case errors.As(err, &expired):
			return nil, ErrTokenExpired
		case strings.Contains(msg, "expected audience"):
			return nil, ErrAudienceMismatch
		case strings.Contains(msg, "id token issued by a different provider"):
			return nil, ErrIssuerMismatch
		case strings.Contains(msg, "signature"):
			return nil, ErrBadSignature
		}
		return nil, fmt.Errorf("%w: %s", ErrUnauthenticated, shortErr(err))
	}
	if nonce == "" || idt.Nonce != nonce {
		return nil, ErrNonceMismatch
	}
	var claims map[string]any
	if err := idt.Claims(&claims); err != nil {
		return nil, fmt.Errorf("%w: unreadable claims", ErrUnauthenticated)
	}
	// With several audiences the authorized party must be this client.
	if len(idt.Audience) > 1 {
		if azp, _ := claims["azp"].(string); azp != p.cfg.ClientID {
			return nil, ErrAudienceMismatch
		}
	}
	user := firstString(claims, p.cfg.UsernameClaim, "preferred_username", "email", "sub")
	if !ValidUsername(user) {
		return nil, ErrNoUsername
	}
	groups := stringList(claims[p.cfg.GroupsClaim])
	if len(p.cfg.RequiredGroups) > 0 && !slices.ContainsFunc(groups, func(g string) bool { return slices.Contains(p.cfg.RequiredGroups, g) }) {
		return nil, ErrNotInGroup
	}
	return &OIDCIdentity{User: user, Subject: idt.Subject, Groups: groups, Expiry: idt.Expiry, IDToken: raw}, nil
}

// LogoutURL returns the provider's end-session URL for RP-initiated logout,
// or "" when the provider has none or logout redirects are off.
func (p *OIDCProvider) LogoutURL(idToken, postLogout string) string {
	if !p.cfg.LogoutRedirect {
		return ""
	}
	p.mu.RLock()
	es := p.endSession
	p.mu.RUnlock()
	u, err := url.Parse(es)
	if es == "" || err != nil || u.Scheme != "https" {
		return ""
	}
	q := u.Query()
	q.Set("client_id", p.cfg.ClientID)
	if idToken != "" {
		q.Set("id_token_hint", idToken)
	}
	if postLogout != "" {
		q.Set("post_logout_redirect_uri", postLogout)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

func firstString(claims map[string]any, names ...string) string {
	for _, n := range names {
		if s, ok := claims[n].(string); ok && strings.TrimSpace(s) != "" {
			return strings.TrimSpace(s)
		}
	}
	return ""
}

// stringList accepts a JSON array of strings or a single (comma or space
// separated) string, as providers differ.
func stringList(v any) []string {
	var out []string
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s != "" && ValidUsername(s) && !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	switch t := v.(type) {
	case []any:
		for _, x := range t {
			if s, ok := x.(string); ok {
				add(s)
			}
		}
	case string:
		for _, s := range strings.FieldsFunc(t, func(r rune) bool { return r == ',' || r == ' ' }) {
			add(s)
		}
	}
	return out
}
