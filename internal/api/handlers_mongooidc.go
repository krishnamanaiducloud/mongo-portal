package api

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/krishnamanaiducloud/mongo-portal/internal/audit"
	"github.com/krishnamanaiducloud/mongo-portal/internal/config"
	"github.com/krishnamanaiducloud/mongo-portal/internal/mongoconn"
	"github.com/krishnamanaiducloud/mongo-portal/internal/session"
	"github.com/krishnamanaiducloud/mongo-portal/internal/tlsx"
)

// MONGODB-OIDC sign-in: the portal runs the authorization code flow (PKCE)
// against the identity provider the MongoDB deployment trusts, and hands
// the resulting access token, which belongs to the user, to MongoDB. The
// portal's own sign-in token (OpenShift or another OIDC provider) is never
// reused for MongoDB.
const (
	mongoOIDCPrefix   = "/oauth/mongodb/"
	mongoOIDCCallback = "/oauth/mongodb/callback"
)

// mongoIdP caches the discovery of a profile's identity provider.
type mongoIdP struct {
	provider *oidc.Provider
	client   *http.Client
	at       time.Time
}

type mongoOIDCCache struct {
	mu sync.Mutex
	m  map[string]*mongoIdP
}

func (s *Server) mongoIdP(ctx context.Context, p *config.Profile) (*mongoIdP, error) {
	s.midp.mu.Lock()
	defer s.midp.mu.Unlock()
	if s.midp.m == nil {
		s.midp.m = map[string]*mongoIdP{}
	}
	if c, ok := s.midp.m[p.Name]; ok && time.Since(c.at) < 10*time.Minute {
		return c, nil
	}
	o := p.OIDC
	client, err := tlsx.HTTPClient(o.RequestTimeout, append([]string{o.CAFile}, o.ExtraCAFiles...)...)
	if err != nil {
		s.Logger.Warn("mongodb oidc CA files could not all be loaded", "profile", p.Name, "error", err.Error())
	}
	ctx, cancel := context.WithTimeout(ctx, 2*o.RequestTimeout)
	defer cancel()
	prov, err := oidc.NewProvider(oidc.ClientContext(ctx, client), o.Issuer)
	if err != nil {
		return nil, err
	}
	c := &mongoIdP{provider: prov, client: client, at: time.Now()}
	s.midp.m[p.Name] = c
	return c, nil
}

func mongoOAuth(p *config.Profile, idp *mongoIdP, redirect string) (*oauth2.Config, error) {
	secret := ""
	if f := p.OIDC.ClientSecretFile; f != "" {
		b, err := os.ReadFile(f) // #nosec G304 G703 -- path from the operator's configuration (secret mount), not from requests
		if err != nil {
			return nil, errors.New("the MongoDB OIDC client secret cannot be read")
		}
		secret = strings.TrimSpace(string(b))
	}
	return &oauth2.Config{ClientID: p.OIDC.ClientID, ClientSecret: secret, Endpoint: idp.provider.Endpoint(), RedirectURL: redirect, Scopes: p.OIDC.Scopes}, nil
}

// mongoLoginRedirect returns to the login page with a reason for the
// MONGODB-OIDC attempt.
func mongoLoginRedirect(w http.ResponseWriter, r *http.Request, profile, reason string) {
	http.Redirect(w, r, "/login?mongo="+url.QueryEscape(reason)+"&profile="+url.QueryEscape(profile), http.StatusFound)
}

func (s *Server) handleMongoOIDCStart(w http.ResponseWriter, r *http.Request) {
	rc := from(r)
	rc.p = s.Identity.Resolve(w, r)
	name := r.PathValue("profile")
	p, ok := s.Config.Profile(name)
	if !ok || p.OIDC == nil {
		mongoLoginRedirect(w, r, name, "oidc_not_offered")
		return
	}
	if s.Config.Identity.RequireSSO && !rc.p.SSO() {
		mongoLoginRedirect(w, r, name, "sso_required")
		return
	}
	idp, err := s.mongoIdP(r.Context(), p)
	if err != nil {
		s.Logger.Warn("mongodb oidc provider unavailable", "profile", p.Name, "error", err.Error())
		mongoLoginRedirect(w, r, name, "idp_unavailable")
		return
	}
	st := oauthState{State: session.NewToken(), Verifier: session.NewToken() + session.NewToken(), Nonce: session.NewToken(),
		Return: safeReturn(r.URL.Query().Get("return")), Redirect: s.callbackURL(r, mongoOIDCCallback), Profile: p.Name}
	oc, err := mongoOAuth(p, idp, st.Redirect)
	if err != nil {
		mongoLoginRedirect(w, r, name, "idp_unavailable")
		return
	}
	if err := s.setStateCookie(w, st); err != nil {
		mongoLoginRedirect(w, r, name, "failed")
		return
	}
	// The target is the configured provider's authorization endpoint.
	http.Redirect(w, r, oc.AuthCodeURL(st.State, oauth2.S256ChallengeOption(st.Verifier), oidc.Nonce(st.Nonce)), http.StatusFound) // #nosec G710 -- endpoint from configured discovery
}

func (s *Server) handleMongoOIDCCallback(w http.ResponseWriter, r *http.Request) {
	rc := from(r)
	rc.p = s.Identity.Resolve(w, r)
	if rc.p != nil {
		rc.owner = rc.p.Key()
	}
	if c, err := r.Cookie(s.Config.Session.CookieName); err == nil {
		rc.secret = c.Value
	}
	st, bad := s.takeState(w, r)
	if bad != "" || st.Profile == "" {
		mongoLoginRedirect(w, r, "", "expired")
		return
	}
	fail := func(reason, detail string) {
		e := s.baseEvent(rc, "mongodb_login", audit.Failure, detail)
		e.Profile, e.Method, e.Client, e.ErrorClass = st.Profile, "mongodb-oidc", clientIP(r), reason
		s.Audit.Record(r.Context(), e)
		s.Metrics.AuthAttempts.WithLabelValues("mongodb-oidc", reason).Inc()
		mongoLoginRedirect(w, r, st.Profile, reason)
	}
	p, ok := s.Config.Profile(st.Profile)
	if !ok || p.OIDC == nil {
		fail("oidc_not_offered", "profile no longer offers MONGODB-OIDC")
		return
	}
	if s.Config.Identity.RequireSSO && !rc.p.SSO() {
		fail("sso_required", "single sign-on required")
		return
	}
	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		reason := "failed"
		if e == "access_denied" {
			reason = "denied"
		}
		fail(reason, "identity provider error "+truncate(e, 64))
		return
	}
	code := q.Get("code")
	if code == "" || len(code) > 4096 {
		fail("failed", "missing authorization code")
		return
	}
	idp, err := s.mongoIdP(r.Context(), p)
	if err != nil {
		fail("idp_unavailable", "identity provider unavailable")
		return
	}
	oc, err := mongoOAuth(p, idp, st.Redirect)
	if err != nil {
		fail("idp_unavailable", err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	tok, err := oc.Exchange(oidc.ClientContext(ctx, idp.client), code, oauth2.VerifierOption(st.Verifier))
	if err != nil {
		fail("failed", "token exchange failed")
		return
	}
	// An ID token, when the provider returns one, must belong to this
	// sign-in. The access token itself is validated by MongoDB.
	if raw, _ := tok.Extra("id_token").(string); raw != "" {
		idt, err := idp.provider.Verifier(&oidc.Config{ClientID: p.OIDC.ClientID}).Verify(oidc.ClientContext(ctx, idp.client), raw)
		if err != nil || idt.Nonce != st.Nonce {
			fail("failed", "ID token verification failed")
			return
		}
	}
	tokens := mongoconn.NewOIDCTokens(p.OIDC.Issuer, p.OIDC.ClientID, oc, idp.client, tok)
	cred := mongoconn.Credentials{Mechanism: config.MechanismOIDC, OIDC: tokens}
	if f := s.openSession(w, r, rc, p, cred); f != nil {
		reason := f.code
		if reason == string(mongoconn.KindAuthFailed) {
			reason = "mongo_rejected"
		}
		mongoLoginRedirect(w, r, p.Name, reason)
		return
	}
	http.Redirect(w, r, safeReturn(st.Return), http.StatusFound)
}
