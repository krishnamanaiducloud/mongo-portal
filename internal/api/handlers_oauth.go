package api

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/krishnamanaiducloud/mongo-portal/internal/audit"
	"github.com/krishnamanaiducloud/mongo-portal/internal/identity"
	"github.com/krishnamanaiducloud/mongo-portal/internal/session"
)

// OpenShift login endpoints. They answer with browser redirects; failures
// send the user back to the login page with a reason, where MongoDB login
// remains available.
const (
	oauthStartPath    = "/oauth/start"
	oauthCallbackPath = "/oauth/callback"
	oauthStateTTL     = 10 * time.Minute
	// OIDC providers: /oauth/oidc/<provider>/start and .../callback.
	oidcPathPrefix = "/oauth/oidc/"
)

// oauthState is sealed into a short-lived cookie, so a login can complete
// on any replica that shares the session key.
type oauthState struct {
	State    string `json:"s"`
	Verifier string `json:"v"`
	Return   string `json:"r"`
	Redirect string `json:"u"`
	// Nonce binds the OIDC ID token to this sign-in.
	Nonce string `json:"n,omitempty"`
	// Provider is the OIDC provider, Profile the MongoDB profile of a
	// MONGODB-OIDC connection.
	Provider string `json:"p,omitempty"`
	Profile  string `json:"pr,omitempty"`
	// Silent marks an automatic MONGODB-OIDC connection (prompt=none).
	Silent bool `json:"si,omitempty"`
}

func (s *Server) stateCookieName() string {
	if *s.Config.Session.SecureCookie {
		return "__Host-mongo_portal_oauth"
	}
	return "mongo_portal_oauth"
}

// redirectURI is the OAuth callback URL. It must match the redirect
// reference of the service account (the portal Route); the OAuth server
// rejects anything else, so a forged Host header cannot redirect codes.
func (s *Server) redirectURI(r *http.Request) string { return s.callbackURL(r, oauthCallbackPath) }

// callbackURL is an absolute URL of this portal for an OAuth redirect.
// Providers only accept registered redirect URIs, so a forged Host header
// cannot divert codes; set server.publicOrigin to pin it.
func (s *Server) callbackURL(r *http.Request, path string) string {
	if o := strings.TrimSuffix(s.Config.Server.PublicOrigin, "/"); o != "" {
		return o + path
	}
	scheme := "http"
	if r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		scheme = "https"
	}
	return scheme + "://" + r.Host + path
}

// setStateCookie seals a login state into the short-lived state cookie.
func (s *Server) setStateCookie(w http.ResponseWriter, st oauthState) error {
	sealed, err := s.state.Seal(st, time.Now().Add(oauthStateTTL))
	if err != nil {
		return err
	}
	// SameSite=Lax: the callback is a top-level navigation from the
	// provider, on which Strict cookies would not be sent.
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- HttpOnly, Secure (outside local dev), short-lived, sealed
		Name: s.stateCookieName(), Value: sealed, Path: "/", MaxAge: int(oauthStateTTL.Seconds()),
		HttpOnly: true, Secure: *s.Config.Session.SecureCookie, SameSite: http.SameSiteLaxMode,
	})
	return nil
}

// takeState reads and clears the single-use state cookie and checks the
// state parameter of the callback.
func (s *Server) takeState(w http.ResponseWriter, r *http.Request) (*oauthState, string) {
	c, err := r.Cookie(s.stateCookieName())
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- expiring cookie
		Name: s.stateCookieName(), Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: *s.Config.Session.SecureCookie, SameSite: http.SameSiteLaxMode,
	})
	var st oauthState
	if err != nil || s.state.Open(c.Value, &st, time.Now()) != nil {
		return nil, "expired"
	}
	if !constantEq(r.URL.Query().Get("state"), st.State) {
		return nil, "failed"
	}
	return &st, ""
}

// handleOIDCStart begins sign-in at an OIDC provider.
func (s *Server) handleOIDCStart(w http.ResponseWriter, r *http.Request) {
	rc := from(r)
	name := r.PathValue("provider")
	prov := s.Identity.Provider(name)
	if prov == nil {
		s.loginRedirect(w, r, "unknown_provider")
		return
	}
	if !prov.Available() {
		if st := prov.Status(); st.State != identity.StateDisabled && time.Since(st.CheckedAt) > 15*time.Second {
			ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
			prov.Probe(ctx)
			cancel()
		}
		if !prov.Available() {
			s.loginRedirect(w, r, "unavailable")
			return
		}
	}
	st := oauthState{State: session.NewToken(), Verifier: session.NewToken() + session.NewToken(), Nonce: session.NewToken(),
		Return: safeReturn(r.URL.Query().Get("return")), Redirect: s.callbackURL(r, oidcPathPrefix+name+"/callback"), Provider: name}
	authURL, err := prov.AuthCodeURL(st.State, st.Nonce, st.Verifier, st.Redirect)
	if err != nil {
		s.loginRedirect(w, r, "unavailable")
		return
	}
	if err := s.setStateCookie(w, st); err != nil {
		s.Logger.Error("cannot seal oidc state", "request_id", rc.requestID, "error", err.Error())
		s.loginRedirect(w, r, "failed")
		return
	}
	http.Redirect(w, r, authURL, http.StatusFound) // #nosec G710 -- the configured provider's authorization endpoint
}

// handleOIDCCallback completes sign-in at an OIDC provider.
func (s *Server) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	rc := from(r)
	name := r.PathValue("provider")
	fail := func(reason, detail string) {
		s.Metrics.AuthAttempts.WithLabelValues("oidc", reason).Inc()
		s.Audit.Record(r.Context(), audit.Event{RequestID: rc.requestID, Identity: string(identity.SourceOIDC), Provider: name,
			Action: "sso_login", Outcome: audit.Failure, Reason: detail})
		s.loginRedirect(w, r, reason)
	}
	st, bad := s.takeState(w, r)
	if bad != "" {
		fail(bad, "missing, expired or mismatched login state")
		return
	}
	prov := s.Identity.Provider(name)
	if prov == nil || st.Provider != name {
		fail("failed", "login state belongs to another provider")
		return
	}
	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		if e == "access_denied" {
			fail("denied", "access denied at the identity provider")
			return
		}
		fail("failed", "provider error "+truncate(e, 64))
		return
	}
	code := q.Get("code")
	if code == "" || len(code) > 4096 {
		fail("failed", "missing authorization code")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	id, err := prov.Exchange(ctx, code, st.Verifier, st.Nonce, st.Redirect)
	if err != nil {
		reason := "failed"
		switch {
		case errors.Is(err, identity.ErrUnavailable):
			reason = "unavailable"
		case errors.Is(err, identity.ErrIssuerMismatch):
			reason = "issuer_mismatch"
		case errors.Is(err, identity.ErrAudienceMismatch):
			reason = "audience_mismatch"
		case errors.Is(err, identity.ErrTokenExpired):
			reason = "token_expired"
		case errors.Is(err, identity.ErrNotInGroup):
			reason = "not_in_group"
		}
		fail(reason, err.Error())
		return
	}
	p := &identity.Principal{User: id.User, Groups: id.Groups, Source: identity.SourceOIDC, Provider: name}
	// A previous MongoDB session belonged to another principal: end it.
	if sc, err := r.Cookie(s.Config.Session.CookieName); err == nil {
		if owner, _ := s.Store.OwnerOf(sc.Value); owner != "" && owner != p.Key() {
			s.Store.Delete(sc.Value, "replaced")
			s.clearCookie(w)
		}
	}
	p = s.Identity.SignInOIDC(w, name, id)
	s.Metrics.AuthAttempts.WithLabelValues("oidc", "success").Inc()
	s.Audit.Record(r.Context(), audit.Event{RequestID: rc.requestID, SSOUser: p.User, Identity: string(identity.SourceOIDC), Provider: name,
		Owner: p.Key(), PortalRole: strings.Join(s.RBAC.Policy().Roles(p.Subjects()), " "), Action: "sso_login", Outcome: audit.Success})
	http.Redirect(w, r, safeReturn(st.Return), http.StatusFound)
}

// safeReturn accepts only local paths ("/x", not "//host" or "/\host").
func safeReturn(p string) string {
	if p == "" || p[0] != '/' || strings.HasPrefix(p, "//") || strings.HasPrefix(p, "/\\") || strings.ContainsAny(p, "\r\n") || len(p) > 512 {
		return "/"
	}
	return p
}

func (s *Server) loginRedirect(w http.ResponseWriter, r *http.Request, reason string) {
	http.Redirect(w, r, "/login?sso="+url.QueryEscape(reason), http.StatusFound)
}

func (s *Server) handleOAuthStart(w http.ResponseWriter, r *http.Request) {
	rc := from(r)
	ret := safeReturn(r.URL.Query().Get("return"))
	if !s.Identity.OpenShift.Available() {
		// The background result may be stale: check once more, but at most
		// every 15s so anonymous requests cannot drive probe traffic.
		if st := s.Identity.OpenShift.Status(); st.State != identity.StateDisabled || st.CheckedAt.IsZero() {
			if time.Since(st.CheckedAt) > 15*time.Second {
				ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
				s.Identity.OpenShift.Probe(ctx)
				cancel()
			}
		}
		if !s.Identity.OpenShift.Available() {
			s.loginRedirect(w, r, "unavailable")
			return
		}
	}
	st := oauthState{State: session.NewToken(), Verifier: session.NewToken() + session.NewToken(), Return: ret, Redirect: s.redirectURI(r)}
	sum := sha256.Sum256([]byte(st.Verifier))
	authURL, err := s.Identity.OpenShift.AuthCodeURL(st.State, base64.RawURLEncoding.EncodeToString(sum[:]), st.Redirect)
	if err != nil {
		s.loginRedirect(w, r, "unavailable")
		return
	}
	if err := s.setStateCookie(w, st); err != nil {
		s.Logger.Error("cannot seal oauth state", "request_id", rc.requestID, "error", err.Error())
		s.loginRedirect(w, r, "failed")
		return
	}
	http.Redirect(w, r, authURL, http.StatusFound)
}

func (s *Server) handleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	rc := from(r)
	q := r.URL.Query()
	fail := func(reason, detail string) {
		s.Metrics.AuthAttempts.WithLabelValues("sso", reason).Inc()
		s.Audit.Record(r.Context(), audit.Event{RequestID: rc.requestID, Identity: string(identity.SourceOpenShift), Action: "sso_login", Outcome: audit.Failure, Reason: detail})
		s.loginRedirect(w, r, reason)
	}
	st, bad := s.takeState(w, r)
	if bad != "" {
		fail(bad, "missing, expired or mismatched login state")
		return
	}
	if st.Provider != "" || st.Profile != "" {
		fail("failed", "login state belongs to another sign-in")
		return
	}
	if e := q.Get("error"); e != "" {
		if e == "access_denied" {
			fail("denied", "access denied at the OAuth server")
			return
		}
		fail("failed", "oauth error "+truncate(e, 64))
		return
	}
	code := q.Get("code")
	if code == "" || len(code) > 4096 {
		fail("failed", "missing authorization code")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	token, ttl, err := s.Identity.OpenShift.Exchange(ctx, code, st.Verifier, st.Redirect)
	if err != nil {
		reason := "unavailable"
		if errors.Is(err, identity.ErrUnauthenticated) {
			reason = "failed"
		}
		fail(reason, "token exchange: "+err.Error())
		return
	}
	user, groups, err := s.Identity.OpenShift.Review(ctx, token)
	if err != nil {
		fail("failed", "user review: "+err.Error())
		return
	}
	// A previous MongoDB session belonged to another principal: end it.
	if sc, err := r.Cookie(s.Config.Session.CookieName); err == nil {
		if owner, _ := s.Store.OwnerOf(sc.Value); owner != "" && owner != (&identity.Principal{User: user, Source: identity.SourceOpenShift}).Key() {
			s.Store.Delete(sc.Value, "replaced")
			s.clearCookie(w)
		}
	}
	s.Identity.SignIn(w, user, groups, token, ttl)
	p := &identity.Principal{User: user, Groups: groups, Source: identity.SourceOpenShift}
	s.Metrics.AuthAttempts.WithLabelValues("sso", "success").Inc()
	s.Audit.Record(r.Context(), audit.Event{RequestID: rc.requestID, SSOUser: user, Identity: string(identity.SourceOpenShift), Owner: p.Key(),
		PortalRole: strings.Join(s.RBAC.Policy().Roles(p.Subjects()), " "), Action: "sso_login", Outcome: audit.Success})
	http.Redirect(w, r, safeReturn(st.Return), http.StatusFound)
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
