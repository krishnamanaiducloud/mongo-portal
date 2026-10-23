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
)

// oauthState is sealed into a short-lived cookie, so a login can complete
// on any replica that shares the session key.
type oauthState struct {
	State    string `json:"s"`
	Verifier string `json:"v"`
	Return   string `json:"r"`
	Redirect string `json:"u"`
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
func (s *Server) redirectURI(r *http.Request) string {
	if o := strings.TrimSuffix(s.Config.Server.PublicOrigin, "/"); o != "" {
		return o + oauthCallbackPath
	}
	scheme := "http"
	if r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		scheme = "https"
	}
	return scheme + "://" + r.Host + oauthCallbackPath
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
	sealed, err := s.state.Seal(st, time.Now().Add(oauthStateTTL))
	if err != nil {
		s.Logger.Error("cannot seal oauth state", "request_id", rc.requestID, "error", err.Error())
		s.loginRedirect(w, r, "failed")
		return
	}
	// SameSite=Lax: the callback is a top-level navigation from the OAuth
	// server, on which Strict cookies would not be sent.
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- HttpOnly, Secure (outside local dev), short-lived, sealed
		Name: s.stateCookieName(), Value: sealed, Path: "/", MaxAge: int(oauthStateTTL.Seconds()),
		HttpOnly: true, Secure: *s.Config.Session.SecureCookie, SameSite: http.SameSiteLaxMode,
	})
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
	c, err := r.Cookie(s.stateCookieName())
	// The state cookie is single use.
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- expiring cookie
		Name: s.stateCookieName(), Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: *s.Config.Session.SecureCookie, SameSite: http.SameSiteLaxMode,
	})
	var st oauthState
	if err != nil || s.state.Open(c.Value, &st, time.Now()) != nil {
		fail("expired", "missing or expired login state")
		return
	}
	if !constantEq(q.Get("state"), st.State) {
		fail("failed", "state mismatch")
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
