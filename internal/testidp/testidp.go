// Package testidp is a minimal OpenID Connect provider for tests: discovery,
// JWKS, an authorization endpoint that signs in a configurable user without
// a form, and a token endpoint with PKCE (S256) and refresh tokens. It is
// never linked into the portal binary.
package testidp

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// User is the identity the authorization endpoint signs in.
type User struct {
	Subject string
	Name    string
	Email   string
	Groups  []string
}

// IdP is the test provider. Fields may be changed between requests to
// simulate misconfiguration.
type IdP struct {
	// Issuer is the URL the provider is served at; IssuerClaim overrides the
	// issuer in discovery and tokens (to simulate an issuer mismatch).
	Issuer      string
	IssuerClaim string
	ClientID    string
	// ClientSecret, if set, is required at the token endpoint.
	ClientSecret string
	// AnyClient accepts every client id (to test what the relying party or
	// MongoDB does with an unexpected client).
	AnyClient bool
	// AccessAudience is the "aud" of access tokens (what MongoDB checks).
	AccessAudience string
	// IDAudience overrides the ID token audience (default ClientID).
	IDAudience string
	TokenTTL   time.Duration
	// ExpireIDToken issues already expired ID tokens; BadNonce breaks the
	// nonce; WrongKey signs with an unpublished key.
	ExpireIDToken, BadNonce, WrongKey bool
	User                              User

	key, otherKey *rsa.PrivateKey
	mu            sync.Mutex
	codes         map[string]grant
	refresh       map[string]User
	// Issued counts access tokens issued (initial and refreshed).
	Issued, Refreshed int
}

type grant struct {
	user                       User
	challenge, nonce, redirect string
	clientID, scope            string
	expires                    time.Time
}

// New creates a provider for issuer (served by the caller with Handler).
func New(issuer, clientID string) *IdP {
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	o, _ := rsa.GenerateKey(rand.Reader, 2048)
	return &IdP{Issuer: issuer, ClientID: clientID, AccessAudience: clientID, TokenTTL: 5 * time.Minute, key: k, otherKey: o,
		codes: map[string]grant{}, refresh: map[string]User{},
		User: User{Subject: "u-1001", Name: "alice", Email: "alice@example.com", Groups: []string{"devs"}}}
}

func (p *IdP) iss() string {
	if p.IssuerClaim != "" {
		return p.IssuerClaim
	}
	return p.Issuer
}

// Handler serves the provider endpoints.
func (p *IdP) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{
			"issuer": p.iss(), "authorization_endpoint": p.Issuer + "/authorize", "token_endpoint": p.Issuer + "/token",
			"jwks_uri": p.Issuer + "/jwks", "end_session_endpoint": p.Issuer + "/logout",
			"response_types_supported": []string{"code"}, "subject_types_supported": []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"}, "code_challenge_methods_supported": []string{"S256"},
		})
	})
	mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &p.key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}})
	})
	mux.HandleFunc("GET /authorize", p.authorize)
	mux.HandleFunc("POST /token", p.token)
	return mux
}

func (p *IdP) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	redirect, err := url.Parse(q.Get("redirect_uri"))
	if err != nil || q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
		http.Error(w, "bad authorization request", http.StatusBadRequest)
		return
	}
	if q.Get("client_id") != p.ClientID && !p.AnyClient {
		http.Error(w, "unknown client", http.StatusBadRequest)
		return
	}
	code := randString()
	p.mu.Lock()
	p.codes[code] = grant{user: p.User, challenge: q.Get("code_challenge"), nonce: q.Get("nonce"), redirect: redirect.String(),
		clientID: q.Get("client_id"), scope: q.Get("scope"), expires: time.Now().Add(time.Minute)}
	p.mu.Unlock()
	rq := redirect.Query()
	rq.Set("code", code)
	rq.Set("state", q.Get("state"))
	redirect.RawQuery = rq.Encode()
	http.Redirect(w, r, redirect.String(), http.StatusFound)
}

func (p *IdP) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		tokenError(w, "invalid_request")
		return
	}
	clientID, secret, basic := r.BasicAuth()
	if !basic {
		clientID, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	if (clientID != p.ClientID && !p.AnyClient) || (p.ClientSecret != "" && secret != p.ClientSecret) {
		tokenError(w, "invalid_client")
		return
	}
	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		code := r.PostForm.Get("code")
		p.mu.Lock()
		g, ok := p.codes[code]
		delete(p.codes, code)
		p.mu.Unlock()
		sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		if !ok || time.Now().After(g.expires) || g.redirect != r.PostForm.Get("redirect_uri") || g.clientID != clientID ||
			base64.RawURLEncoding.EncodeToString(sum[:]) != g.challenge {
			tokenError(w, "invalid_grant")
			return
		}
		p.issue(w, g.user, g.nonce, false)
	case "refresh_token":
		rt := r.PostForm.Get("refresh_token")
		p.mu.Lock()
		u, ok := p.refresh[rt]
		delete(p.refresh, rt)
		p.mu.Unlock()
		if !ok {
			tokenError(w, "invalid_grant")
			return
		}
		p.issue(w, u, "", true)
	default:
		tokenError(w, "unsupported_grant_type")
	}
}

func (p *IdP) issue(w http.ResponseWriter, u User, nonce string, refreshed bool) {
	now := time.Now()
	access := p.sign(jwt.Claims{Issuer: p.iss(), Subject: u.Subject, Audience: jwt.Audience{p.AccessAudience},
		IssuedAt: jwt.NewNumericDate(now), NotBefore: jwt.NewNumericDate(now.Add(-time.Minute)), Expiry: jwt.NewNumericDate(now.Add(p.TokenTTL))},
		map[string]any{"groups": u.Groups, "preferred_username": u.Name})
	aud := p.IDAudience
	if aud == "" {
		aud = p.ClientID
	}
	exp := now.Add(p.TokenTTL)
	if p.ExpireIDToken {
		exp = now.Add(-time.Hour)
	}
	if p.BadNonce {
		nonce += "x"
	}
	extra := map[string]any{"groups": u.Groups, "preferred_username": u.Name, "email": u.Email}
	if nonce != "" {
		extra["nonce"] = nonce
	}
	id := p.sign(jwt.Claims{Issuer: p.iss(), Subject: u.Subject, Audience: jwt.Audience{aud}, IssuedAt: jwt.NewNumericDate(now), Expiry: jwt.NewNumericDate(exp)}, extra)
	rt := randString()
	p.mu.Lock()
	p.refresh[rt] = u
	p.Issued++
	if refreshed {
		p.Refreshed++
	}
	p.mu.Unlock()
	writeJSON(w, map[string]any{"access_token": access, "id_token": id, "refresh_token": rt, "token_type": "Bearer", "expires_in": int(p.TokenTTL.Seconds())})
}

// AccessToken mints an access token for u without a browser flow.
func (p *IdP) AccessToken(u User, ttl time.Duration) string {
	now := time.Now()
	return p.sign(jwt.Claims{Issuer: p.iss(), Subject: u.Subject, Audience: jwt.Audience{p.AccessAudience}, IssuedAt: jwt.NewNumericDate(now),
		NotBefore: jwt.NewNumericDate(now.Add(-time.Minute)), Expiry: jwt.NewNumericDate(now.Add(ttl))}, map[string]any{"groups": u.Groups})
}

func (p *IdP) sign(c jwt.Claims, extra map[string]any) string {
	key := p.key
	if p.WrongKey {
		key = p.otherKey
	}
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "k1"))
	if err != nil {
		panic(err)
	}
	s, err := jwt.Signed(sig).Claims(c).Claims(extra).Serialize()
	if err != nil {
		panic(err)
	}
	return s
}

func randString() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func tokenError(w http.ResponseWriter, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
}
