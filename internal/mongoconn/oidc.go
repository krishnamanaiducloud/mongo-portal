package mongoconn

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"golang.org/x/oauth2"
)

// ErrOIDCProviderMismatch means the MongoDB deployment trusts a different
// identity provider (or client) than the profile is configured for.
var ErrOIDCProviderMismatch = errors.New("MongoDB expects a different OIDC issuer or client id than the connection profile")

// ErrOIDCSignInRequired means the user's tokens expired and cannot be
// refreshed; the user has to sign in at the identity provider again.
var ErrOIDCSignInRequired = errors.New("the OIDC sign-in for MongoDB has expired; sign in again")

// OIDCTokens holds one user's tokens for MONGODB-OIDC. They live only in
// this process's memory, belong to exactly one MongoDB client, and are
// refreshed with the refresh token when MongoDB or the expiry requires it.
type OIDCTokens struct {
	issuer, clientID string
	oauth            *oauth2.Config
	client           *http.Client

	mu  sync.Mutex
	tok *oauth2.Token
	// Refreshes counts token refreshes (for the session view).
	Refreshes int
}

// NewOIDCTokens wraps the tokens of a completed authorization code flow.
func NewOIDCTokens(issuer, clientID string, oc *oauth2.Config, client *http.Client, tok *oauth2.Token) *OIDCTokens {
	return &OIDCTokens{issuer: strings.TrimSuffix(issuer, "/"), clientID: clientID, oauth: oc, client: client, tok: tok}
}

// Expiry returns the current access token's expiry (zero if unknown).
func (t *OIDCTokens) Expiry() time.Time {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.tok.Expiry
}

// CanRefresh reports whether a refresh token is available.
func (t *OIDCTokens) CanRefresh() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.tok.RefreshToken != ""
}

// Callback is the driver's OIDC human callback. It checks that the server
// expects the configured provider, then returns the current access token,
// refreshing it when the driver asks (after MongoDB rejected it) or when it
// has expired.
func (t *OIDCTokens) Callback(ctx context.Context, args *options.OIDCArgs) (*options.OIDCCredential, error) {
	if args.IDPInfo != nil {
		if strings.TrimSuffix(args.IDPInfo.Issuer, "/") != t.issuer || (args.IDPInfo.ClientID != "" && args.IDPInfo.ClientID != t.clientID) {
			return nil, fmt.Errorf("%w (server: issuer %q, client %q)", ErrOIDCProviderMismatch, args.IDPInfo.Issuer, args.IDPInfo.ClientID)
		}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if args.RefreshToken != nil || !t.tok.Valid() {
		if err := t.refreshLocked(ctx); err != nil {
			return nil, err
		}
	}
	exp := t.tok.Expiry
	cred := &options.OIDCCredential{AccessToken: t.tok.AccessToken}
	if !exp.IsZero() {
		cred.ExpiresAt = &exp
	}
	if t.tok.RefreshToken != "" {
		// A marker only: the driver passes it back when it wants a refresh.
		rt := "portal-managed"
		cred.RefreshToken = &rt
	}
	return cred, nil
}

// TokenProblem is why an access token cannot work with MongoDB, found
// before the token is sent. MongoDB remains the authority that validates
// tokens; this only turns its generic refusal into a precise reason.
type TokenProblem struct {
	Code   string // token_not_jwt, token_issuer_mismatch, token_audience_mismatch
	Detail string
}

func (p *TokenProblem) Error() string { return p.Detail }

// CheckAccessToken inspects (without trusting) the claims of an access
// token: MONGODB-OIDC needs a JWT whose issuer is the provider MongoDB
// trusts and, when audience is set, whose audience includes it.
func CheckAccessToken(raw, issuer, audience string) *TokenProblem {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return &TokenProblem{"token_not_jwt", "the identity provider issued an opaque access token; MONGODB-OIDC needs a JWT access token (check the provider's access token format for this client)"}
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	var claims struct {
		Iss string          `json:"iss"`
		Aud json.RawMessage `json:"aud"`
	}
	if err != nil || json.Unmarshal(payload, &claims) != nil {
		return &TokenProblem{"token_not_jwt", "the access token is not a readable JWT"}
	}
	if strings.TrimSuffix(claims.Iss, "/") != strings.TrimSuffix(issuer, "/") {
		return &TokenProblem{"token_issuer_mismatch", fmt.Sprintf("the access token was issued by %q, but MongoDB trusts %q (for Microsoft Entra ID, set accessTokenAcceptedVersion to 2)", claims.Iss, issuer)}
	}
	if audience == "" {
		return nil
	}
	var auds []string
	var one string
	if json.Unmarshal(claims.Aud, &one) == nil {
		auds = []string{one}
	} else {
		_ = json.Unmarshal(claims.Aud, &auds)
	}
	if !slices.Contains(auds, audience) {
		return &TokenProblem{"token_audience_mismatch", fmt.Sprintf("the access token audience is %q, but MongoDB expects %q", strings.Join(auds, ","), audience)}
	}
	return nil
}

func (t *OIDCTokens) refreshLocked(ctx context.Context) error {
	if t.tok.RefreshToken == "" || t.oauth == nil {
		return ErrOIDCSignInRequired
	}
	ctx = context.WithValue(ctx, oauth2.HTTPClient, t.client)
	nt, err := t.oauth.TokenSource(ctx, &oauth2.Token{RefreshToken: t.tok.RefreshToken}).Token()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrOIDCSignInRequired, err)
	}
	if nt.RefreshToken == "" {
		nt.RefreshToken = t.tok.RefreshToken
	}
	t.tok = nt
	t.Refreshes++
	return nil
}
