package identity

import (
	"context"
	"crypto/sha256"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/krishnamanaiducloud/mongo-portal/internal/config"
)

// SSOCookieName holds the encrypted OpenShift sign-in.
const SSOCookieName = "__Host-mongo_portal_sso"

// ssoClaims is the content of the SSO cookie. The OpenShift access token is
// kept (encrypted) only to re-check the user's identity and groups; the
// portal never calls the OpenShift API on the user's behalf otherwise.
type ssoClaims struct {
	User      string   `json:"u"`
	Groups    []string `json:"g,omitempty"`
	Token     string   `json:"t,omitempty"`
	Validated int64    `json:"val"`
	Expires   int64    `json:"exp"`
	// Source is "" (OpenShift) or "oidc"; Provider names the OIDC provider.
	Source   string `json:"src,omitempty"`
	Provider string `json:"p,omitempty"`
}

// Options configures a Resolver.
type Options struct {
	Config config.IdentityConfig
	// Key is the shared session key (at least 32 bytes).
	Key []byte
	// SecureCookie sets the cookie Secure attribute (always true outside
	// local development).
	SecureCookie bool
	// MaxAge caps the SSO sign-in lifetime (the session absolute timeout).
	MaxAge time.Duration
	// KeepGroup decides which groups are stored in the SSO cookie (the
	// groups the RBAC policy refers to). Nil keeps all groups.
	KeepGroup func(group string) bool
	Logger    *slog.Logger
}

// Resolver resolves the SSO principal of a request from the enabled
// sources. It never fails a request: invalid or unverifiable identities are
// dropped and the request continues anonymously.
type Resolver struct {
	opts      Options
	header    *headerSource
	dev       *Principal
	OpenShift *OpenShift
	// OIDC providers in configuration order.
	OIDC   []*OIDCProvider
	sealer *Sealer
	now    func() time.Time

	untrustedOnce sync.Once

	cacheMu sync.Mutex
	cache   map[[32]byte]reviewEntry
	// revalidateBefore: OpenShift sign-ins validated at or before this Unix
	// time re-check token and groups on their next request.
	revalidateBefore atomic.Int64
}

// RevalidateIdentities empties the token review cache and makes every
// OpenShift sign-in re-check its token and groups at the API server on its
// next request (for example after group membership changed).
func (r *Resolver) RevalidateIdentities() {
	r.cacheMu.Lock()
	r.cache = map[[32]byte]reviewEntry{}
	r.cacheMu.Unlock()
	r.revalidateBefore.Store(r.now().Unix())
}

// ReviewCacheStats returns the number of cached token reviews and when the
// last identity revalidation was requested (zero if never).
func (r *Resolver) ReviewCacheStats() (int, time.Time) {
	r.cacheMu.Lock()
	n := len(r.cache)
	r.cacheMu.Unlock()
	var at time.Time
	if v := r.revalidateBefore.Load(); v > 0 {
		at = time.Unix(v, 0).UTC()
	}
	return n, at
}

type reviewEntry struct {
	user   string
	groups []string
	at     time.Time
}

// NewResolver builds the resolver. The OpenShift client is created even
// when OpenShift is unavailable; it reports its own status.
func NewResolver(o Options) (*Resolver, error) {
	trusted, err := parseCIDRs(o.Config.TrustedProxyCIDRs)
	if err != nil {
		return nil, err
	}
	s, err := NewSealer(o.Key, "sso")
	if err != nil {
		return nil, err
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	r := &Resolver{opts: o, sealer: s, now: time.Now, cache: map[[32]byte]reviewEntry{}}
	if o.Config.Header.Enabled {
		r.header = &headerSource{cfg: o.Config.Header, trusted: trusted}
	}
	if o.Config.Dev.Enabled {
		r.dev = &Principal{User: o.Config.Dev.User, Groups: slices.Clone(o.Config.Dev.Groups), Source: SourceDev}
	}
	r.OpenShift = NewOpenShift(o.Config.OpenShift, o.Logger)
	for _, pc := range o.Config.OIDC.Providers {
		r.OIDC = append(r.OIDC, NewOIDCProvider(pc, o.Logger))
	}
	return r, nil
}

// Provider returns the named OIDC provider.
func (r *Resolver) Provider(name string) *OIDCProvider {
	for _, p := range r.OIDC {
		if p.Name() == name {
			return p
		}
	}
	return nil
}

// RunProviders runs the background discovery of every SSO source.
func (r *Resolver) RunProviders(ctx context.Context) {
	go r.OpenShift.Run(ctx)
	for _, p := range r.OIDC {
		go p.Run(ctx)
	}
}

// Sources describes which SSO sources can currently be used.
type Sources struct {
	OpenShift  Status       `json:"openshift"`
	OIDC       []OIDCSource `json:"oidc"`
	Header     bool         `json:"header"`
	Dev        bool         `json:"dev"`
	RequireSSO bool         `json:"requireSSO"`
}

// OIDCSource describes one OIDC provider for the login page.
type OIDCSource struct {
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
	Status      Status `json:"status"`
}

// Sources returns the current SSO source availability.
func (r *Resolver) Sources() Sources {
	src := Sources{OpenShift: r.OpenShift.Status(), OIDC: []OIDCSource{}, Header: r.header != nil, Dev: r.dev != nil, RequireSSO: r.opts.Config.RequireSSO}
	for _, p := range r.OIDC {
		src.OIDC = append(src.OIDC, OIDCSource{Name: p.Name(), DisplayName: p.DisplayName(), Status: p.Status()})
	}
	return src
}

// AnySSO reports whether any SSO source is able to sign users in now.
func (r *Resolver) AnySSO() bool {
	if r.header != nil || r.dev != nil || r.OpenShift.Available() {
		return true
	}
	return slices.ContainsFunc(r.OIDC, func(p *OIDCProvider) bool { return p.Available() })
}

// Resolve returns the request's SSO principal, or nil for anonymous
// requests. It may refresh the SSO cookie on w.
func (r *Resolver) Resolve(w http.ResponseWriter, req *http.Request) *Principal {
	if r.dev != nil {
		p := *r.dev
		return &p
	}
	if r.header != nil {
		p, untrusted := r.header.resolve(req)
		if p != nil {
			return p
		}
		if untrusted {
			r.untrustedOnce.Do(func() {
				r.opts.Logger.Warn("identity headers from an untrusted peer were ignored", "peer", peerIP(req))
			})
		}
	}
	c, err := req.Cookie(r.cookieName())
	if err != nil || c.Value == "" {
		return nil
	}
	var cl ssoClaims
	now := r.now()
	if err := r.sealer.Open(c.Value, &cl, now); err != nil || cl.Expires <= now.Unix() {
		r.clear(w)
		return nil
	}
	if cl.Source == string(SourceOIDC) {
		// OIDC sign-ins last until their expiry; a provider removed or
		// turned off in the configuration ends them.
		p := r.Provider(cl.Provider)
		if p == nil || p.Status().State == StateDisabled {
			r.clear(w)
			return nil
		}
		return &Principal{User: cl.User, Groups: cl.Groups, Source: SourceOIDC, Provider: cl.Provider}
	}
	if age := now.Sub(time.Unix(cl.Validated, 0)); age >= r.opts.Config.OpenShift.RevalidateInterval || cl.Validated <= r.revalidateBefore.Load() {
		user, groups, err := r.review(req.Context(), cl.Token)
		switch {
		case err == nil && user == cl.User:
			cl.Groups, cl.Validated = r.keep(groups), now.Unix()
			r.set(w, cl)
		case err == nil, errors.Is(err, ErrUnauthenticated):
			// Token revoked, expired, or now belongs to someone else.
			r.clear(w)
			return nil
		case age >= r.opts.Config.OpenShift.MaxStale:
			// The API server has been unreachable for too long to keep
			// trusting the cached groups.
			r.clear(w)
			return nil
		}
	}
	return &Principal{User: cl.User, Groups: cl.Groups, Source: SourceOpenShift}
}

// review checks a token, deduplicating concurrent requests of one browser.
func (r *Resolver) review(ctx context.Context, token string) (string, []string, error) {
	key := sha256.Sum256([]byte(token))
	now := r.now()
	r.cacheMu.Lock()
	if e, ok := r.cache[key]; ok && now.Sub(e.at) < 30*time.Second {
		r.cacheMu.Unlock()
		return e.user, e.groups, nil
	}
	r.cacheMu.Unlock()
	user, groups, err := r.OpenShift.Review(ctx, token)
	if err != nil {
		return "", nil, err
	}
	r.cacheMu.Lock()
	if len(r.cache) > 5000 {
		r.cache = map[[32]byte]reviewEntry{}
	}
	r.cache[key] = reviewEntry{user: user, groups: groups, at: now}
	r.cacheMu.Unlock()
	return user, groups, nil
}

// SignIn stores an OpenShift sign-in in the SSO cookie.
func (r *Resolver) SignIn(w http.ResponseWriter, user string, groups []string, token string, tokenTTL time.Duration) {
	now := r.now()
	ttl := min(tokenTTL, r.opts.MaxAge)
	if ttl <= 0 {
		ttl = r.opts.MaxAge
	}
	r.set(w, ssoClaims{User: user, Groups: r.keep(groups), Token: token, Validated: now.Unix(), Expires: now.Add(ttl).Unix()})
}

// SignInOIDC stores a verified OIDC sign-in in the SSO cookie. It lasts
// for the provider's sessionMaxAge (or the portal maximum), not for the
// ID token's lifetime: the ID token only proves the sign-in.
func (r *Resolver) SignInOIDC(w http.ResponseWriter, provider string, id *OIDCIdentity) *Principal {
	now := r.now()
	ttl := r.opts.MaxAge
	if p := r.Provider(provider); p != nil && p.SessionMaxAge() > 0 && p.SessionMaxAge() < ttl {
		ttl = p.SessionMaxAge()
	}
	groups := r.keep(id.Groups)
	r.set(w, ssoClaims{User: id.User, Groups: groups, Validated: now.Unix(), Expires: now.Add(ttl).Unix(), Source: string(SourceOIDC), Provider: provider})
	return &Principal{User: id.User, Groups: groups, Source: SourceOIDC, Provider: provider}
}

// SignOut removes the SSO cookie.
func (r *Resolver) SignOut(w http.ResponseWriter) { r.clear(w) }

// keep filters groups to the ones the RBAC policy uses and bounds the
// cookie size.
func (r *Resolver) keep(groups []string) []string {
	var out []string
	for _, g := range groups {
		if r.opts.KeepGroup == nil || r.opts.KeepGroup(g) {
			out = append(out, g)
		}
		if len(out) == 64 {
			break
		}
	}
	return out
}

func (r *Resolver) set(w http.ResponseWriter, cl ssoClaims) {
	exp := time.Unix(cl.Expires, 0)
	v, err := r.sealer.Seal(cl, exp)
	if err != nil {
		r.opts.Logger.Error("cannot seal sso cookie", "error", err.Error())
		return
	}
	for len(v) > maxSealed-200 && len(cl.Groups) > 0 {
		cl.Groups = cl.Groups[:len(cl.Groups)/2]
		v, _ = r.sealer.Seal(cl, exp)
	}
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- HttpOnly, SameSite=Strict; Secure unless local dev
		Name: r.cookieName(), Value: v, Path: "/", Expires: exp,
		HttpOnly: true, Secure: r.opts.SecureCookie, SameSite: http.SameSiteStrictMode,
	})
}

func (r *Resolver) clear(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- expiring cookie; same attributes as set
		Name: r.cookieName(), Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: r.opts.SecureCookie, SameSite: http.SameSiteStrictMode,
	})
}

func peerIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// cookieName drops the __Host- prefix when cookies are not Secure (local
// development only), because browsers reject such cookies.
func (r *Resolver) cookieName() string {
	if r.opts.SecureCookie {
		return SSOCookieName
	}
	return "mongo_portal_sso"
}
