// Package identity resolves who is using the portal.
//
// Identity is optional and comes from one of several sources:
//
//   - OpenShift: the portal's built-in OAuth login; the signed-in user is
//     carried in an encrypted cookie.
//   - Header: a trusted authenticating reverse proxy sets user and group
//     headers (for example oauth2-proxy).
//   - Dev: a fixed identity for local development behind an explicit gate.
//   - MongoDB: no SSO; the user is known by the MongoDB credentials they
//     signed in with. These principals are created at MongoDB login.
//
// A request without an SSO identity is anonymous, which is not an error: the
// portal stays usable through MongoDB login whenever SSO is unavailable.
package identity

import (
	"errors"
	"net"
	"net/http"
	"slices"
	"strings"
	"unicode"

	"github.com/krishnamanaiducloud/mongo-portal/internal/config"
)

// Source identifies how a principal authenticated.
type Source string

const (
	SourceOpenShift Source = "openshift"
	SourceHeader    Source = "header"
	SourceDev       Source = "dev"
	SourceMongoDB   Source = "mongodb"
)

// Principal is an authenticated user.
type Principal struct {
	User   string   `json:"user"`
	Groups []string `json:"groups"`
	Source Source   `json:"source"`
}

// SSO reports whether the principal came from a single sign-on source.
func (p *Principal) SSO() bool { return p != nil && p.Source != SourceMongoDB }

// Key identifies the principal for session ownership. It is qualified by
// source so a MongoDB-only session can never be used by an SSO user of the
// same name, or the other way round.
func (p *Principal) Key() string {
	if p.Source == SourceMongoDB {
		return "mongodb:" + p.User
	}
	return "sso:" + p.User
}

// Subjects lists the RBAC subjects of the principal. SSO users and groups
// match both bare names and qualified "user:"/"group:"
// names. MongoDB-only principals match "mongodb:<user>@<authSource>" and
// "mongodb:<user>".
func (p *Principal) Subjects() []string {
	if p == nil {
		return nil
	}
	if p.Source == SourceMongoDB {
		out := []string{"mongodb:" + p.User}
		if user, _, ok := strings.Cut(p.User, "@"); ok {
			out = append(out, "mongodb:"+user)
		}
		return out
	}
	out := []string{p.User, "user:" + p.User}
	for _, g := range p.Groups {
		out = append(out, g, "group:"+g)
	}
	return out
}

var (
	// ErrUnauthenticated means credentials were presented but are invalid.
	ErrUnauthenticated = errors.New("not authenticated")
	// ErrUnavailable means identity could not be verified right now.
	ErrUnavailable = errors.New("identity verification unavailable")
)

// MongoDBPrincipal returns the principal for a MongoDB-only login.
func MongoDBPrincipal(user, authSource string) *Principal {
	return &Principal{User: user + "@" + authSource, Source: SourceMongoDB}
}

// headerSource trusts user and group headers set by a generic
// authenticating proxy. Group membership is asserted by the proxy, so the
// proxy must be the only network path to the portal.
type headerSource struct {
	cfg     config.HeaderConfig
	trusted []*net.IPNet
}

// resolve returns nil without error when no identity header is present or
// the peer is not trusted (the headers are then ignored).
func (h *headerSource) resolve(r *http.Request) (*Principal, bool) {
	user := r.Header.Get(h.cfg.UserHeader)
	if user == "" {
		return nil, false
	}
	if !peerTrusted(r, h.trusted) {
		return nil, true
	}
	if !ValidUsername(user) {
		return nil, true
	}
	var groups []string
	for _, g := range strings.Split(r.Header.Get(h.cfg.GroupsHeader), ",") {
		if g = strings.TrimSpace(g); g != "" && ValidUsername(g) && !slices.Contains(groups, g) {
			groups = append(groups, g)
		}
	}
	return &Principal{User: user, Groups: groups, Source: SourceHeader}, false
}

// ValidUsername rejects empty, oversized or control-character identities.
func ValidUsername(s string) bool {
	if s == "" || len(s) > 256 {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func parseCIDRs(cidrs []string) ([]*net.IPNet, error) {
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, nil
}

func peerTrusted(r *http.Request, trusted []*net.IPNet) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, n := range trusted {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
