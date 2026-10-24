// Package preflight checks, without changing anything, whether a portal
// configuration can work in its environment: name resolution, network
// reachability, TLS verification, MongoDB topology and version, the
// identity provider MongoDB trusts for MONGODB-OIDC, the portal's sign-in
// providers and the shared store. It never sends a user token or password
// to MongoDB, never writes, and never prints secret values.
package preflight

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/mongo/readpref"

	"github.com/krishnamanaiducloud/mongo-portal/internal/config"
	"github.com/krishnamanaiducloud/mongo-portal/internal/identity"
	"github.com/krishnamanaiducloud/mongo-portal/internal/mongoconn"
	"github.com/krishnamanaiducloud/mongo-portal/internal/store"
	"github.com/krishnamanaiducloud/mongo-portal/internal/tlsx"
)

// Check outcomes.
const (
	Pass = "pass"
	Warn = "warn"
	Fail = "fail"
	Skip = "skip"
)

// Result is one check.
type Result struct {
	Area   string `json:"area"`
	Check  string `json:"check"`
	Target string `json:"target,omitempty"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// Report is the outcome of a preflight run.
type Report struct {
	Version  string         `json:"version,omitempty"`
	Started  time.Time      `json:"started"`
	Results  []Result       `json:"results"`
	Summary  map[string]int `json:"summary"`
	Duration string         `json:"duration"`
}

// Failed reports whether any check failed.
func (r *Report) Failed() bool { return r.Summary[Fail] > 0 }

// Options select what runs.
type Options struct {
	// Profiles limits the profile checks (default: every profile).
	Profiles []string
	// OIDCUser is an optional principal name hint for MONGODB-OIDC servers
	// that select among several identity providers by user name.
	OIDCUser string
	// Timeout bounds each network check (default 10s).
	Timeout time.Duration
	// SkipPortal leaves out the portal-level checks (identity providers,
	// store, files), as the per-profile API does.
	SkipPortal bool
	Logger     *slog.Logger
}

type run struct {
	o   Options
	out []Result
}

func (r *run) add(area, check, target, status, detail string) {
	r.out = append(r.out, Result{Area: area, Check: check, Target: target, Status: status, Detail: detail})
}

// Run executes the checks.
func Run(ctx context.Context, cfg *config.Config, o Options) Report {
	if o.Timeout <= 0 {
		o.Timeout = 10 * time.Second
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	start := time.Now()
	r := &run{o: o}
	if !o.SkipPortal {
		r.portal(ctx, cfg)
	}
	for i := range cfg.Profiles {
		p := &cfg.Profiles[i]
		if len(o.Profiles) > 0 && !slices.Contains(o.Profiles, p.Name) {
			continue
		}
		profile(ctx, r, p)
	}
	rep := Report{Started: start.UTC(), Results: r.out, Summary: map[string]int{Pass: 0, Warn: 0, Fail: 0, Skip: 0}}
	for _, x := range r.out {
		rep.Summary[x.Status]++
	}
	rep.Duration = time.Since(start).Round(time.Millisecond).String()
	return rep
}

// ProfileReport checks one connection profile (used by the API).
func ProfileReport(ctx context.Context, cfg *config.Config, name string, o Options) Report {
	o.Profiles, o.SkipPortal = []string{name}, true
	return Run(ctx, cfg, o)
}

func (r *run) portal(ctx context.Context, cfg *config.Config) {
	const area = "portal"
	if cfg.IsProduction() && cfg.Server.PublicOrigin == "" {
		r.add(area, "public origin", "", Warn, "server.publicOrigin is not set: OAuth redirect URIs follow the request Host header")
	} else if cfg.Server.PublicOrigin != "" {
		r.add(area, "public origin", cfg.Server.PublicOrigin, Pass, "")
	}
	switch f := cfg.Session.KeyFile; {
	case f == "":
		r.add(area, "session key", "", Warn, "session.keyFile is not set: a random key is used, which only works with a single replica")
	default:
		b, err := os.ReadFile(f) // #nosec G304 G703 -- operator configured secret mount; only the length is used
		switch {
		case err != nil:
			r.add(area, "session key", f, Fail, "cannot be read: "+shortErr(err))
		case len(strings.TrimSpace(string(b))) < 32:
			r.add(area, "session key", f, Fail, "shorter than 32 bytes")
		default:
			r.add(area, "session key", f, Pass, "readable, at least 32 bytes (value not shown)")
		}
		clear(b)
	}
	if t := cfg.Server.TLS; t.CertFile != "" {
		r.certFile(area, "portal TLS certificate", t.CertFile, t.KeyFile)
	}
	if err := writable(cfg.Transfer.TempDir); cfg.TransferEnabled() && err != nil {
		r.add(area, "transfer directory", cfg.Transfer.TempDir, Fail, "not writable: "+shortErr(err))
	} else if cfg.TransferEnabled() {
		r.add(area, "transfer directory", cfg.Transfer.TempDir, Pass, "writable")
	}

	// Sign-in providers: the same probes the portal runs at startup.
	osh := identity.NewOpenShift(cfg.Identity.OpenShift, r.o.Logger)
	st := osh.Probe(ctx)
	switch st.State {
	case identity.StateAvailable:
		r.add("identity", "OpenShift OAuth", st.Issuer, Pass, "discovery succeeded")
	case identity.StateDisabled:
		r.add("identity", "OpenShift OAuth", "", Skip, st.Reason)
	default:
		status := Warn
		if cfg.Identity.OpenShift.Enabled == config.EnabledTrue {
			status = Fail
		}
		r.add("identity", "OpenShift OAuth", cfg.Identity.OpenShift.APIURL, status, st.Reason)
	}
	for _, pc := range cfg.Identity.OIDC.Providers {
		if pc.Enabled == config.EnabledFalse {
			r.add("identity", "OIDC provider "+pc.Name, pc.Issuer, Skip, "disabled")
			continue
		}
		st := identity.NewOIDCProvider(pc, r.o.Logger).Probe(ctx)
		if st.State == identity.StateAvailable {
			r.add("identity", "OIDC provider "+pc.Name, pc.Issuer, Pass, "discovery and keys reachable")
		} else {
			r.add("identity", "OIDC provider "+pc.Name, pc.Issuer, Fail, st.Reason)
		}
	}

	if !cfg.Store.Enabled {
		r.add("store", "shared store", "", Skip, "store.enabled is false: audit stays in the log stream and sessions per replica")
		return
	}
	cctx, cancel := context.WithTimeout(ctx, 2*r.o.Timeout)
	defer cancel()
	if detail, err := store.Probe(cctx, cfg); err != nil {
		r.add("store", "shared store", cfg.Store.Profile+"/"+cfg.Store.Database, Fail, err.Error())
	} else {
		r.add("store", "shared store", cfg.Store.Profile+"/"+cfg.Store.Database, Pass, detail)
	}
}

// profile runs the checks of one connection profile.
func profile(ctx context.Context, r *run, p *config.Profile) {
	area := "profile " + p.Name
	if p.TLS.Mode == config.TLSDisabled {
		status := Warn
		if p.PlaintextApproved {
			status = Pass
		}
		r.add(area, "transport", "", status, "TLS is disabled for this profile (plaintextApproved="+strconv.FormatBool(p.PlaintextApproved)+")")
	}
	addrs, srv := hostPorts(p.URI)
	if srv {
		host := addrs[0]
		_, recs, err := net.DefaultResolver.LookupSRV(ctx, "mongodb", "tcp", host)
		if err != nil {
			r.add(area, "DNS SRV", host, Fail, shortErr(err))
			return
		}
		addrs = nil
		for _, s := range recs {
			addrs = append(addrs, net.JoinHostPort(strings.TrimSuffix(s.Target, "."), strconv.Itoa(int(s.Port))))
		}
		r.add(area, "DNS SRV", host, Pass, fmt.Sprintf("%d hosts", len(addrs)))
	}
	var tc *tls.Config
	if p.TLS.Mode == config.TLSEnabled {
		var err error
		if tc, err = mongoconn.BuildTLSConfig(p.TLS); err != nil {
			r.add(area, "TLS configuration", "", Fail, shortErr(err))
			return
		}
		if p.TLS.CAFile != "" {
			r.certFile(area, "CA certificate", p.TLS.CAFile, "")
		}
		if p.TLS.ClientCertFile != "" {
			r.certFile(area, "client certificate", p.TLS.ClientCertFile, p.TLS.ClientKeyFile)
		}
	}
	var reachable []string
	for _, a := range addrs {
		host, _, _ := net.SplitHostPort(a)
		if _, err := net.DefaultResolver.LookupHost(ctx, host); err != nil {
			r.add(area, "DNS", host, Fail, shortErr(err))
			continue
		}
		d := net.Dialer{Timeout: r.o.Timeout}
		conn, err := d.DialContext(ctx, "tcp", a)
		if err != nil {
			r.add(area, "TCP", a, Fail, shortErr(err))
			continue
		}
		_ = conn.Close()
		reachable = append(reachable, a)
		if tc != nil {
			r.tlsHandshake(ctx, area, a, tc)
		}
	}
	if len(reachable) == 0 {
		return
	}
	direct := ""
	if !srv {
		direct = reachable[0]
	}
	r.hello(ctx, area, p, direct)
	if p.OIDC != nil {
		r.mongoOIDC(ctx, area, p)
	}
}

func (r *run) tlsHandshake(ctx context.Context, area, addr string, base *tls.Config) {
	host, _, _ := net.SplitHostPort(addr)
	tc := base.Clone()
	if tc.ServerName == "" {
		tc.ServerName = host
	}
	d := tls.Dialer{NetDialer: &net.Dialer{Timeout: r.o.Timeout}, Config: tc}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		r.add(area, "TLS", addr, Fail, tlsReason(err))
		return
	}
	defer conn.Close()
	cs := conn.(*tls.Conn).ConnectionState()
	leaf := cs.PeerCertificates[0]
	left := time.Until(leaf.NotAfter)
	detail := fmt.Sprintf("verified %s, issuer %q, expires %s (%d days)", tls.VersionName(cs.Version), leaf.Issuer.CommonName,
		leaf.NotAfter.UTC().Format("2006-01-02"), int(left.Hours()/24))
	status := Pass
	if left < 30*24*time.Hour {
		status = Warn
	}
	r.add(area, "TLS", addr, status, detail)
}

func tlsReason(err error) string {
	var ua x509.UnknownAuthorityError
	var he x509.HostnameError
	var ci x509.CertificateInvalidError
	switch {
	case errors.As(err, &ua):
		return "the server certificate is not signed by a trusted CA (check tls.caFile)"
	case errors.As(err, &he):
		return "the server certificate does not cover this host name (" + he.Error() + ")"
	case errors.As(err, &ci) && ci.Reason == x509.Expired:
		return "the server certificate has expired or is not yet valid"
	case strings.Contains(err.Error(), "certificate required"):
		return "the server requires a client certificate (tls.clientCertFile)"
	}
	return shortErr(err)
}

// hello reads topology and version without authenticating. With direct
// set it talks to that member only, so a wrong replica set name in the
// profile is reported as such instead of as a server selection timeout.
func (r *run) hello(ctx context.Context, area string, p *config.Profile, direct string) {
	opts, err := mongoconn.ClientOptions(p, mongoconn.PoolHooks{})
	if err != nil {
		r.add(area, "MongoDB", "", Fail, shortErr(err))
		return
	}
	opts.SetAppName("mongo-portal-preflight").SetMaxPoolSize(1).SetRetryReads(false).SetServerSelectionTimeout(r.o.Timeout)
	if direct != "" {
		opts.ReplicaSet = nil
		opts.SetHosts([]string{direct}).SetDirect(true)
	}
	c, err := mongo.Connect(opts)
	if err != nil {
		r.add(area, "MongoDB", "", Fail, shortErr(err))
		return
	}
	defer disconnect(c)
	cctx, cancel := context.WithTimeout(ctx, 2*r.o.Timeout)
	defer cancel()
	var h struct {
		SetName           string   `bson:"setName"`
		Hosts             []string `bson:"hosts"`
		Primary           string   `bson:"primary"`
		IsWritablePrimary bool     `bson:"isWritablePrimary"`
		MaxWireVersion    int32    `bson:"maxWireVersion"`
	}
	nearest := options.RunCmd().SetReadPreference(readpref.Nearest())
	if err := c.Database("admin").RunCommand(cctx, bson.D{{Key: "hello", Value: 1}}, nearest).Decode(&h); err != nil {
		r.add(area, "MongoDB hello", "", Fail, mongoconn.Classify(err).Msg)
		return
	}
	topo := "standalone"
	if h.SetName != "" {
		topo = fmt.Sprintf("replica set %q, %d members, primary %s", h.SetName, len(h.Hosts), orNone(h.Primary))
	}
	status := Pass
	want := p.ReplicaSet
	if want == "" {
		if _, q, ok := strings.Cut(p.URI, "?"); ok {
			v, _ := url.ParseQuery(q)
			want = v.Get("replicaSet")
		}
	}
	switch {
	case want != "" && h.SetName != want:
		status, topo = Fail, topo+fmt.Sprintf(": the profile expects replica set %q", want)
	case h.SetName != "" && h.Primary == "":
		status, topo = Warn, topo+" (no primary: writes are not possible)"
	}
	r.add(area, "MongoDB topology", "", status, topo)
	var bi struct {
		Version string   `bson:"version"`
		Modules []string `bson:"modules"`
	}
	if err := c.Database("admin").RunCommand(cctx, bson.D{{Key: "buildInfo", Value: 1}}, nearest).Decode(&bi); err != nil {
		r.add(area, "MongoDB version", "", Warn, "buildInfo is not available without authentication: "+mongoconn.Classify(err).Msg)
		return
	}
	edition := "Community"
	if slices.Contains(bi.Modules, "enterprise") {
		edition = "Enterprise"
	}
	r.add(area, "MongoDB version", "", Pass, bi.Version+" "+edition)
	if p.OIDC != nil {
		major, _, _ := strings.Cut(bi.Version, ".")
		if n, _ := strconv.Atoi(major); n < 7 || edition != "Enterprise" {
			r.add(area, "MONGODB-OIDC support", "", Fail, "MONGODB-OIDC needs MongoDB Enterprise 7.0 or later (server: "+bi.Version+" "+edition+")")
		}
	}
}

// errStop ends the MONGODB-OIDC conversation after the server announced its
// identity provider; no token is ever sent.
var errStop = errors.New("preflight: identity provider information received")

// ServerIdP asks the server which identity provider it trusts for
// MONGODB-OIDC (the first step of the conversation, before any token).
func ServerIdP(ctx context.Context, p *config.Profile, user string, timeout time.Duration) (*options.IDPInfo, error) {
	opts, err := mongoconn.ClientOptions(p, mongoconn.PoolHooks{})
	if err != nil {
		return nil, err
	}
	var got *options.IDPInfo
	opts.SetAppName("mongo-portal-preflight").SetMaxPoolSize(1).SetRetryReads(false).SetServerSelectionTimeout(timeout)
	opts.SetAuth(options.Credential{
		AuthMechanism: config.MechanismOIDC, Username: user,
		AuthMechanismProperties: map[string]string{"ALLOWED_HOSTS": strings.Join(p.OIDC.AllowedHosts, ",")},
		OIDCHumanCallback: func(_ context.Context, a *options.OIDCArgs) (*options.OIDCCredential, error) {
			got = a.IDPInfo
			return nil, errStop
		},
	})
	c, err := mongo.Connect(opts)
	if err != nil {
		return nil, err
	}
	defer disconnect(c)
	cctx, cancel := context.WithTimeout(ctx, 2*timeout)
	defer cancel()
	err = c.Ping(cctx, readpref.PrimaryPreferred())
	if got != nil {
		return got, nil
	}
	if err == nil {
		err = errors.New("the server accepted the connection without asking for a token")
	}
	return nil, err
}

func (r *run) mongoOIDC(ctx context.Context, area string, p *config.Profile) {
	o := p.OIDC
	client, err := tlsx.HTTPClient(o.RequestTimeout, append([]string{o.CAFile}, o.ExtraCAFiles...)...)
	if err != nil {
		r.add(area, "MONGODB-OIDC provider", o.Issuer, Warn, "CA files: "+shortErr(err))
	}
	if d, err := discover(ctx, client, o.Issuer); err != nil {
		r.add(area, "MONGODB-OIDC provider", o.Issuer, Fail, err.Error())
	} else {
		r.add(area, "MONGODB-OIDC provider", o.Issuer, Pass, d)
	}
	info, err := ServerIdP(ctx, p, r.o.OIDCUser, r.o.Timeout)
	if err != nil {
		msg := mongoconn.Classify(err).Msg
		if strings.Contains(strings.ToLower(err.Error()), "mechanism") {
			msg = "the server does not accept MONGODB-OIDC (authenticationMechanisms / oidcIdentityProviders): " + shortErr(err)
		}
		r.add(area, "MONGODB-OIDC server", "", Fail, msg)
		return
	}
	switch {
	case strings.TrimSuffix(info.Issuer, "/") != strings.TrimSuffix(o.Issuer, "/"):
		r.add(area, "MONGODB-OIDC server", "", Fail, fmt.Sprintf("MongoDB trusts issuer %q, the profile is configured for %q", info.Issuer, o.Issuer))
	case info.ClientID != "" && info.ClientID != o.ClientID:
		r.add(area, "MONGODB-OIDC server", "", Fail, fmt.Sprintf("MongoDB announces client id %q, the profile uses %q", info.ClientID, o.ClientID))
	default:
		r.add(area, "MONGODB-OIDC server", "", Pass, fmt.Sprintf("MongoDB trusts %s (client %s, scopes %s)", info.Issuer, orNone(info.ClientID), orNone(strings.Join(info.RequestScopes, " "))))
	}
}

func (r *run) certFile(area, check, certFile, keyFile string) {
	b, err := os.ReadFile(certFile) // #nosec G304 G703 -- operator configured mount
	if err != nil {
		r.add(area, check, certFile, Fail, "cannot be read: "+shortErr(err))
		return
	}
	certs, err := parsePEM(b)
	if err != nil || len(certs) == 0 {
		r.add(area, check, certFile, Fail, "no PEM certificate")
		return
	}
	if keyFile != "" {
		if _, err := tls.LoadX509KeyPair(certFile, keyFile); err != nil {
			r.add(area, check, certFile, Fail, "certificate and key do not form a pair: "+shortErr(err))
			return
		}
	}
	leaf := certs[0]
	left := time.Until(leaf.NotAfter)
	status, detail := Pass, fmt.Sprintf("%q expires %s (%d days)", leaf.Subject.CommonName, leaf.NotAfter.UTC().Format("2006-01-02"), int(left.Hours()/24))
	switch {
	case left <= 0:
		status, detail = Fail, "expired "+leaf.NotAfter.UTC().Format("2006-01-02")
	case left < 30*24*time.Hour:
		status = Warn
	}
	r.add(area, check, certFile, status, detail)
}

// hostPorts returns host:port pairs of a profile URI (or the SRV name).
func hostPorts(uri string) ([]string, bool) {
	srv := strings.HasPrefix(uri, "mongodb+srv://")
	rest := strings.TrimPrefix(strings.TrimPrefix(uri, "mongodb+srv://"), "mongodb://")
	authority, _, _ := strings.Cut(rest, "?")
	hosts, _, _ := strings.Cut(authority, "/")
	var out []string
	for _, h := range strings.Split(hosts, ",") {
		if h == "" {
			continue
		}
		if _, _, err := net.SplitHostPort(h); err != nil && !srv {
			h = net.JoinHostPort(strings.Trim(h, "[]"), "27017")
		}
		out = append(out, h)
	}
	return out, srv
}

func writable(dir string) error {
	f, err := os.CreateTemp(dir, ".preflight-*")
	if err != nil {
		return err
	}
	name := f.Name()
	_ = f.Close()
	return os.Remove(name)
}

func disconnect(c *mongo.Client) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = c.Disconnect(ctx)
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

func shortErr(err error) string {
	s := err.Error()
	if u := (*url.Error)(nil); errors.As(err, &u) {
		s = u.Err.Error()
	}
	if len(s) > 240 {
		s = s[:240] + "..."
	}
	return s
}
