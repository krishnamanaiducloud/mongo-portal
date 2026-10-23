// Package config loads and validates the portal configuration.
//
// Configuration comes from a YAML file (normally a mounted ConfigMap) with a
// small number of environment variable overrides. Secrets are never placed in
// the YAML file; they are referenced by file path (mounted Kubernetes Secrets).
package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// Deprecated identity.mode values, still accepted and mapped onto the
// identity sources below.
const (
	IdentityOpenShift = "openshift"
	IdentityHeader    = "header"
	IdentityDev       = "dev"
)

// OpenShift SSO enablement. "auto" offers OpenShift login whenever the
// portal runs in an OpenShift cluster whose OAuth server is reachable, and
// stays silent otherwise.
const (
	EnabledAuto  = "auto"
	EnabledTrue  = "true"
	EnabledFalse = "false"
)

// TLS modes for MongoDB connection profiles. There is intentionally no
// default: every profile must state its transport security explicitly.
const (
	TLSEnabled  = "enabled"
	TLSDisabled = "disabled"
)

// DevIdentityGateEnv must be set to "true" before the insecure development
// identity mode is accepted. This prevents accidental use in a cluster.
const DevIdentityGateEnv = "PORTAL_ALLOW_INSECURE_DEV_IDENTITY"

type Config struct {
	// Environment is a free-form label (dev, test, prod). The value
	// "production" or "prod" enables stricter startup checks.
	Environment string           `yaml:"environment"`
	Server      ServerConfig     `yaml:"server"`
	Identity    IdentityConfig   `yaml:"identity"`
	RBAC        RBACConfig       `yaml:"rbac"`
	Session     SessionConfig    `yaml:"session"`
	Query       QueryConfig      `yaml:"query"`
	Login       LoginConfig      `yaml:"login"`
	Audit       AuditConfig      `yaml:"audit"`
	Shell       ShellConfig      `yaml:"shell"`
	Monitoring  MonitoringConfig `yaml:"monitoring"`
	Profiles    []Profile        `yaml:"profiles"`
}

type ServerConfig struct {
	// ListenAddress serves the UI and API.
	ListenAddress string `yaml:"listenAddress"`
	// OpsListenAddress serves /healthz, /readyz and /metrics only.
	OpsListenAddress string `yaml:"opsListenAddress"`
	// TLS serves ListenAddress over HTTPS when set (for example with the
	// OpenShift service CA certificate behind a re-encrypt Route). The
	// certificate is reloaded when the files change.
	TLS ServerTLSConfig `yaml:"tls"`
	// PublicOrigin is the externally visible origin (https://host). When set,
	// unsafe requests must carry a matching Origin header and OAuth redirect
	// URIs are built from it.
	PublicOrigin    string        `yaml:"publicOrigin"`
	MaxBodyBytes    int64         `yaml:"maxBodyBytes"`
	ReadTimeout     time.Duration `yaml:"readTimeout"`
	WriteTimeout    time.Duration `yaml:"writeTimeout"`
	ShutdownDelay   time.Duration `yaml:"shutdownDelay"`
	ShutdownTimeout time.Duration `yaml:"shutdownTimeout"`
	HSTS            bool          `yaml:"hsts"`
}

type ServerTLSConfig struct {
	CertFile string `yaml:"certFile"`
	KeyFile  string `yaml:"keyFile"`
}

// IdentityConfig configures single sign-on. Every SSO source is optional:
// when none is available, users sign in with their MongoDB credentials and
// the RBAC policy applies to their MongoDB identity.
type IdentityConfig struct {
	// Mode is deprecated; use the per-source settings.
	Mode string `yaml:"mode"`
	// RequireSSO refuses MongoDB logins without an SSO identity. With the
	// default (false) MongoDB-only login stays available, which keeps the
	// portal usable when OpenShift is unreachable.
	RequireSSO bool `yaml:"requireSSO"`
	// DeveloperGroups and SREGroups are deprecated shortcuts for the RBAC
	// lines "g, <group>, role:readonly" and "g, <group>, role:admin".
	DeveloperGroups []string `yaml:"developerGroups"`
	SREGroups       []string `yaml:"sreGroups"`
	// TrustedProxyCIDRs lists the source networks allowed to supply identity
	// headers (header source only). Defaults to loopback only.
	TrustedProxyCIDRs []string `yaml:"trustedProxyCIDRs"`
	// SSOLogoutURL, if set, is offered in the UI to end the SSO session at
	// the identity provider.
	SSOLogoutURL string          `yaml:"ssoLogoutURL"`
	OpenShift    OpenShiftConfig `yaml:"openshift"`
	Header       HeaderConfig    `yaml:"header"`
	Dev          DevConfig       `yaml:"dev"`
}

// OpenShiftConfig configures the built-in OpenShift OAuth login, which works
// like Argo CD's OpenShift connector: the portal's service account is the
// OAuth client and group membership comes from the user's own token.
type OpenShiftConfig struct {
	// Enabled is "auto" (default), "true" or "false". "true" only changes
	// logging: an unavailable OAuth server is reported as a warning.
	Enabled string `yaml:"enabled"`
	APIURL  string `yaml:"apiURL"`
	// CAFile trusts the API server and, in OpenShift, the default ingress
	// certificate of the OAuth server. ExtraCAFiles are optional (missing
	// files are skipped); the system roots are always trusted.
	CAFile       string   `yaml:"caFile"`
	ExtraCAFiles []string `yaml:"extraCAFiles"`
	// ServiceAccountTokenFile is the OAuth client secret; NamespaceFile and
	// the token's subject give the client id
	// system:serviceaccount:<namespace>:<name> unless ClientID is set.
	ServiceAccountFile string   `yaml:"serviceAccountTokenFile"`
	NamespaceFile      string   `yaml:"namespaceFile"`
	ClientID           string   `yaml:"clientID"`
	Scopes             []string `yaml:"scopes"`
	// ProbeInterval is how often OAuth availability is re-checked while it
	// is unavailable (healthy servers are re-checked 5x less often).
	ProbeInterval time.Duration `yaml:"probeInterval"`
	// RevalidateInterval re-checks a signed-in user's token and groups.
	// MaxStale bounds how long a user stays signed in while the API server
	// cannot be reached for revalidation.
	RevalidateInterval time.Duration `yaml:"revalidateInterval"`
	MaxStale           time.Duration `yaml:"maxStale"`
	RequestTimeout     time.Duration `yaml:"requestTimeout"`
}

type HeaderConfig struct {
	// Enabled accepts identity headers from a trusted authenticating proxy.
	Enabled      bool   `yaml:"enabled"`
	UserHeader   string `yaml:"userHeader"`
	GroupsHeader string `yaml:"groupsHeader"`
}

// DevConfig is a fixed identity for local development only. It requires the
// PORTAL_ALLOW_INSECURE_DEV_IDENTITY=true environment gate.
type DevConfig struct {
	Enabled bool     `yaml:"enabled"`
	User    string   `yaml:"user"`
	Groups  []string `yaml:"groups"`
}

// RBACConfig configures Argo CD-style portal RBAC (see package rbac).
type RBACConfig struct {
	// DefaultRole applies to signed-in users (SSO or MongoDB-only) whom no
	// "g" line maps. Defaults to role:mongodb: the portal then offers what the
	// user's MongoDB privileges allow and MongoDB decides. Set "" to grant
	// nothing unless mapped, or role:readonly to cap unmapped users.
	DefaultRole *string `yaml:"defaultRole"`
	// Policy is inline CSV (p and g lines).
	Policy string `yaml:"policy"`
	// PolicyDir optionally contains policy.csv and policy.default (an
	// RBAC ConfigMap mount). It is re-read every ReloadInterval; a missing
	// directory is ignored.
	PolicyDir      string        `yaml:"policyDir"`
	ReloadInterval time.Duration `yaml:"reloadInterval"`
}

// MonitoringConfig controls background health checks of the connection
// profiles (unauthenticated "hello"/"ping"; no credentials are used).
type MonitoringConfig struct {
	// ProfileHealthInterval defaults to 30s; a negative value disables it.
	ProfileHealthInterval time.Duration `yaml:"profileHealthInterval"`
}

type SessionConfig struct {
	CookieName      string        `yaml:"cookieName"`
	SecureCookie    *bool         `yaml:"secureCookie"`
	IdleTimeout     time.Duration `yaml:"idleTimeout"`
	AbsoluteTimeout time.Duration `yaml:"absoluteTimeout"`
	MaxPerUser      int           `yaml:"maxPerUser"`
	MaxTotal        int           `yaml:"maxTotal"`
	// KeyFile holds the HMAC key (>= 32 bytes) used for pre-login CSRF
	// tokens. It must be identical on all replicas. If unset, a random key is
	// generated at startup (acceptable for a single replica only).
	KeyFile string `yaml:"keyFile"`
}

type QueryConfig struct {
	DefaultLimit     int64         `yaml:"defaultLimit"`
	MaxLimit         int64         `yaml:"maxLimit"`
	MaxSkip          int64         `yaml:"maxSkip"`
	DefaultMaxTime   time.Duration `yaml:"defaultMaxTime"`
	MaxMaxTime       time.Duration `yaml:"maxMaxTime"`
	MaxResponseBytes int           `yaml:"maxResponseBytes"`
	MaxDocumentBytes int64         `yaml:"maxDocumentBytes"`
	MaxCount         int64         `yaml:"maxCount"`
	// AllowWriteStages permits $out/$merge for users whose RBAC role may
	// create documents in the source and target namespaces.
	AllowWriteStages bool `yaml:"allowWriteStages"`
	// Deprecated alias of AllowWriteStages.
	AllowWriteStagesForSRE bool `yaml:"allowWriteStagesForSRE"`
}

type LoginConfig struct {
	// Per SSO identity: at most AttemptsPerWindow login attempts per Window.
	AttemptsPerWindow int           `yaml:"attemptsPerWindow"`
	Window            time.Duration `yaml:"window"`
	// Per (profile, MongoDB user): lock after FailuresBeforeLock failures.
	FailuresBeforeLock int           `yaml:"failuresBeforeLock"`
	LockDuration       time.Duration `yaml:"lockDuration"`
	MaxLockDuration    time.Duration `yaml:"maxLockDuration"`
	MaxConcurrent      int           `yaml:"maxConcurrent"`
	Timeout            time.Duration `yaml:"timeout"`
}

type AuditConfig struct {
	BufferSize int `yaml:"bufferSize"`
}

// ShellConfig controls the in-browser mongosh shell.
type ShellConfig struct {
	// Enabled turns the shell API on (default true).
	Enabled *bool `yaml:"enabled"`
	// MaxCursors open per session; CursorIdleTimeout closes unused ones.
	MaxCursors        int           `yaml:"maxCursors"`
	CursorIdleTimeout time.Duration `yaml:"cursorIdleTimeout"`
	// MaxCursorDocuments caps the documents one cursor may return in total.
	MaxCursorDocuments int64 `yaml:"maxCursorDocuments"`
	// MaxBatchDocuments caps one find/aggregate/getMore response.
	MaxBatchDocuments int `yaml:"maxBatchDocuments"`
	// MaxInsertDocuments caps insertMany and bulkWrite operation counts.
	MaxInsertDocuments int `yaml:"maxInsertDocuments"`
	// AllowDropDatabase permits db.dropDatabase() for SREs (default false).
	AllowDropDatabase bool `yaml:"allowDropDatabase"`
}

// ShellEnabled reports whether the shell API is enabled.
func (c *Config) ShellEnabled() bool { return c.Shell.Enabled == nil || *c.Shell.Enabled }

// Profile is an administrator-approved MongoDB deployment. Users can only
// connect to hosts listed in profiles; they never supply addresses.
type Profile struct {
	Name        string `yaml:"name"`
	DisplayName string `yaml:"displayName"`
	Description string `yaml:"description"`
	// URI contains hosts and non-security options only. Credentials, auth
	// and TLS options are rejected; TLS is configured in the TLS block.
	URI                    string        `yaml:"uri"`
	ReplicaSet             string        `yaml:"replicaSet"`
	DefaultAuthSource      string        `yaml:"defaultAuthSource"`
	AuthMechanisms         []string      `yaml:"authMechanisms"`
	ReadPreference         string        `yaml:"readPreference"`
	ConnectTimeout         time.Duration `yaml:"connectTimeout"`
	ServerSelectionTimeout time.Duration `yaml:"serverSelectionTimeout"`
	OperationTimeout       time.Duration `yaml:"operationTimeout"`
	MaxPoolSize            uint64        `yaml:"maxPoolSize"`
	MaxConnIdleTime        time.Duration `yaml:"maxConnIdleTime"`
	TLS                    TLSConfig     `yaml:"tls"`
	// PlaintextApproved records an explicit security exception for non-TLS
	// connections. Required when Environment is production.
	PlaintextApproved    bool   `yaml:"plaintextApproved"`
	SecurityExceptionRef string `yaml:"securityExceptionRef"`
}

type TLSConfig struct {
	Mode string `yaml:"mode"`
	// VerifyServerCertificate exists so configuration is self-describing. It
	// must be true (or omitted); disabling verification is not supported.
	VerifyServerCertificate *bool  `yaml:"verifyServerCertificate"`
	CAFile                  string `yaml:"caFile"`
	// UseSystemRoots adds the container's system trust store to CAFile.
	UseSystemRoots bool   `yaml:"useSystemRoots"`
	ClientCertFile string `yaml:"clientCertFile"`
	ClientKeyFile  string `yaml:"clientKeyFile"`
	MinVersion     string `yaml:"minVersion"`
	// ServerName overrides the hostname used for certificate verification.
	ServerName string `yaml:"serverName"`
}

var (
	profileNameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	headerNameRe  = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)
	authSourceRe  = regexp.MustCompile(`^[^/\\. "$*<>:|?\x00]{1,64}$`)
)

// SupportedMechanisms lists MongoDB auth mechanisms usable with a password.
var SupportedMechanisms = []string{"SCRAM-SHA-256", "SCRAM-SHA-1"}

// forbiddenURIOptions may not appear in a profile URI. Credentials, auth and
// TLS behaviour are controlled exclusively by structured configuration so
// that certificate verification can never be disabled through the URI.
var forbiddenURIOptions = []string{
	"tls", "ssl", "tlsinsecure", "tlsallowinvalidcertificates",
	"tlsallowinvalidhostnames", "tlsdisableocspendpointcheck",
	"tlsdisablecertificaterevocationcheck", "sslallowinvalidcertificates",
	"sslallowinvalidhostnames", "tlscafile", "tlscertificatekeyfile",
	"tlscertificatekeyfilepassword", "sslcafile", "sslpemkeyfile",
	"authmechanism", "authsource", "authmechanismproperties",
	"username", "password",
}

// Load reads the YAML file at path, applies defaults and environment
// overrides, and validates the result.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- path is operator supplied
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	return Parse(raw)
}

// Parse parses YAML configuration bytes.
func Parse(raw []byte) (*Config, error) {
	cfg := &Config{}
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	cfg.applyEnv()
	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) applyEnv() {
	if v := os.Getenv("PORTAL_LISTEN_ADDRESS"); v != "" {
		c.Server.ListenAddress = v
	}
	if v := os.Getenv("PORTAL_OPS_LISTEN_ADDRESS"); v != "" {
		c.Server.OpsListenAddress = v
	}
	if v := os.Getenv("PORTAL_PUBLIC_ORIGIN"); v != "" {
		c.Server.PublicOrigin = v
	}
	if v := os.Getenv("PORTAL_SESSION_KEY_FILE"); v != "" {
		c.Session.KeyFile = v
	}
}

func (c *Config) applyDefaults() {
	s := &c.Server
	setDefault(&s.ListenAddress, "127.0.0.1:8080")
	setDefault(&s.OpsListenAddress, "0.0.0.0:9090")
	if s.MaxBodyBytes == 0 {
		s.MaxBodyBytes = 1 << 20
	}
	setDuration(&s.ReadTimeout, 30*time.Second)
	setDuration(&s.WriteTimeout, 90*time.Second)
	setDuration(&s.ShutdownDelay, 5*time.Second)
	setDuration(&s.ShutdownTimeout, 30*time.Second)

	id := &c.Identity
	if len(id.TrustedProxyCIDRs) == 0 {
		id.TrustedProxyCIDRs = []string{"127.0.0.1/32", "::1/128"}
	}
	// Deprecated identity.mode: map onto the source settings.
	switch id.Mode {
	case IdentityHeader:
		id.Header.Enabled = true
	case IdentityDev:
		id.Dev.Enabled = true
	}
	o := &id.OpenShift
	if id.Mode == IdentityHeader || id.Mode == IdentityDev {
		setDefault(&o.Enabled, EnabledFalse)
	}
	setDefault(&o.Enabled, EnabledAuto)
	o.Enabled = strings.ToLower(o.Enabled)
	setDefault(&o.APIURL, "https://kubernetes.default.svc")
	setDefault(&o.CAFile, "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
	setDefault(&o.ServiceAccountFile, "/var/run/secrets/kubernetes.io/serviceaccount/token")
	setDefault(&o.NamespaceFile, "/var/run/secrets/kubernetes.io/serviceaccount/namespace")
	if len(o.Scopes) == 0 {
		o.Scopes = []string{"user:info"}
	}
	setDuration(&o.ProbeInterval, time.Minute)
	setDuration(&o.RevalidateInterval, 5*time.Minute)
	setDuration(&o.MaxStale, time.Hour)
	setDuration(&o.RequestTimeout, 5*time.Second)
	setDefault(&id.Header.UserHeader, "X-Forwarded-User")
	setDefault(&id.Header.GroupsHeader, "X-Forwarded-Groups")

	rb := &c.RBAC
	if rb.DefaultRole == nil {
		d := "role:mongodb"
		rb.DefaultRole = &d
	}
	setDefault(&rb.PolicyDir, "/etc/mongo-portal/rbac")
	setDuration(&rb.ReloadInterval, 30*time.Second)
	setDuration(&c.Monitoring.ProfileHealthInterval, 30*time.Second)
	if c.Query.AllowWriteStagesForSRE {
		c.Query.AllowWriteStages = true
	}

	ss := &c.Session
	setDefault(&ss.CookieName, "__Host-mongo_portal_session")
	if ss.SecureCookie == nil {
		t := true
		ss.SecureCookie = &t
	}
	setDuration(&ss.IdleTimeout, 15*time.Minute)
	setDuration(&ss.AbsoluteTimeout, 8*time.Hour)
	setInt(&ss.MaxPerUser, 3)
	setInt(&ss.MaxTotal, 200)

	q := &c.Query
	setInt64(&q.DefaultLimit, 20)
	setInt64(&q.MaxLimit, 200)
	setInt64(&q.MaxSkip, 100000)
	setDuration(&q.DefaultMaxTime, 10*time.Second)
	setDuration(&q.MaxMaxTime, 60*time.Second)
	setInt(&q.MaxResponseBytes, 8<<20)
	setInt64(&q.MaxDocumentBytes, 4<<20)
	setInt64(&q.MaxCount, 1000000)

	l := &c.Login
	setInt(&l.AttemptsPerWindow, 10)
	setDuration(&l.Window, 5*time.Minute)
	setInt(&l.FailuresBeforeLock, 5)
	setDuration(&l.LockDuration, 5*time.Minute)
	setDuration(&l.MaxLockDuration, 30*time.Minute)
	setInt(&l.MaxConcurrent, 20)
	setDuration(&l.Timeout, 15*time.Second)

	setInt(&c.Audit.BufferSize, 1000)

	sh := &c.Shell
	setInt(&sh.MaxCursors, 20)
	setDuration(&sh.CursorIdleTimeout, 10*time.Minute)
	setInt64(&sh.MaxCursorDocuments, 100000)
	setInt(&sh.MaxBatchDocuments, 1000)
	setInt(&sh.MaxInsertDocuments, 1000)

	for i := range c.Profiles {
		p := &c.Profiles[i]
		setDefault(&p.DisplayName, p.Name)
		setDefault(&p.DefaultAuthSource, "admin")
		if len(p.AuthMechanisms) == 0 {
			p.AuthMechanisms = slices.Clone(SupportedMechanisms)
		}
		setDefault(&p.ReadPreference, "primary")
		setDuration(&p.ConnectTimeout, 10*time.Second)
		setDuration(&p.ServerSelectionTimeout, 10*time.Second)
		setDuration(&p.OperationTimeout, 2*time.Minute)
		if p.MaxPoolSize == 0 {
			p.MaxPoolSize = 5
		}
		setDuration(&p.MaxConnIdleTime, 5*time.Minute)
		setDefault(&p.TLS.MinVersion, "1.2")
	}
}

// IsProduction reports whether strict production checks apply.
func (c *Config) IsProduction() bool {
	e := strings.ToLower(c.Environment)
	return e == "prod" || e == "production"
}

// Validate checks the configuration for unsafe or inconsistent settings.
func (c *Config) Validate() error {
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	if _, _, err := net.SplitHostPort(c.Server.ListenAddress); err != nil {
		add("server.listenAddress: %v", err)
	}
	if _, _, err := net.SplitHostPort(c.Server.OpsListenAddress); err != nil {
		add("server.opsListenAddress: %v", err)
	}
	if c.Server.PublicOrigin != "" {
		u, err := url.Parse(c.Server.PublicOrigin)
		if err != nil || u.Scheme == "" || u.Host == "" || (u.Path != "" && u.Path != "/") {
			add("server.publicOrigin must be an origin such as https://portal.example.com")
		}
	}

	if (c.Server.TLS.CertFile == "") != (c.Server.TLS.KeyFile == "") {
		add("server.tls.certFile and server.tls.keyFile must be set together")
	}

	id := c.Identity
	switch id.Mode {
	case "", IdentityOpenShift, IdentityHeader, IdentityDev:
	default:
		add("identity.mode (deprecated) must be one of %q, %q, %q", IdentityOpenShift, IdentityHeader, IdentityDev)
	}
	switch id.OpenShift.Enabled {
	case EnabledAuto, EnabledTrue, EnabledFalse:
	default:
		add("identity.openshift.enabled must be auto, true or false")
	}
	if u, err := url.Parse(id.OpenShift.APIURL); err != nil || u.Scheme != "https" || u.Host == "" {
		add("identity.openshift.apiURL must be an https URL")
	}
	for _, s := range id.OpenShift.Scopes {
		if s == "" || strings.ContainsAny(s, " \t\r\n") {
			add("identity.openshift.scopes contains an invalid scope %q", s)
		}
	}
	if id.Header.Enabled && (!validHeader(id.Header.UserHeader) || !validHeader(id.Header.GroupsHeader)) {
		add("identity.header header names are invalid")
	}
	if id.Dev.Enabled {
		if os.Getenv(DevIdentityGateEnv) != "true" {
			add("identity.dev requires %s=true and must never be used in a cluster", DevIdentityGateEnv)
		}
		if c.IsProduction() {
			add("identity.dev is not allowed when environment is production")
		}
		if id.Dev.User == "" {
			add("identity.dev.user is required")
		}
	}
	if id.Dev.Enabled && id.Header.Enabled {
		add("identity.dev and identity.header cannot both be enabled")
	}
	if id.RequireSSO && !id.Dev.Enabled && !id.Header.Enabled && id.OpenShift.Enabled == EnabledFalse {
		add("identity.requireSSO needs an SSO source (openshift, header or dev)")
	}
	for _, cidr := range id.TrustedProxyCIDRs {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			add("identity.trustedProxyCIDRs: %v", err)
		}
	}
	if !*c.Session.SecureCookie && !id.Dev.Enabled {
		add("session.secureCookie=false is only permitted with the development identity")
	}
	for _, g := range append(slices.Clone(id.DeveloperGroups), id.SREGroups...) {
		if g == "" || strings.ContainsAny(g, ",\r\n") {
			add("identity group names must not be empty or contain commas: %q", g)
		}
	}
	if d := *c.RBAC.DefaultRole; d != "" && !strings.HasPrefix(d, "role:") {
		add("rbac.defaultRole must be empty or start with role:")
	}
	if strings.HasPrefix(c.Session.CookieName, "__Host-") && !*c.Session.SecureCookie {
		add("session.cookieName with __Host- prefix requires secureCookie")
	}
	if c.Session.AbsoluteTimeout < c.Session.IdleTimeout {
		add("session.absoluteTimeout must be >= session.idleTimeout")
	}
	if c.Query.DefaultLimit > c.Query.MaxLimit || c.Query.DefaultMaxTime > c.Query.MaxMaxTime {
		add("query defaults must not exceed maximums")
	}

	if len(c.Profiles) == 0 {
		add("at least one MongoDB connection profile is required")
	}
	seen := map[string]bool{}
	for i := range c.Profiles {
		p := &c.Profiles[i]
		if !profileNameRe.MatchString(p.Name) {
			add("profiles[%d].name %q must be a DNS-label style name", i, p.Name)
		}
		if seen[p.Name] {
			add("profiles[%d].name %q is duplicated", i, p.Name)
		}
		seen[p.Name] = true
		if err := ValidateProfileURI(p.URI); err != nil {
			add("profiles[%s].uri: %v", p.Name, err)
		}
		if !authSourceRe.MatchString(p.DefaultAuthSource) {
			add("profiles[%s].defaultAuthSource is invalid", p.Name)
		}
		for _, m := range p.AuthMechanisms {
			if !slices.Contains(SupportedMechanisms, m) {
				add("profiles[%s].authMechanisms: %q is not supported", p.Name, m)
			}
		}
		switch strings.ToLower(p.ReadPreference) {
		case "primary", "primarypreferred", "secondary", "secondarypreferred", "nearest":
		default:
			add("profiles[%s].readPreference %q is invalid", p.Name, p.ReadPreference)
		}
		if err := p.TLS.validate(); err != nil {
			add("profiles[%s].tls: %v", p.Name, err)
		}
		if p.TLS.Mode == TLSDisabled && c.IsProduction() && !p.PlaintextApproved {
			add("profiles[%s]: tls.mode=disabled in production requires plaintextApproved=true (security exception)", p.Name)
		}
	}
	return errors.Join(errs...)
}

func (t TLSConfig) validate() error {
	switch t.Mode {
	case TLSEnabled:
	case TLSDisabled:
		if t.CAFile != "" || t.ClientCertFile != "" || t.ClientKeyFile != "" {
			return errors.New("certificate files are set but mode is disabled; refusing ambiguous configuration")
		}
		return nil
	case "":
		return errors.New("mode is required and must be \"enabled\" or \"disabled\"")
	default:
		return fmt.Errorf("mode %q must be \"enabled\" or \"disabled\"", t.Mode)
	}
	if t.VerifyServerCertificate != nil && !*t.VerifyServerCertificate {
		return errors.New("verifyServerCertificate=false is not supported; provide a trusted CA instead")
	}
	if (t.ClientCertFile == "") != (t.ClientKeyFile == "") {
		return errors.New("clientCertFile and clientKeyFile must be set together")
	}
	if t.MinVersion != "1.2" && t.MinVersion != "1.3" {
		return fmt.Errorf("minVersion %q must be 1.2 or 1.3", t.MinVersion)
	}
	return nil
}

// ValidateProfileURI ensures a profile URI is a credential-free MongoDB URI
// without security-relevant options.
func ValidateProfileURI(uri string) error {
	var rest string
	switch {
	case strings.HasPrefix(uri, "mongodb://"):
		rest = strings.TrimPrefix(uri, "mongodb://")
	case strings.HasPrefix(uri, "mongodb+srv://"):
		rest = strings.TrimPrefix(uri, "mongodb+srv://")
	default:
		return errors.New("must start with mongodb:// or mongodb+srv://")
	}
	authority, query, _ := strings.Cut(rest, "?")
	hosts, _, _ := strings.Cut(authority, "/")
	if hosts == "" {
		return errors.New("no hosts")
	}
	if strings.Contains(hosts, "@") {
		return errors.New("must not contain credentials")
	}
	vals, err := url.ParseQuery(query)
	if err != nil {
		return fmt.Errorf("invalid options: %w", err)
	}
	for k := range vals {
		if slices.Contains(forbiddenURIOptions, strings.ToLower(k)) {
			return fmt.Errorf("option %q is not permitted in profile URIs", k)
		}
	}
	return nil
}

// ValidAuthSource reports whether s is an acceptable authentication database.
func ValidAuthSource(s string) bool { return authSourceRe.MatchString(s) }

// Profile returns the named profile.
func (c *Config) Profile(name string) (*Profile, bool) {
	for i := range c.Profiles {
		if c.Profiles[i].Name == name {
			return &c.Profiles[i], true
		}
	}
	return nil, false
}

// LegacyRBACPolicy converts the deprecated identity.developerGroups and
// identity.sreGroups settings into RBAC policy lines.
func (c *Config) LegacyRBACPolicy() string {
	var b strings.Builder
	for _, g := range c.Identity.DeveloperGroups {
		fmt.Fprintf(&b, "g, %s, role:readonly\n", g)
	}
	for _, g := range c.Identity.SREGroups {
		fmt.Fprintf(&b, "g, %s, role:admin\n", g)
	}
	return b.String()
}

func validHeader(h string) bool { return headerNameRe.MatchString(h) }

func setDefault(p *string, v string) {
	if *p == "" {
		*p = v
	}
}

func setDuration(p *time.Duration, v time.Duration) {
	if *p == 0 {
		*p = v
	}
}

func setInt(p *int, v int) {
	if *p == 0 {
		*p = v
	}
}

func setInt64(p *int64, v int64) {
	if *p == 0 {
		*p = v
	}
}
