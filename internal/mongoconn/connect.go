// Package mongoconn creates per-user authenticated MongoDB clients from
// administrator-controlled connection profiles.
package mongoconn

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/event"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/mongo/readpref"

	"github.com/krishnamanaiducloud/mongo-portal/internal/config"
)

// Credentials are supplied by the user at login. The password is passed to
// the driver, which keeps it in process memory only for re-authenticating
// new pool connections (for example after a replica-set failover).
type Credentials struct {
	Username   string
	Password   string
	AuthSource string
	Mechanism  string
	// OIDC carries the user's own tokens for MONGODB-OIDC (no password).
	OIDC *OIDCTokens
}

// ConnectResult describes a successfully authenticated client.
type ConnectResult struct {
	Client     *mongo.Client
	Status     *ConnectionStatus
	Mechanism  string
	TLSEnabled bool
	// User and AuthSource are the principal MongoDB authenticated (for
	// MONGODB-OIDC the server derives them from the token).
	User       string
	AuthSource string
}

// PoolHooks receives connection pool lifecycle callbacks (for metrics).
type PoolHooks struct {
	Created func()
	Closed  func()
	// Stats, if set, tracks open and in-use connections of this client.
	Stats *PoolStats
}

// PoolStats counts the connections of one MongoDB client (one session).
type PoolStats struct {
	open, inUse atomic.Int64
}

// PoolSnapshot is a point-in-time view of a client's connection pool.
type PoolSnapshot struct {
	Open  int64 `json:"open"`
	InUse int64 `json:"inUse"`
	Idle  int64 `json:"idle"`
}

// Snapshot returns the current counts.
func (p *PoolStats) Snapshot() PoolSnapshot {
	if p == nil {
		return PoolSnapshot{}
	}
	open, inUse := max(p.open.Load(), 0), max(p.inUse.Load(), 0)
	return PoolSnapshot{Open: open, InUse: min(inUse, open), Idle: max(open-inUse, 0)}
}

// Validate checks user supplied credential fields.
func (c Credentials) Validate(p *config.Profile) error {
	if c.Mechanism == config.MechanismOIDC {
		switch {
		case p.OIDC == nil || !slices.Contains(p.AuthMechanisms, config.MechanismOIDC):
			return errors.New("this connection profile does not offer MONGODB-OIDC")
		case c.OIDC == nil:
			return errors.New("MONGODB-OIDC needs a sign-in at the identity provider")
		case c.Password != "":
			return errors.New("MONGODB-OIDC does not use a password")
		}
		return nil
	}
	if c.OIDC != nil {
		return errors.New("OIDC tokens are only used with MONGODB-OIDC")
	}
	if c.Username == "" || len(c.Username) > 256 || strings.ContainsAny(c.Username, "\x00\r\n") {
		return errors.New("username is required and must not contain control characters")
	}
	if c.Password == "" || len(c.Password) > 1024 {
		return errors.New("password is required")
	}
	if !config.ValidAuthSource(c.AuthSource) {
		return errors.New("authentication database is invalid")
	}
	if c.Mechanism != "" && !slices.Contains(p.AuthMechanisms, c.Mechanism) {
		return fmt.Errorf("authentication mechanism %q is not allowed for this profile", c.Mechanism)
	}
	return nil
}

// Connect builds a client for the profile, authenticates with the user's
// credentials and verifies the authenticated principal. On any failure the
// client is disconnected and an error is returned; there is no fallback
// between TLS and plaintext.
func Connect(ctx context.Context, p *config.Profile, cred Credentials, hooks PoolHooks) (*ConnectResult, error) {
	if err := cred.Validate(p); err != nil {
		return nil, &Error{Kind: KindInvalidInput, Msg: err.Error()}
	}
	opts, err := ClientOptions(p, hooks)
	if err != nil {
		return nil, &Error{Kind: KindConfig, Msg: "connection profile is misconfigured", Err: err}
	}
	mech := cred.Mechanism
	if mech == "" && len(p.AuthMechanisms) == 1 {
		mech = p.AuthMechanisms[0]
	}
	if mech == config.MechanismOIDC {
		// The human callback hands MongoDB the user's own access token. The
		// token is only sent to the profile's hosts (ALLOWED_HOSTS).
		opts.SetAuth(options.Credential{
			AuthMechanism:           config.MechanismOIDC,
			OIDCHumanCallback:       cred.OIDC.Callback,
			AuthMechanismProperties: map[string]string{"ALLOWED_HOSTS": strings.Join(p.OIDC.AllowedHosts, ",")},
		})
	} else {
		opts.SetAuth(options.Credential{
			AuthMechanism: mech,
			AuthSource:    cred.AuthSource,
			Username:      cred.Username,
			Password:      cred.Password,
			PasswordSet:   true,
		})
	}

	client, err := mongo.Connect(opts)
	if err != nil {
		return nil, Classify(err)
	}
	ok := false
	defer func() {
		if !ok {
			dctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = client.Disconnect(dctx)
		}
	}()

	// Ping checks out a pooled connection, which performs the handshake and
	// SASL authentication. A successful ping means MongoDB verified the
	// credentials.
	if err := client.Ping(ctx, readpref.PrimaryPreferred()); err != nil {
		return nil, Classify(err)
	}
	status, err := GetConnectionStatus(ctx, client)
	if err != nil {
		return nil, Classify(err)
	}
	user, source := cred.Username, cred.AuthSource
	if mech == config.MechanismOIDC {
		// OIDC users live in $external under the server's authNamePrefix.
		for _, u := range status.AuthInfo.AuthenticatedUsers {
			if u.DB == "$external" {
				user, source = u.User, u.DB
				break
			}
		}
		if user == "" {
			return nil, &Error{Kind: KindAuthFailed, Msg: "MongoDB did not confirm an OIDC user"}
		}
	}
	if !status.HasUser(user, source) {
		return nil, &Error{Kind: KindAuthFailed, Msg: "MongoDB did not confirm the authenticated user"}
	}
	ok = true
	if mech == "" {
		mech = "SCRAM (negotiated)"
	}
	return &ConnectResult{Client: client, Status: status, Mechanism: mech, TLSEnabled: p.TLS.Mode == config.TLSEnabled, User: user, AuthSource: source}, nil
}

// ClientOptions builds driver options for a profile without credentials.
func ClientOptions(p *config.Profile, hooks PoolHooks) (*options.ClientOptions, error) {
	if err := config.ValidateProfileURI(p.URI); err != nil {
		return nil, err
	}
	opts := options.Client().ApplyURI(p.URI)
	opts.SetAppName("mongo-portal")
	if p.ReplicaSet != "" {
		opts.SetReplicaSet(p.ReplicaSet)
	}
	rp, err := readPref(p.ReadPreference)
	if err != nil {
		return nil, err
	}
	opts.SetReadPreference(rp)
	opts.SetConnectTimeout(p.ConnectTimeout)
	opts.SetServerSelectionTimeout(p.ServerSelectionTimeout)
	// Client-side operation timeout enables CSOT: per-request context
	// deadlines are sent to the server as maxTimeMS.
	opts.SetTimeout(p.OperationTimeout)
	opts.SetMaxPoolSize(p.MaxPoolSize)
	opts.SetMinPoolSize(0)
	opts.SetMaxConnIdleTime(p.MaxConnIdleTime)
	opts.SetRetryReads(true)
	opts.SetRetryWrites(true)

	switch p.TLS.Mode {
	case config.TLSEnabled:
		tc, err := BuildTLSConfig(p.TLS)
		if err != nil {
			return nil, err
		}
		opts.SetTLSConfig(tc)
	case config.TLSDisabled:
		// Explicit plaintext. Also overrides the implicit TLS default of
		// mongodb+srv URIs so the configured mode is always what is used.
		opts.TLSConfig = nil
	default:
		return nil, fmt.Errorf("tls.mode %q is invalid", p.TLS.Mode)
	}

	if hooks.Created != nil || hooks.Closed != nil || hooks.Stats != nil {
		st := hooks.Stats
		opts.SetPoolMonitor(&event.PoolMonitor{Event: func(e *event.PoolEvent) {
			switch e.Type {
			case event.ConnectionCreated:
				if hooks.Created != nil {
					hooks.Created()
				}
				if st != nil {
					st.open.Add(1)
				}
			case event.ConnectionClosed:
				if hooks.Closed != nil {
					hooks.Closed()
				}
				if st != nil {
					st.open.Add(-1)
				}
			case event.ConnectionCheckedOut:
				if st != nil {
					st.inUse.Add(1)
				}
			case event.ConnectionCheckedIn:
				if st != nil {
					st.inUse.Add(-1)
				}
			}
		}})
	}
	if err := opts.Validate(); err != nil {
		return nil, err
	}
	return opts, nil
}

func readPref(mode string) (*readpref.ReadPref, error) {
	m, err := readpref.ModeFromString(mode)
	if err != nil {
		return nil, err
	}
	return readpref.New(m)
}

// BuildTLSConfig creates a verifying TLS client configuration. Certificate
// files are re-read on every login, and client certificates are reloaded
// when they change on disk, so rotated Secrets are picked up without a
// restart.
func BuildTLSConfig(t config.TLSConfig) (*tls.Config, error) {
	if t.VerifyServerCertificate != nil && !*t.VerifyServerCertificate {
		return nil, errors.New("disabling server certificate verification is not supported")
	}
	tc := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: t.ServerName}
	if t.MinVersion == "1.3" {
		tc.MinVersion = tls.VersionTLS13
	}
	if t.CAFile != "" {
		var pool *x509.CertPool
		if t.UseSystemRoots {
			sp, err := x509.SystemCertPool()
			if err == nil && sp != nil {
				pool = sp
			}
		}
		if pool == nil {
			pool = x509.NewCertPool()
		}
		pem, err := os.ReadFile(t.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read CA file: %w", err)
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("CA file contains no PEM certificates")
		}
		tc.RootCAs = pool
	}
	if t.ClientCertFile != "" {
		kp := &keyPairLoader{certFile: t.ClientCertFile, keyFile: t.ClientKeyFile}
		if _, err := kp.get(); err != nil {
			return nil, err
		}
		tc.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return kp.get() }
	}
	return tc, nil
}

type keyPairLoader struct {
	certFile, keyFile string
	mu                sync.Mutex
	cert              *tls.Certificate
	certMod, keyMod   time.Time
}

func (k *keyPairLoader) get() (*tls.Certificate, error) {
	cs, err := os.Stat(k.certFile)
	if err != nil {
		return nil, fmt.Errorf("client certificate: %w", err)
	}
	ks, err := os.Stat(k.keyFile)
	if err != nil {
		return nil, fmt.Errorf("client key: %w", err)
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.cert != nil && cs.ModTime().Equal(k.certMod) && ks.ModTime().Equal(k.keyMod) {
		return k.cert, nil
	}
	c, err := tls.LoadX509KeyPair(k.certFile, k.keyFile)
	if err != nil {
		if k.cert != nil {
			// Mid-rotation (files partially written): keep the last good pair.
			return k.cert, nil
		}
		return nil, fmt.Errorf("load client key pair: %w", err)
	}
	k.cert, k.certMod, k.keyMod = &c, cs.ModTime(), ks.ModTime()
	return k.cert, nil
}

// RunCommand executes a fixed, portal-defined command (never user supplied).
func RunCommand(ctx context.Context, db *mongo.Database, cmd bson.D, into any) error {
	return db.RunCommand(ctx, cmd).Decode(into)
}
