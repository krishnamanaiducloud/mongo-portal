// Package store keeps the portal's shared state in MongoDB: the durable
// audit trail and the session registry. It connects with a dedicated
// account (readWrite on the store database is enough) that is never used for
// user operations, and it is optional: when it is unreachable the portal
// keeps working with per-replica state and reports the store as unavailable.
package store

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"os"
	"strings"
	"sync"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/mongo/readpref"

	"github.com/krishnamanaiducloud/mongo-portal/internal/config"
	"github.com/krishnamanaiducloud/mongo-portal/internal/mongoconn"
)

// ErrUnavailable means the store is not connected (yet).
var ErrUnavailable = errors.New("the shared store is not available")

// Status describes the store connection.
type Status struct {
	State     string    `json:"state"` // connected, unavailable, disabled
	Reason    string    `json:"reason,omitempty"`
	Database  string    `json:"database,omitempty"`
	CheckedAt time.Time `json:"checkedAt,omitzero"`
}

// Store is the shared state connection.
type Store struct {
	cfg     config.StoreConfig
	profile *config.Profile
	audit   config.AuditConfig
	log     *slog.Logger

	mu     sync.RWMutex
	client *mongo.Client
	db     *mongo.Database
	status Status
}

// New prepares the store; Run connects.
func New(cfg *config.Config, log *slog.Logger) *Store {
	s := &Store{cfg: cfg.Store, audit: cfg.Audit, log: log, status: Status{State: "disabled"}}
	if !cfg.Store.Enabled {
		return s
	}
	s.profile, _ = cfg.Profile(cfg.Store.Profile)
	s.status = Status{State: "unavailable", Reason: "not connected yet", Database: cfg.Store.Database}
	return s
}

// Enabled reports whether a store is configured.
func (s *Store) Enabled() bool { return s.cfg.Enabled }

// Status returns the connection state.
func (s *Store) Status() Status {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.status
}

func (s *Store) database() (*mongo.Database, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.db == nil {
		return nil, ErrUnavailable
	}
	return s.db, nil
}

// Connect makes one connection attempt and prepares the collections.
func (s *Store) Connect(ctx context.Context) error {
	if !s.cfg.Enabled {
		return nil
	}
	err := s.connect(ctx)
	st := Status{State: "connected", Database: s.cfg.Database, CheckedAt: time.Now().UTC()}
	if err != nil {
		st = Status{State: "unavailable", Reason: err.Error(), Database: s.cfg.Database, CheckedAt: time.Now().UTC()}
	}
	s.mu.Lock()
	prev := s.status.State
	s.status = st
	s.mu.Unlock()
	if prev != st.State {
		if err != nil {
			s.log.Warn("shared store unavailable; audit stays in the log stream and sessions per replica", "reason", st.Reason)
		} else {
			s.log.Info("shared store connected", "database", s.cfg.Database)
		}
	}
	return err
}

// Run connects, retrying until it succeeds or ctx ends.
func (s *Store) Run(ctx context.Context) {
	if !s.cfg.Enabled {
		return
	}
	wait := 5 * time.Second
	for {
		if _, err := s.database(); err == nil {
			return
		}
		if s.Connect(ctx) == nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		wait = min(wait*2, 2*time.Minute)
	}
}

// dial connects and authenticates the store account (one ping).
func (s *Store) dial(ctx context.Context) (*mongo.Client, error) {
	if s.profile == nil {
		return nil, errors.New("store.profile is not a configured profile")
	}
	opts, err := mongoconn.ClientOptions(s.profile, mongoconn.PoolHooks{})
	if err != nil {
		return nil, fmt.Errorf("profile: %w", err)
	}
	opts.SetAppName("mongo-portal-store")
	cred := options.Credential{AuthMechanism: s.cfg.Mechanism}
	if s.cfg.Mechanism == config.MechanismX509 {
		cred.AuthSource = "$external"
	} else {
		user, err1 := readSecret(s.cfg.UsernameFile)
		pass, err2 := readSecret(s.cfg.PasswordFile)
		if err := errors.Join(err1, err2); err != nil {
			return nil, err
		}
		cred.Username, cred.Password, cred.PasswordSet, cred.AuthSource = user, pass, true, s.cfg.AuthSource
	}
	opts.SetAuth(cred)
	client, err := mongo.Connect(opts)
	if err != nil {
		return nil, err
	}
	if err := client.Ping(ctx, readpref.Primary()); err != nil {
		_ = client.Disconnect(context.Background())
		return nil, fmt.Errorf("connect: %s", mongoconn.Classify(err).Msg)
	}
	return client, nil
}

// storeActions are the privileges the store account needs on its database.
var storeActions = []string{"find", "insert", "update", "remove", "createIndex", "listIndexes", "dropIndex"}

// Probe checks, without writing, that the store account can sign in and
// holds the privileges the store needs on its database.
func Probe(ctx context.Context, cfg *config.Config) (string, error) {
	s := New(cfg, slog.New(slog.DiscardHandler))
	client, err := s.dial(ctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = client.Disconnect(context.Background()) }()
	var st struct {
		AuthInfo struct {
			Privileges []struct {
				Resource struct {
					DB         *string `bson:"db"`
					Collection *string `bson:"collection"`
					Cluster    bool    `bson:"cluster"`
				} `bson:"resource"`
				Actions []string `bson:"actions"`
			} `bson:"authenticatedUserPrivileges"`
		} `bson:"authInfo"`
	}
	cmd := bson.D{{Key: "connectionStatus", Value: 1}, {Key: "showPrivileges", Value: true}}
	if err := client.Database("admin").RunCommand(ctx, cmd).Decode(&st); err != nil {
		return "", fmt.Errorf("connectionStatus: %s", mongoconn.Classify(err).Msg)
	}
	have := map[string]bool{}
	for _, p := range st.AuthInfo.Privileges {
		db, coll := p.Resource.DB, p.Resource.Collection
		if db == nil || coll == nil || (*db != "" && *db != cfg.Store.Database) || *coll != "" {
			continue
		}
		for _, a := range p.Actions {
			have[a] = true
		}
	}
	var missing []string
	for _, a := range storeActions {
		if !have[a] {
			missing = append(missing, a)
		}
	}
	if len(missing) > 0 {
		return "", fmt.Errorf("signed in, but the account lacks %s on database %q (grant readWrite on it)", strings.Join(missing, ", "), cfg.Store.Database)
	}
	detail := "signed in; readWrite privileges on " + cfg.Store.Database + " (nothing written)"
	if !have["collMod"] {
		// readWrite lacks collMod; it is only used to change an existing
		// audit retention, which the database administrator can also do.
		detail += "; without collMod, a later change of audit.retention must be applied by a database administrator"
	}
	return detail, nil
}

func (s *Store) connect(ctx context.Context) error {
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	client, err := s.dial(cctx)
	if err != nil {
		return err
	}
	db := client.Database(s.cfg.Database)
	if err := s.prepare(cctx, db); err != nil {
		_ = client.Disconnect(context.Background())
		return err
	}
	s.mu.Lock()
	s.client, s.db = client, db
	s.mu.Unlock()
	return nil
}

func (s *Store) prepare(ctx context.Context, db *mongo.Database) error {
	ac := db.Collection(s.audit.Collection)
	idx := []mongo.IndexModel{
		{Keys: bson.D{{Key: "time", Value: -1}, {Key: "_id", Value: -1}}},
		{Keys: bson.D{{Key: "owner", Value: 1}, {Key: "time", Value: -1}}},
		{Keys: bson.D{{Key: "action", Value: 1}, {Key: "time", Value: -1}}},
		{Keys: bson.D{{Key: "pod", Value: 1}, {Key: "seq", Value: 1}}},
	}
	if _, err := ac.Indexes().CreateMany(ctx, idx); err != nil {
		return fmt.Errorf("audit indexes: %s", mongoconn.Classify(err).Msg)
	}
	if err := s.retention(ctx, db, ac); err != nil {
		return err
	}
	sc := db.Collection(sessionsColl)
	_, err := sc.Indexes().CreateMany(ctx, []mongo.IndexModel{
		{Keys: bson.D{{Key: "owner", Value: 1}}},
		{Keys: bson.D{{Key: "pod", Value: 1}, {Key: "revoked", Value: 1}}},
		// Registry entries disappear after the session's absolute expiry.
		{Keys: bson.D{{Key: "expiresAt", Value: 1}}, Options: options.Index().SetExpireAfterSeconds(0).SetName("expiresAt_ttl")},
	})
	if err != nil {
		return fmt.Errorf("session registry indexes: %s", mongoconn.Classify(err).Msg)
	}
	// Cache invalidations only need to outlive the replicas' sync interval.
	_, err = db.Collection(cachesColl).Indexes().CreateOne(ctx, mongo.IndexModel{Keys: bson.D{{Key: "at", Value: 1}},
		Options: options.Index().SetExpireAfterSeconds(7 * 24 * 3600).SetName("at_ttl")})
	if err != nil {
		return fmt.Errorf("cache invalidation index: %s", mongoconn.Classify(err).Msg)
	}
	return nil
}

// retention keeps the TTL index of the audit collection in line with
// audit.retention (create, change with collMod, or drop).
func (s *Store) retention(ctx context.Context, db *mongo.Database, ac *mongo.Collection) error {
	const name = "time_ttl"
	// TTL indexes take int32 seconds; longer retention is capped (68 years).
	secs := int32(min(s.audit.Retention/time.Second, math.MaxInt32)) // #nosec G115 -- bounded by MaxInt32 above
	cur, err := ac.Indexes().ListSpecifications(ctx)
	if err != nil {
		return fmt.Errorf("audit indexes: %s", mongoconn.Classify(err).Msg)
	}
	var existing *mongo.IndexSpecification
	for _, sp := range cur {
		if sp.Name == name {
			existing = &sp
		}
	}
	switch {
	case secs <= 0 && existing != nil:
		return ac.Indexes().DropOne(ctx, name)
	case secs <= 0:
		return nil
	case existing == nil:
		_, err := ac.Indexes().CreateOne(ctx, mongo.IndexModel{Keys: bson.D{{Key: "time", Value: 1}},
			Options: options.Index().SetName(name).SetExpireAfterSeconds(secs)})
		return err
	case existing.ExpireAfterSeconds == nil || *existing.ExpireAfterSeconds != secs:
		err := db.RunCommand(ctx, bson.D{{Key: "collMod", Value: s.audit.Collection},
			{Key: "index", Value: bson.D{{Key: "name", Value: name}, {Key: "expireAfterSeconds", Value: secs}}}}).Err()
		if err != nil && mongoconn.Classify(err).Kind == mongoconn.KindUnauthorized {
			// readWrite has no collMod: keep the store usable with the old
			// retention and tell the operator what to run.
			s.log.Warn("audit retention not changed: the store account lacks collMod; a database administrator can apply it",
				"collection", s.audit.Collection, "expireAfterSeconds", secs)
			return nil
		}
		return err
	}
	return nil
}

// Close disconnects.
func (s *Store) Close(ctx context.Context) {
	s.mu.Lock()
	c := s.client
	s.client, s.db = nil, nil
	s.mu.Unlock()
	if c != nil {
		_ = c.Disconnect(ctx)
	}
}

func readSecret(path string) (string, error) {
	if path == "" {
		return "", errors.New("credential file not configured")
	}
	b, err := os.ReadFile(path) // #nosec G304 -- operator supplied secret mount
	if err != nil {
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	v := strings.TrimSpace(string(b))
	if v == "" {
		return "", fmt.Errorf("%s is empty", path)
	}
	return v, nil
}
