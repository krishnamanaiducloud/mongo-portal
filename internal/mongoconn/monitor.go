package mongoconn

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/mongo/readpref"

	"github.com/krishnamanaiducloud/mongo-portal/internal/config"
)

// Profile health states.
const (
	HealthUnknown       = "unknown"
	HealthOnline        = "online"
	HealthDegraded      = "degraded" // reachable, but no writable primary
	HealthOffline       = "offline"
	HealthMisconfigured = "misconfigured"
	HealthDisabled      = "disabled"
)

// Health is the last known state of a connection profile.
type Health struct {
	State     string    `json:"state"`
	Reason    string    `json:"reason,omitempty"`
	LatencyMS int64     `json:"latencyMs,omitempty"`
	SetName   string    `json:"setName,omitempty"`
	CheckedAt time.Time `json:"checkedAt,omitzero"`
}

// Monitor checks connection profiles in the background with the
// unauthenticated "hello" command, which MongoDB permits before
// authentication. No credentials are used and nothing is retried
// aggressively: an unreachable MongoDB is reported, never raised.
type Monitor struct {
	profiles []config.Profile
	interval time.Duration
	log      *slog.Logger

	mu      sync.RWMutex
	health  map[string]Health
	clients map[string]*mongo.Client
}

// NewMonitor creates a monitor. interval <= 0 disables checks.
func NewMonitor(profiles []config.Profile, interval time.Duration, log *slog.Logger) *Monitor {
	m := &Monitor{profiles: profiles, interval: interval, log: log, health: map[string]Health{}, clients: map[string]*mongo.Client{}}
	state := HealthUnknown
	if interval <= 0 {
		state = HealthDisabled
	}
	for _, p := range profiles {
		m.health[p.Name] = Health{State: state}
	}
	return m
}

// Health returns the state of one profile.
func (m *Monitor) Health(profile string) Health {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.health[profile]
}

// Run checks every profile now and then every interval until ctx ends, and
// closes its clients on exit.
func (m *Monitor) Run(ctx context.Context) {
	if m.interval <= 0 {
		return
	}
	defer m.close()
	for {
		m.CheckNow(ctx)
		select {
		case <-ctx.Done():
			return
		case <-time.After(m.interval):
		}
	}
}

// CheckNow checks every profile immediately (also used to refresh the
// health shown on the login page on request).
func (m *Monitor) CheckNow(ctx context.Context) {
	if m.interval <= 0 {
		return
	}
	var wg sync.WaitGroup
	for i := range m.profiles {
		wg.Add(1)
		go func(p *config.Profile) {
			defer wg.Done()
			m.check(ctx, p)
		}(&m.profiles[i])
	}
	wg.Wait()
}

func (m *Monitor) client(p *config.Profile) (*mongo.Client, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if c, ok := m.clients[p.Name]; ok {
		return c, nil
	}
	opts, err := ClientOptions(p, PoolHooks{})
	if err != nil {
		return nil, err
	}
	opts.SetAppName("mongo-portal-health")
	opts.SetMaxPoolSize(1)
	opts.SetServerSelectionTimeout(min(5*time.Second, p.ServerSelectionTimeout))
	opts.SetRetryReads(false)
	c, err := mongo.Connect(opts)
	if err != nil {
		return nil, err
	}
	m.clients[p.Name] = c
	return c, nil
}

func (m *Monitor) check(ctx context.Context, p *config.Profile) {
	h := Health{CheckedAt: time.Now().UTC()}
	c, err := m.client(p)
	if err != nil {
		// Typically a missing or invalid CA/client certificate file.
		h.State, h.Reason = HealthMisconfigured, "the connection profile cannot be used: "+Classify(err).Msg
		m.set(p.Name, h)
		return
	}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	start := time.Now()
	// hello may be answered by any reachable member (read preference nearest),
	// so a replica set without a primary is reported as degraded, not offline.
	var hello struct {
		SetName           string `bson:"setName"`
		IsWritablePrimary bool   `bson:"isWritablePrimary"`
		Primary           string `bson:"primary"`
	}
	err = c.Database("admin").RunCommand(cctx, bson.D{{Key: "hello", Value: 1}}, options.RunCmd().SetReadPreference(readpref.Nearest())).Decode(&hello)
	h.LatencyMS = time.Since(start).Milliseconds()
	switch {
	case err != nil:
		me := Classify(err)
		h.State, h.Reason, h.LatencyMS = HealthOffline, me.Msg, 0
		if me.Kind == KindTLS {
			h.Reason = "TLS certificate verification failed"
		}
	case hello.IsWritablePrimary || (hello.SetName == "" && hello.Primary == ""):
		h.State, h.SetName = HealthOnline, hello.SetName
	case hello.Primary != "":
		// Answered by a secondary that knows the primary.
		h.State, h.SetName = HealthOnline, hello.SetName
	default:
		h.State, h.SetName, h.Reason = HealthDegraded, hello.SetName, "no writable primary"
	}
	m.set(p.Name, h)
}

func (m *Monitor) set(name string, h Health) {
	m.mu.Lock()
	prev := m.health[name]
	m.health[name] = h
	m.mu.Unlock()
	// Log changes, except the normal first result (unknown -> online).
	if prev.State != h.State && (prev.State != HealthUnknown || h.State != HealthOnline) {
		m.log.Info("connection profile health changed", "profile", name, "from", prev.State, "to", h.State, "reason", h.Reason)
	}
}

func (m *Monitor) close() {
	m.mu.Lock()
	clients := m.clients
	m.clients = map[string]*mongo.Client{}
	m.mu.Unlock()
	for _, c := range clients {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = c.Disconnect(ctx)
		cancel()
	}
}
