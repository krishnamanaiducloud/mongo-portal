// Package audit records security-relevant events. Every event is written as
// a structured JSON log line (for Splunk / cluster log forwarding) and kept
// in a bounded in-memory buffer for the UI. Events never contain passwords,
// tokens or document contents.
package audit

import (
	"context"
	"log/slog"
	"slices"
	"sync"
	"time"
)

// Event is one audit record.
type Event struct {
	Time      time.Time `json:"time"`
	RequestID string    `json:"requestId,omitempty"`
	SSOUser   string    `json:"ssoUser"`
	// Identity is how the user signed in (openshift, header, dev, mongodb).
	Identity string `json:"identity,omitempty"`
	// Owner is the principal key used to show users their own events.
	Owner      string `json:"-"`
	PortalRole string `json:"portalRole,omitempty"`
	MongoUser  string `json:"mongoUser,omitempty"`
	Profile    string `json:"profile,omitempty"`
	Action     string `json:"action"`
	Database   string `json:"database,omitempty"`
	Collection string `json:"collection,omitempty"`
	Target     string `json:"target,omitempty"`
	Outcome    string `json:"outcome"`
	Reason     string `json:"reason,omitempty"`
}

// Outcomes.
const (
	Success = "success"
	Denied  = "denied"
	Failure = "failure"
)

// Log is an audit sink.
type Log struct {
	logger *slog.Logger
	mu     sync.Mutex
	buf    []Event
	next   int
	full   bool
}

// New creates an audit log with the given in-memory capacity.
func New(logger *slog.Logger, capacity int) *Log {
	if capacity <= 0 {
		capacity = 1000
	}
	return &Log{logger: logger, buf: make([]Event, capacity)}
}

// Record stores and logs an event.
func (l *Log) Record(ctx context.Context, e Event) {
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	l.logger.LogAttrs(ctx, slog.LevelInfo, "audit",
		slog.Bool("audit", true),
		slog.String("request_id", e.RequestID),
		slog.String("sso_user", e.SSOUser),
		slog.String("identity", e.Identity),
		slog.String("portal_role", e.PortalRole),
		slog.String("mongo_user", e.MongoUser),
		slog.String("profile", e.Profile),
		slog.String("action", e.Action),
		slog.String("database", e.Database),
		slog.String("collection", e.Collection),
		slog.String("target", e.Target),
		slog.String("outcome", e.Outcome),
		slog.String("reason", e.Reason),
	)
	l.mu.Lock()
	l.buf[l.next] = e
	l.next = (l.next + 1) % len(l.buf)
	if l.next == 0 {
		l.full = true
	}
	l.mu.Unlock()
}

// Recent returns up to limit events, newest first, optionally filtered to one
// principal (owner key).
func (l *Log) Recent(owner string, limit int) []Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := l.next
	if l.full {
		n = len(l.buf)
	}
	out := make([]Event, 0, min(limit, n))
	for i := 0; i < n && len(out) < limit; i++ {
		idx := (l.next - 1 - i + len(l.buf)) % len(l.buf)
		e := l.buf[idx]
		if owner == "" || e.Owner == owner {
			out = append(out, e)
		}
	}
	return slices.Clip(out)
}
