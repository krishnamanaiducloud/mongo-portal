// Package audit records security-relevant events. Every event is written as
// a structured JSON log line (for cluster log forwarding), kept in a bounded
// in-memory buffer, and optionally persisted to a durable store. Events never
// contain passwords, tokens or document contents.
//
// Each replica chains its events: Hash is SHA-256 over the previous hash and
// the event, so a stored trail can be checked for removed or altered events
// (tamper evidence, not tamper proofing: use write-once storage for that).
package audit

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel/trace"
)

// Event is one audit record.
type Event struct {
	ID        string    `json:"id" bson:"_id"`
	Time      time.Time `json:"time" bson:"time"`
	RequestID string    `json:"requestId,omitempty" bson:"requestId,omitempty"`
	TraceID   string    `json:"traceId,omitempty" bson:"traceId,omitempty"`
	SSOUser   string    `json:"ssoUser" bson:"ssoUser"`
	// Identity is how the user signed in (openshift, oidc, header, dev, mongodb).
	Identity string `json:"identity,omitempty" bson:"identity,omitempty"`
	// Provider is the OIDC provider of an oidc identity.
	Provider string `json:"provider,omitempty" bson:"provider,omitempty"`
	// Method is the authentication method of a login (mongodb, mongodb-oidc).
	Method string `json:"method,omitempty" bson:"method,omitempty"`
	// Owner is the principal key used to show users their own events.
	Owner      string `json:"-" bson:"owner"`
	PortalRole string `json:"portalRole,omitempty" bson:"portalRole,omitempty"`
	MongoUser  string `json:"mongoUser,omitempty" bson:"mongoUser,omitempty"`
	Profile    string `json:"profile,omitempty" bson:"profile,omitempty"`
	Action     string `json:"action" bson:"action"`
	Database   string `json:"database,omitempty" bson:"database,omitempty"`
	Collection string `json:"collection,omitempty" bson:"collection,omitempty"`
	Target     string `json:"target,omitempty" bson:"target,omitempty"`
	Outcome    string `json:"outcome" bson:"outcome"`
	Reason     string `json:"reason,omitempty" bson:"reason,omitempty"`
	ErrorClass string `json:"errorClass,omitempty" bson:"errorClass,omitempty"`
	DurationMS int64  `json:"durationMs,omitempty" bson:"durationMs,omitempty"`
	// Count is the number of documents affected, imported or exported.
	Count     int64  `json:"count,omitempty" bson:"count,omitempty"`
	Client    string `json:"client,omitempty" bson:"client,omitempty"`
	UserAgent string `json:"userAgent,omitempty" bson:"userAgent,omitempty"`
	Session   string `json:"session,omitempty" bson:"session,omitempty"`
	Pod       string `json:"pod,omitempty" bson:"pod,omitempty"`
	Seq       int64  `json:"seq,omitempty" bson:"seq,omitempty"`
	PrevHash  string `json:"prevHash,omitempty" bson:"prevHash,omitempty"`
	Hash      string `json:"hash,omitempty" bson:"hash,omitempty"`
}

// Outcomes.
const (
	Success = "success"
	Denied  = "denied"
	Failure = "failure"
)

// Sink persists events. The log hands it batches from a bounded background
// queue, so a slow sink never blocks requests.
type Sink interface {
	Write(ctx context.Context, events []Event) error
	Query(ctx context.Context, f Filter) ([]Event, error)
}

// Filter selects events. Zero values do not filter.
type Filter struct {
	Owner      string
	User       string // substring of the SSO or MongoDB user
	Action     string
	Outcome    string
	Profile    string
	Database   string
	Collection string
	Text       string // substring of action, target or reason
	From, To   time.Time
	// Before pages backwards: events older than (Before, BeforeID).
	Before   time.Time
	BeforeID string
	Limit    int
}

// Match reports whether e passes the filter.
func (f Filter) Match(e Event) bool {
	switch {
	case f.Owner != "" && e.Owner != f.Owner,
		f.Action != "" && e.Action != f.Action,
		f.Outcome != "" && e.Outcome != f.Outcome,
		f.Profile != "" && e.Profile != f.Profile,
		f.Database != "" && e.Database != f.Database,
		f.Collection != "" && e.Collection != f.Collection,
		!f.From.IsZero() && e.Time.Before(f.From),
		!f.To.IsZero() && !e.Time.Before(f.To):
		return false
	}
	if !f.Before.IsZero() && (e.Time.After(f.Before) || (e.Time.Equal(f.Before) && e.ID >= f.BeforeID)) {
		return false
	}
	if f.User != "" && !containsFold(e.SSOUser, f.User) && !containsFold(e.MongoUser, f.User) {
		return false
	}
	if f.Text != "" && !containsFold(e.Action, f.Text) && !containsFold(e.Target, f.Text) && !containsFold(e.Reason, f.Text) {
		return false
	}
	return true
}

func containsFold(s, sub string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(sub))
}

// Options configures a Log.
type Options struct {
	Capacity int
	Pod      string
	Sink     Sink
	// OnDrop is called when events could not be persisted (metrics).
	OnDrop func(n int)
}

// Log is the audit sink of the portal.
type Log struct {
	logger *slog.Logger
	opts   Options

	mu   sync.Mutex
	buf  []Event
	next int
	full bool
	prev string
	seq  int64

	queue   chan Event
	done    chan struct{}
	dropped atomic.Int64
	written atomic.Int64
	lastErr atomic.Value // string
}

// New creates an audit log with the given in-memory capacity and no sink.
func New(logger *slog.Logger, capacity int) *Log {
	return NewWithOptions(logger, Options{Capacity: capacity})
}

// NewWithOptions creates an audit log. With a sink, events are written by a
// background worker; call Close to flush.
func NewWithOptions(logger *slog.Logger, o Options) *Log {
	if o.Capacity <= 0 {
		o.Capacity = 1000
	}
	l := &Log{logger: logger, opts: o, buf: make([]Event, o.Capacity)}
	if o.Sink != nil {
		l.queue = make(chan Event, 10000)
		l.done = make(chan struct{})
		go l.worker()
	}
	return l
}

// Persistent reports whether events go to a durable sink.
func (l *Log) Persistent() bool { return l.opts.Sink != nil }

// SinkStatus reports the durable sink's state for the status page.
func (l *Log) SinkStatus() map[string]any {
	st := map[string]any{"persistent": l.opts.Sink != nil, "written": l.written.Load(), "dropped": l.dropped.Load()}
	if v, _ := l.lastErr.Load().(string); v != "" {
		st["lastError"] = v
	}
	return st
}

// Record stores and logs an event.
func (l *Log) Record(ctx context.Context, e Event) {
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	e.Time = e.Time.UTC().Truncate(time.Millisecond)
	if e.ID == "" {
		e.ID = newID(e.Time)
	}
	if e.TraceID == "" {
		if sc := trace.SpanContextFromContext(ctx); sc.HasTraceID() {
			e.TraceID = sc.TraceID().String()
		}
	}
	if e.Pod == "" {
		e.Pod = l.opts.Pod
	}

	l.mu.Lock()
	l.seq++
	e.Seq, e.PrevHash = l.seq, l.prev
	e.Hash = ChainHash(e)
	l.prev = e.Hash
	l.buf[l.next] = e
	l.next = (l.next + 1) % len(l.buf)
	if l.next == 0 {
		l.full = true
	}
	l.mu.Unlock()

	l.logger.LogAttrs(ctx, slog.LevelInfo, "audit",
		slog.Bool("audit", true),
		slog.String("event_id", e.ID),
		slog.String("request_id", e.RequestID),
		slog.String("sso_user", e.SSOUser),
		slog.String("identity", e.Identity),
		slog.String("provider", e.Provider),
		slog.String("method", e.Method),
		slog.String("portal_role", e.PortalRole),
		slog.String("mongo_user", e.MongoUser),
		slog.String("profile", e.Profile),
		slog.String("action", e.Action),
		slog.String("database", e.Database),
		slog.String("collection", e.Collection),
		slog.String("target", e.Target),
		slog.String("outcome", e.Outcome),
		slog.String("reason", e.Reason),
		slog.String("error_class", e.ErrorClass),
		slog.Int64("duration_ms", e.DurationMS),
		slog.Int64("count", e.Count),
		slog.String("client", e.Client),
		slog.String("session", e.Session),
		slog.String("pod", e.Pod),
		slog.Int64("seq", e.Seq),
		slog.String("hash", e.Hash),
	)
	if l.queue != nil {
		select {
		case l.queue <- e:
		default:
			l.drop(1)
		}
	}
}

func (l *Log) drop(n int) {
	l.dropped.Add(int64(n))
	if l.opts.OnDrop != nil {
		l.opts.OnDrop(n)
	}
}

// ChainHash is the tamper-evidence hash of an event: SHA-256 of the previous
// hash, the event's JSON with Hash cleared, and the owner key (which is not
// part of the JSON form).
func ChainHash(e Event) string {
	e.Hash = ""
	b, _ := json.Marshal(e)
	h := sha256.New()
	h.Write([]byte(e.PrevHash))
	h.Write([]byte{0})
	h.Write(b)
	h.Write([]byte{0})
	h.Write([]byte(e.Owner))
	return hex.EncodeToString(h.Sum(nil))
}

// VerifyChain checks consecutive events of one replica (in sequence order)
// and returns the index of the first broken link, or -1.
func VerifyChain(events []Event) int {
	for i, e := range events {
		if ChainHash(e) != e.Hash {
			return i
		}
		if i > 0 && (e.PrevHash != events[i-1].Hash || e.Seq != events[i-1].Seq+1) {
			return i
		}
	}
	return -1
}

func (l *Log) worker() {
	defer close(l.done)
	batch := make([]Event, 0, 200)
	write := func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		return l.opts.Sink.Write(ctx, batch)
	}
	flush := func() {
		if len(batch) == 0 {
			return
		}
		err := write()
		if err != nil {
			// One retry after a pause; the log stream keeps every record.
			time.Sleep(2 * time.Second)
			err = write()
		}
		if err != nil {
			l.lastErr.Store(err.Error())
			l.drop(len(batch))
			l.logger.Warn("audit events could not be persisted; they remain in the log stream", "count", len(batch), "error", err.Error())
		} else {
			l.lastErr.Store("")
			l.written.Add(int64(len(batch)))
		}
		batch = batch[:0]
	}
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case e, ok := <-l.queue:
			if !ok {
				flush()
				return
			}
			batch = append(batch, e)
			if len(batch) == cap(batch) {
				flush()
			}
		case <-tick.C:
			flush()
		}
	}
}

// Close flushes the sink queue. Record must not be called afterwards.
func (l *Log) Close() {
	if l.queue == nil {
		return
	}
	close(l.queue)
	<-l.done
}

// Recent returns up to limit events, newest first, optionally filtered to one
// principal (owner key).
func (l *Log) Recent(owner string, limit int) []Event {
	return l.Local(Filter{Owner: owner, Limit: limit})
}

// Local returns matching events from this replica's buffer, newest first.
func (l *Log) Local(f Filter) []Event {
	if f.Limit <= 0 {
		f.Limit = 200
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	n := l.next
	if l.full {
		n = len(l.buf)
	}
	out := make([]Event, 0, min(f.Limit, n))
	for i := 0; i < n && len(out) < f.Limit; i++ {
		e := l.buf[(l.next-1-i+len(l.buf))%len(l.buf)]
		if f.Match(e) {
			out = append(out, e)
		}
	}
	return slices.Clip(out)
}

// Query returns matching events, newest first, from the durable sink when
// there is one (durable=true), otherwise from this replica's buffer.
func (l *Log) Query(ctx context.Context, f Filter) (events []Event, durable bool, err error) {
	if l.opts.Sink == nil {
		return l.Local(f), false, nil
	}
	ev, err := l.opts.Sink.Query(ctx, f)
	return ev, true, err
}

// newID returns a time-sortable unique id.
func newID(t time.Time) string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return t.UTC().Format("20060102T150405.000Z") + "-" + hex.EncodeToString(b)
}
