// Package session holds server-side portal sessions. Each session owns one
// MongoDB client authenticated as an individual user. Sessions live only in
// this process's memory: nothing (and in particular no password) is
// persisted, and a restarted or different pod requires MongoDB re-login.
package session

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"slices"
	"sync"
	"time"

	"go.mongodb.org/mongo-driver/v2/mongo"

	"github.com/krishnamanaiducloud/mongo-portal/internal/identity"
	"github.com/krishnamanaiducloud/mongo-portal/internal/mongoconn"
)

var (
	ErrNotFound   = errors.New("session not found")
	ErrExpired    = errors.New("session expired")
	ErrWrongOwner = errors.New("session belongs to a different identity")
	ErrCapacity   = errors.New("session capacity reached")
)

// Session is an authenticated MongoDB session bound to one principal: an SSO
// user, or the MongoDB user itself when signed in without SSO.
type Session struct {
	// Handle is a non-secret identifier used to refer to the session in the
	// API (for example to terminate it). The bearer secret is never exposed
	// after it is set as a cookie.
	Handle    string
	CSRFToken string
	// Owner is identity.Principal.Key() of the principal that signed in.
	Owner string
	// Principal is the principal at sign-in; for MongoDB-only sessions it is
	// the identity used for RBAC on every request.
	Principal  *identity.Principal
	Profile    string
	MongoUser  string
	AuthSource string
	Mechanism  string
	TLS        bool
	Client     *mongo.Client
	Status     *mongoconn.ConnectionStatus
	// Pool counts this session's MongoDB connections (monitoring page).
	Pool      *mongoconn.PoolStats
	CreatedAt time.Time
	ExpiresAt time.Time
	UserAgent string

	mu       sync.Mutex
	lastSeen time.Time
	key      [32]byte

	curMu   sync.Mutex
	cursors map[string]*Cursor
	// Shell limits concurrent shell operations for this session.
	Shell chan struct{}
}

// CursorCloser is the subset of *mongo.Cursor the registry needs.
type CursorCloser interface {
	Close(ctx context.Context) error
}

// Cursor is a server-side cursor kept open between shell requests.
type Cursor struct {
	ID       string
	Cursor   CursorCloser
	Returned int64
	lastUsed time.Time
	mu       sync.Mutex
}

// Lock serialises use of one cursor (getMore calls must not interleave).
func (c *Cursor) Lock()   { c.mu.Lock() }
func (c *Cursor) Unlock() { c.mu.Unlock() }

// ErrTooManyCursors is returned when a session already holds the maximum
// number of open cursors.
var ErrTooManyCursors = errors.New("too many open cursors for this session; exhaust or close existing cursors")

// AddCursor registers an open cursor. Idle cursors older than idle are
// closed first; at most max cursors may be open.
func (s *Session) AddCursor(c CursorCloser, max int, idle time.Duration) (*Cursor, error) {
	s.curMu.Lock()
	defer s.curMu.Unlock()
	s.reapLocked(idle)
	if s.cursors == nil {
		s.cursors = map[string]*Cursor{}
	}
	if len(s.cursors) >= max {
		return nil, ErrTooManyCursors
	}
	cur := &Cursor{ID: NewToken()[:22], Cursor: c, lastUsed: time.Now()}
	s.cursors[cur.ID] = cur
	return cur, nil
}

// GetCursor returns an open cursor by id.
func (s *Session) GetCursor(id string, idle time.Duration) (*Cursor, bool) {
	s.curMu.Lock()
	defer s.curMu.Unlock()
	s.reapLocked(idle)
	c, ok := s.cursors[id]
	if ok {
		c.lastUsed = time.Now()
	}
	return c, ok
}

// CloseCursor closes and forgets a cursor.
func (s *Session) CloseCursor(id string) {
	s.curMu.Lock()
	c, ok := s.cursors[id]
	delete(s.cursors, id)
	s.curMu.Unlock()
	if ok {
		closeCursor(c)
	}
}

// CursorCount returns the number of open cursors.
func (s *Session) CursorCount() int {
	s.curMu.Lock()
	defer s.curMu.Unlock()
	return len(s.cursors)
}

func (s *Session) reapLocked(idle time.Duration) {
	now := time.Now()
	for id, c := range s.cursors {
		if now.Sub(c.lastUsed) > idle {
			delete(s.cursors, id)
			go closeCursor(c)
		}
	}
}

func (s *Session) closeAllCursors() {
	s.curMu.Lock()
	all := s.cursors
	s.cursors = nil
	s.curMu.Unlock()
	for _, c := range all {
		closeCursor(c)
	}
}

func closeCursor(c *Cursor) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = c.Cursor.Close(ctx)
}

// LastSeen returns the last activity time.
func (s *Session) LastSeen() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastSeen
}

// IdleExpiry returns when the session expires if idle.
func (s *Session) IdleExpiry(idle time.Duration) time.Time {
	t := s.LastSeen().Add(idle)
	if t.After(s.ExpiresAt) {
		return s.ExpiresAt
	}
	return t
}

// Options configures a Store.
type Options struct {
	IdleTimeout     time.Duration
	AbsoluteTimeout time.Duration
	MaxPerUser      int
	MaxTotal        int
	// OnClose is called (outside locks) whenever a session is removed.
	OnClose func(s *Session, reason string)
}

// Store is an in-memory session store.
type Store struct {
	opts Options
	now  func() time.Time

	mu       sync.Mutex
	sessions map[[32]byte]*Session

	stop chan struct{}
	done chan struct{}
}

// NewStore creates a store and starts its expiry janitor.
func NewStore(opts Options) *Store {
	s := &Store{opts: opts, now: time.Now, sessions: map[[32]byte]*Session{}, stop: make(chan struct{}), done: make(chan struct{})}
	go s.janitor()
	return s
}

// NewToken returns a 256-bit random URL-safe token.
func NewToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failure: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func keyOf(secret string) [32]byte { return sha256.Sum256([]byte(secret)) }

// Create stores a new session and returns its bearer secret. A fresh secret
// is always generated (session rotation on authentication), and any session
// identified by replaceSecret is destroyed first (fixation protection).
func (st *Store) Create(sess *Session, replaceSecret string) (string, error) {
	if replaceSecret != "" {
		st.Delete(replaceSecret, "replaced")
	}
	secret := NewToken()
	now := st.now()
	sess.key = keyOf(secret)
	sess.Handle = NewToken()[:16]
	sess.CSRFToken = NewToken()
	sess.CreatedAt = now
	sess.ExpiresAt = now.Add(st.opts.AbsoluteTimeout)
	sess.lastSeen = now
	if sess.Shell == nil {
		sess.Shell = make(chan struct{}, 4)
	}

	var evicted []*Session
	st.mu.Lock()
	var mine []*Session
	for _, s := range st.sessions {
		if s.Owner == sess.Owner {
			mine = append(mine, s)
		}
	}
	// Enforce per-user limit by evicting that user's oldest sessions.
	if st.opts.MaxPerUser > 0 && len(mine) >= st.opts.MaxPerUser {
		slices.SortFunc(mine, func(a, b *Session) int { return a.CreatedAt.Compare(b.CreatedAt) })
		for _, s := range mine[:len(mine)-st.opts.MaxPerUser+1] {
			delete(st.sessions, s.key)
			evicted = append(evicted, s)
		}
	}
	if st.opts.MaxTotal > 0 && len(st.sessions) >= st.opts.MaxTotal {
		st.mu.Unlock()
		st.closeAll(evicted, "evicted")
		return "", ErrCapacity
	}
	st.sessions[sess.key] = sess
	st.mu.Unlock()
	st.closeAll(evicted, "evicted")
	return secret, nil
}

// Get returns the session for secret if it is valid and owned by owner,
// and records activity.
func (st *Store) Get(secret, owner string) (*Session, error) {
	if secret == "" {
		return nil, ErrNotFound
	}
	k := keyOf(secret)
	st.mu.Lock()
	sess, ok := st.sessions[k]
	if !ok {
		st.mu.Unlock()
		return nil, ErrNotFound
	}
	now := st.now()
	if st.expired(sess, now) {
		delete(st.sessions, k)
		st.mu.Unlock()
		st.closeAll([]*Session{sess}, "expired")
		return nil, ErrExpired
	}
	if sess.Owner != owner {
		// Cookie presented under a different identity: never serve it,
		// and destroy it because the bearer secret has leaked across users.
		delete(st.sessions, k)
		st.mu.Unlock()
		st.closeAll([]*Session{sess}, "owner_mismatch")
		return nil, ErrWrongOwner
	}
	st.mu.Unlock()
	sess.mu.Lock()
	sess.lastSeen = now
	sess.mu.Unlock()
	return sess, nil
}

// OwnerOf returns the owner key and principal of the live session for
// secret, or "" when there is none. It records no activity; callers then
// use Get with the owner they expect.
func (st *Store) OwnerOf(secret string) (string, *identity.Principal) {
	if secret == "" {
		return "", nil
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	sess, ok := st.sessions[keyOf(secret)]
	if !ok || st.expired(sess, st.now()) {
		return "", nil
	}
	return sess.Owner, sess.Principal
}

// Delete removes the session identified by secret.
func (st *Store) Delete(secret, reason string) bool {
	if secret == "" {
		return false
	}
	k := keyOf(secret)
	st.mu.Lock()
	sess, ok := st.sessions[k]
	delete(st.sessions, k)
	st.mu.Unlock()
	if ok {
		st.closeAll([]*Session{sess}, reason)
	}
	return ok
}

// DeleteByHandle removes a session of owner by its public handle.
func (st *Store) DeleteByHandle(owner, handle, reason string) bool {
	st.mu.Lock()
	var found *Session
	for k, s := range st.sessions {
		if s.Owner == owner && s.Handle == handle {
			found = s
			delete(st.sessions, k)
			break
		}
	}
	st.mu.Unlock()
	if found != nil {
		st.closeAll([]*Session{found}, reason)
	}
	return found != nil
}

// ListByOwner returns the live sessions of a principal.
func (st *Store) ListByOwner(owner string) []*Session {
	now := st.now()
	st.mu.Lock()
	defer st.mu.Unlock()
	var out []*Session
	for _, s := range st.sessions {
		if s.Owner == owner && !st.expired(s, now) {
			out = append(out, s)
		}
	}
	slices.SortFunc(out, func(a, b *Session) int { return a.CreatedAt.Compare(b.CreatedAt) })
	return out
}

// Count returns the number of stored sessions.
func (st *Store) Count() int {
	st.mu.Lock()
	defer st.mu.Unlock()
	return len(st.sessions)
}

func (st *Store) expired(s *Session, now time.Time) bool {
	if !now.Before(s.ExpiresAt) {
		return true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return now.Sub(s.lastSeen) >= st.opts.IdleTimeout
}

// Sweep removes expired sessions.
func (st *Store) Sweep() {
	now := st.now()
	var dead []*Session
	st.mu.Lock()
	for k, s := range st.sessions {
		if st.expired(s, now) {
			delete(st.sessions, k)
			dead = append(dead, s)
		}
	}
	st.mu.Unlock()
	st.closeAll(dead, "expired")
}

func (st *Store) janitor() {
	defer close(st.done)
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			st.Sweep()
		case <-st.stop:
			return
		}
	}
}

// Close stops the janitor and disconnects every session.
func (st *Store) Close() {
	close(st.stop)
	<-st.done
	st.mu.Lock()
	all := make([]*Session, 0, len(st.sessions))
	for k, s := range st.sessions {
		all = append(all, s)
		delete(st.sessions, k)
	}
	st.mu.Unlock()
	var wg sync.WaitGroup
	for _, s := range all {
		wg.Add(1)
		go func() {
			defer wg.Done()
			st.disconnect(s, "shutdown")
		}()
	}
	wg.Wait()
}

func (st *Store) closeAll(list []*Session, reason string) {
	for _, s := range list {
		go st.disconnect(s, reason)
	}
}

func (st *Store) disconnect(s *Session, reason string) {
	s.closeAllCursors()
	if s.Client != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		_ = s.Client.Disconnect(ctx)
		cancel()
	}
	if st.opts.OnClose != nil {
		st.opts.OnClose(s, reason)
	}
}
