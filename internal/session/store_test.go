package session

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/krishnamanaiducloud/mongo-portal/internal/identity"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

func newTestStore(t *testing.T, o Options) (*Store, *clock, *atomic.Int32) {
	t.Helper()
	var closed atomic.Int32
	o.OnClose = func(*Session, string) { closed.Add(1) }
	st := NewStore(o)
	c := &clock{t: time.Unix(1_700_000_000, 0)}
	st.now = c.now
	t.Cleanup(st.Close)
	return st, c, &closed
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition not met")
}

func TestCreateGetAndOwnerBinding(t *testing.T) {
	st, _, closed := newTestStore(t, Options{IdleTimeout: time.Minute, AbsoluteTimeout: time.Hour, MaxPerUser: 3, MaxTotal: 10})
	secret, err := st.Create(&Session{Owner: "alice"}, "")
	if err != nil {
		t.Fatal(err)
	}
	s, err := st.Get(secret, "alice")
	if err != nil || s.Owner != "alice" || s.CSRFToken == "" || s.Handle == "" {
		t.Fatalf("get: %v %+v", err, s)
	}
	// Another SSO user presenting alice's cookie is rejected and the session destroyed.
	if _, err := st.Get(secret, "mallory"); !errors.Is(err, ErrWrongOwner) {
		t.Fatalf("owner mismatch: %v", err)
	}
	if _, err := st.Get(secret, "alice"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("session should be destroyed: %v", err)
	}
	waitFor(t, func() bool { return closed.Load() == 1 })
}

func TestIdleAndAbsoluteExpiry(t *testing.T) {
	st, c, _ := newTestStore(t, Options{IdleTimeout: 10 * time.Minute, AbsoluteTimeout: 30 * time.Minute})
	secret, _ := st.Create(&Session{Owner: "a"}, "")
	c.add(9 * time.Minute)
	if _, err := st.Get(secret, "a"); err != nil {
		t.Fatalf("active session: %v", err)
	}
	c.add(9 * time.Minute)
	if _, err := st.Get(secret, "a"); err != nil {
		t.Fatalf("activity should extend idle: %v", err)
	}
	c.add(11 * time.Minute)
	if _, err := st.Get(secret, "a"); !errors.Is(err, ErrExpired) {
		t.Fatalf("idle expiry: %v", err)
	}

	secret, _ = st.Create(&Session{Owner: "a"}, "")
	for i := 0; i < 4; i++ {
		c.add(8 * time.Minute)
		_, err := st.Get(secret, "a")
		if i < 3 && err != nil {
			t.Fatalf("step %d: %v", i, err)
		}
		if i == 3 && !errors.Is(err, ErrExpired) {
			t.Fatalf("absolute expiry not enforced: %v", err)
		}
	}
}

func TestRotationAndFixation(t *testing.T) {
	st, _, _ := newTestStore(t, Options{IdleTimeout: time.Minute, AbsoluteTimeout: time.Hour})
	old, _ := st.Create(&Session{Owner: "a"}, "")
	fresh, _ := st.Create(&Session{Owner: "a"}, old)
	if old == fresh {
		t.Fatal("secret must rotate")
	}
	if _, err := st.Get(old, "a"); !errors.Is(err, ErrNotFound) {
		t.Fatal("replaced session must be destroyed")
	}
	if _, err := st.Get(fresh, "a"); err != nil {
		t.Fatal(err)
	}
}

func TestLimits(t *testing.T) {
	st, c, _ := newTestStore(t, Options{IdleTimeout: time.Hour, AbsoluteTimeout: time.Hour, MaxPerUser: 2, MaxTotal: 3})
	s1, _ := st.Create(&Session{Owner: "a"}, "")
	c.add(time.Second)
	s2, _ := st.Create(&Session{Owner: "a"}, "")
	c.add(time.Second)
	s3, _ := st.Create(&Session{Owner: "a"}, "")
	if _, err := st.Get(s1, "a"); err == nil {
		t.Fatal("oldest session should be evicted at per-user limit")
	}
	for _, s := range []string{s2, s3} {
		if _, err := st.Get(s, "a"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := st.Create(&Session{Owner: "b"}, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Create(&Session{Owner: "c"}, ""); !errors.Is(err, ErrCapacity) {
		t.Fatalf("global cap: %v", err)
	}
}

func TestConcurrentUsersAreIsolated(t *testing.T) {
	st, _, _ := newTestStore(t, Options{IdleTimeout: time.Hour, AbsoluteTimeout: time.Hour, MaxPerUser: 5, MaxTotal: 1000})
	var wg sync.WaitGroup
	errs := make(chan error, 100)
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			user := string(rune('a' + i%26))
			sec, err := st.Create(&Session{Owner: user, MongoUser: user}, "")
			if err != nil {
				errs <- err
				return
			}
			s, err := st.Get(sec, user)
			if err != nil {
				errs <- err
				return
			}
			if s.MongoUser != user {
				errs <- errors.New("cross-user session confusion")
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if !errors.Is(err, ErrNotFound) { // eviction under per-user limit is allowed
			t.Fatal(err)
		}
	}
}

type fakeCursor struct{ closed *atomic.Int32 }

func (f fakeCursor) Close(context.Context) error { f.closed.Add(1); return nil }

func TestCursorRegistry(t *testing.T) {
	st, _, _ := newTestStore(t, Options{IdleTimeout: time.Hour, AbsoluteTimeout: time.Hour})
	sec, _ := st.Create(&Session{Owner: "a"}, "")
	s, _ := st.Get(sec, "a")
	var closed atomic.Int32
	c1, err := s.AddCursor(fakeCursor{&closed}, 2, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddCursor(fakeCursor{&closed}, 2, time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddCursor(fakeCursor{&closed}, 2, time.Hour); !errors.Is(err, ErrTooManyCursors) {
		t.Fatalf("cursor limit: %v", err)
	}
	if got, ok := s.GetCursor(c1.ID, time.Hour); !ok || got != c1 {
		t.Fatal("get cursor")
	}
	s.CloseCursor(c1.ID)
	if _, ok := s.GetCursor(c1.ID, time.Hour); ok || closed.Load() != 1 {
		t.Fatal("close cursor")
	}
	// Idle cursors are reaped.
	time.Sleep(5 * time.Millisecond)
	if _, ok := s.GetCursor("x", time.Millisecond); ok || s.CursorCount() != 0 {
		t.Fatal("idle reap")
	}
	// Ending the session closes remaining cursors.
	_, _ = s.AddCursor(fakeCursor{&closed}, 2, time.Hour)
	st.Delete(sec, "logout")
	waitFor(t, func() bool { return closed.Load() == 3 })
}

func TestDeleteByHandleAndSweep(t *testing.T) {
	st, c, closed := newTestStore(t, Options{IdleTimeout: time.Minute, AbsoluteTimeout: time.Hour})
	sec, _ := st.Create(&Session{Owner: "a"}, "")
	s, _ := st.Get(sec, "a")
	if st.DeleteByHandle("b", s.Handle, "x") {
		t.Fatal("other user must not delete session by handle")
	}
	if !st.DeleteByHandle("a", s.Handle, "x") {
		t.Fatal("delete by handle")
	}
	_, _ = st.Create(&Session{Owner: "a"}, "")
	c.add(2 * time.Minute)
	st.Sweep()
	if st.Count() != 0 {
		t.Fatal("sweep should remove idle sessions")
	}
	waitFor(t, func() bool { return closed.Load() == 2 })
}

func TestOwnerOf(t *testing.T) {
	st := NewStore(Options{IdleTimeout: time.Hour, AbsoluteTimeout: time.Hour})
	defer st.Close()
	p := identity.MongoDBPrincipal("u", "admin")
	secret, _ := st.Create(&Session{Owner: p.Key(), Principal: p}, "")
	if owner, got := st.OwnerOf(secret); owner != p.Key() || got != p {
		t.Fatalf("owner of: %q %v", owner, got)
	}
	if owner, got := st.OwnerOf("unknown"); owner != "" || got != nil {
		t.Fatal("unknown secret")
	}
	if owner, _ := st.OwnerOf(""); owner != "" {
		t.Fatal("empty secret")
	}
}
