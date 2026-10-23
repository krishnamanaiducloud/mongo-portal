package ratelimit

import (
	"testing"
	"time"
)

func TestWindowAndLockout(t *testing.T) {
	now := time.Unix(0, 0)
	l := New(3, time.Minute, 2, time.Minute, 4*time.Minute)
	l.now = func() time.Time { return now }

	for i := 0; i < 3; i++ {
		if ok, _ := l.Allow("alice", "p/u"); !ok {
			t.Fatalf("attempt %d should be allowed", i)
		}
	}
	if ok, wait := l.Allow("alice", "p/u"); ok || wait <= 0 {
		t.Fatal("4th attempt within window must be denied")
	}
	if ok, _ := l.Allow("bob", "p/u"); !ok {
		t.Fatal("other actor has own window")
	}
	now = now.Add(61 * time.Second)
	if ok, _ := l.Allow("alice", "p/u"); !ok {
		t.Fatal("window should slide")
	}

	l.Failure("p/x")
	l.Failure("p/x")
	if ok, _ := l.Allow("carol", "p/x"); ok {
		t.Fatal("target should be locked after failures")
	}
	now = now.Add(61 * time.Second)
	if ok, _ := l.Allow("carol", "p/x"); !ok {
		t.Fatal("lock should expire")
	}
	// Second lock doubles.
	l.Failure("p/x")
	l.Failure("p/x")
	now = now.Add(90 * time.Second)
	if ok, _ := l.Allow("dave", "p/x"); ok {
		t.Fatal("second lock should be 2 minutes")
	}
	l.Success("p/x")
	if ok, _ := l.Allow("dave", "p/x"); !ok {
		t.Fatal("success clears lock")
	}
}
