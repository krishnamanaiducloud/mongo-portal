package rbac

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Source configures where a Store reads its policy.
type Source struct {
	// Inline is CSV from the portal configuration file.
	Inline string
	// DefaultRole applies when the policy directory does not set one.
	DefaultRole string
	// Dir optionally holds "policy.csv" and "policy.default" (the keys of an
	// RBAC ConfigMap). A missing directory is not an error.
	Dir string
	// Extra lines appended after the inline policy (for example derived from
	// deprecated configuration).
	Extra string
}

// Status describes the active policy for operators and the UI.
type Status struct {
	Source      string    `json:"source"` // "file", "config" or "built-in"
	DefaultRole string    `json:"defaultRole"`
	LoadedAt    time.Time `json:"loadedAt"`
	Error       string    `json:"error,omitempty"`
}

// Store holds the active policy and reloads it when the policy files
// change. An invalid update is rejected and the previous policy stays
// active, so a bad ConfigMap edit never locks users out.
type Store struct {
	src Source
	log *slog.Logger

	mu     sync.RWMutex
	policy *Policy
	status Status
	digest [32]byte
}

// NewStore loads the policy. Only an invalid inline policy is fatal (it is
// part of the validated configuration); problems with the optional policy
// directory are reported in Status and the configuration policy is used.
func NewStore(src Source, log *slog.Logger) (*Store, error) {
	s := &Store{src: src, log: log}
	if _, err := Parse(src.Inline+"\n"+src.Extra, src.DefaultRole); err != nil {
		return nil, err
	}
	s.reload(true)
	return s, nil
}

// Policy returns the active policy.
func (s *Store) Policy() *Policy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.policy
}

// Status returns the active policy status.
func (s *Store) Status() Status {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.status
}

// Reload re-reads the policy now instead of at the next interval.
func (s *Store) Reload() Status {
	s.reload(false)
	return s.Status()
}

// Watch reloads the policy every interval until ctx ends.
func (s *Store) Watch(ctx context.Context, interval time.Duration) {
	if s.src.Dir == "" || interval <= 0 {
		return
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.reload(false)
		}
	}
}

func (s *Store) reload(initial bool) {
	csv, def, fromFile, err := s.read()
	sum := sha256.Sum256([]byte(csv + "\x00" + def + "\x00" + fmt.Sprint(fromFile)))
	s.mu.RLock()
	unchanged := !initial && sum == s.digest && err == nil && s.status.Error == ""
	s.mu.RUnlock()
	if unchanged {
		return
	}
	if err == nil {
		var p *Policy
		if p, err = Parse(csv, def); err == nil {
			source := "built-in"
			switch {
			case fromFile:
				source = "file"
			case strings.TrimSpace(s.src.Inline+s.src.Extra) != "":
				source = "config"
			}
			s.mu.Lock()
			s.policy, s.digest = p, sum
			s.status = Status{Source: source, DefaultRole: p.DefaultRole(), LoadedAt: time.Now().UTC()}
			s.mu.Unlock()
			s.log.Info("rbac policy loaded", "source", source, "default_role", p.DefaultRole())
			return
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.policy == nil {
		// First load with a broken policy directory: fall back to the
		// validated configuration policy.
		p, perr := Parse(s.src.Inline+"\n"+s.src.Extra, s.src.DefaultRole)
		if perr != nil {
			p, _ = Parse("", s.src.DefaultRole)
		}
		s.policy = p
		s.status = Status{Source: "config", DefaultRole: p.DefaultRole(), LoadedAt: time.Now().UTC()}
	}
	if s.status.Error != err.Error() {
		s.log.Warn("rbac policy update rejected; keeping the previous policy", "error", err.Error())
	}
	s.status.Error = err.Error()
	s.digest = sum
}

// read returns the combined CSV and default role. fromFile reports whether
// the policy directory contributed.
func (s *Store) read() (csv, def string, fromFile bool, err error) {
	csv, def = s.src.Inline+"\n"+s.src.Extra, s.src.DefaultRole
	if s.src.Dir == "" {
		return csv, def, false, nil
	}
	b, err := os.ReadFile(filepath.Join(s.src.Dir, "policy.csv")) // #nosec G304 -- operator supplied mount
	switch {
	case err == nil:
		csv += "\n" + string(b)
		fromFile = true
	case errors.Is(err, fs.ErrNotExist):
	default:
		return "", "", false, fmt.Errorf("read policy.csv: %w", err)
	}
	b, err = os.ReadFile(filepath.Join(s.src.Dir, "policy.default")) // #nosec G304 -- operator supplied mount
	switch {
	case err == nil:
		def = strings.TrimSpace(string(b))
		fromFile = true
	case errors.Is(err, fs.ErrNotExist):
	default:
		return "", "", false, fmt.Errorf("read policy.default: %w", err)
	}
	return csv, def, fromFile, nil
}
