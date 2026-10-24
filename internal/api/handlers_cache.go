package api

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/krishnamanaiducloud/mongo-portal/internal/audit"
	"github.com/krishnamanaiducloud/mongo-portal/internal/config"
	"github.com/krishnamanaiducloud/mongo-portal/internal/identity"
	"github.com/krishnamanaiducloud/mongo-portal/internal/rbac"
	"github.com/krishnamanaiducloud/mongo-portal/internal/store"
)

// The portal's own caches. Each replica holds its own copy; invalidating
// re-reads or re-checks the source, it never deletes data and never
// touches MongoDB's caches (WiredTiger) or storage.

// CacheInvalidations is the shared invalidation log (nil without a store).
type CacheInvalidations interface {
	Publish(ctx context.Context, inv store.Invalidation) (bson.ObjectID, error)
	Pending(ctx context.Context, pod string, since time.Time) ([]store.Invalidation, error)
	Ack(ctx context.Context, id bson.ObjectID, a store.Applied) error
	Recent(ctx context.Context, limit int64) ([]store.Invalidation, error)
}

type cacheView struct {
	Name        string    `json:"name"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Entries     int       `json:"entries"`
	RefreshedAt time.Time `json:"refreshedAt,omitzero"`
	LastError   string    `json:"lastError,omitempty"`
}

type cacheDef struct {
	name, title, desc string
	view              func() cacheView
	invalidate        func(ctx context.Context) error
}

func (s *Server) cacheDefs() []cacheDef {
	return []cacheDef{
		{
			name: "identities", title: "Signed-in identities and groups",
			desc: "OpenShift token reviews and the group memberships carried in sign-in cookies. Invalidating makes every OpenShift sign-in re-check its token and groups on its next request.",
			view: func() cacheView {
				n, at := s.Identity.ReviewCacheStats()
				return cacheView{Entries: n, RefreshedAt: at}
			},
			invalidate: func(context.Context) error { s.Identity.RevalidateIdentities(); return nil },
		},
		{
			name: "sign-in-providers", title: "Sign-in provider discovery",
			desc: "Discovery documents and signing keys of OpenShift OAuth and the OIDC providers. Invalidating checks every provider again now.",
			view: func() cacheView {
				src := s.Identity.Sources()
				v := cacheView{RefreshedAt: src.OpenShift.CheckedAt}
				var errs []string
				add := func(name string, st identity.Status) {
					if st.State == identity.StateDisabled {
						return
					}
					v.Entries++
					if st.CheckedAt.After(v.RefreshedAt) {
						v.RefreshedAt = st.CheckedAt
					}
					if st.State != identity.StateAvailable && st.Reason != "" {
						errs = append(errs, name+": "+st.Reason)
					}
				}
				add("OpenShift", src.OpenShift)
				for _, o := range src.OIDC {
					add(o.DisplayName, o.Status)
				}
				v.LastError = strings.Join(errs, "; ")
				return v
			},
			invalidate: func(ctx context.Context) error {
				if s.Config.Identity.OpenShift.Enabled != config.EnabledFalse {
					s.Identity.OpenShift.Probe(ctx)
				}
				var errs []error
				for _, p := range s.Identity.OIDC {
					if st := p.Probe(ctx); st.State != identity.StateAvailable && st.State != identity.StateDisabled {
						errs = append(errs, errors.New(p.DisplayName()+": "+st.Reason))
					}
				}
				return errors.Join(errs...)
			},
		},
		{
			name: "mongodb-oidc-providers", title: "MongoDB OIDC provider discovery",
			desc: "Discovery of the identity providers the MongoDB deployments trust (kept up to 10 minutes). Invalidating discovers them again at the next connection.",
			view: func() cacheView {
				s.midp.mu.Lock()
				defer s.midp.mu.Unlock()
				v := cacheView{Entries: len(s.midp.m)}
				for _, c := range s.midp.m {
					if v.RefreshedAt.IsZero() || c.at.Before(v.RefreshedAt) {
						v.RefreshedAt = c.at
					}
				}
				return v
			},
			invalidate: func(context.Context) error {
				s.midp.mu.Lock()
				s.midp.m = nil
				s.midp.mu.Unlock()
				return nil
			},
		},
		{
			name: "rbac-policy", title: "RBAC policy",
			desc: "The role policy from the configuration and the RBAC ConfigMap (re-read periodically). Invalidating re-reads it now; an invalid policy is rejected and the previous one stays active.",
			view: func() cacheView {
				st := s.RBAC.Status()
				return cacheView{Entries: 1, RefreshedAt: st.LoadedAt, LastError: st.Error}
			},
			invalidate: func(context.Context) error {
				if st := s.RBAC.Reload(); st.Error != "" {
					return errors.New(st.Error)
				}
				return nil
			},
		},
		{
			name: "profile-health", title: "Connection profile health",
			desc: "Reachability of each MongoDB deployment shown on the sign-in page (checked periodically without credentials). Invalidating checks every profile now.",
			view: func() cacheView {
				v := cacheView{}
				for _, p := range s.Config.Profiles {
					h := s.profileHealth(p.Name)
					v.Entries++
					if h.CheckedAt.After(v.RefreshedAt) {
						v.RefreshedAt = h.CheckedAt
					}
				}
				return v
			},
			invalidate: func(ctx context.Context) error {
				if s.Monitor != nil {
					s.Monitor.CheckNow(ctx)
				}
				return nil
			},
		},
	}
}

func (s *Server) handleCaches(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	if !s.authorize(w, r, rc, rbac.Cache, rbac.Get, "*") {
		return
	}
	out := []cacheView{}
	for _, d := range s.cacheDefs() {
		v := d.view()
		v.Name, v.Title, v.Description = d.name, d.title, d.desc
		out = append(out, v)
	}
	resp := map[string]any{"pod": s.Pod, "caches": out, "shared": s.Invalidations != nil,
		"canInvalidate": s.allowed(rc, rbac.Cache, rbac.Delete, "*")}
	if s.Invalidations != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		recent, err := s.Invalidations.Recent(ctx, 20)
		if err != nil {
			resp["recentError"] = "the shared store is not available; invalidations apply to this replica only"
		} else {
			resp["recent"] = recent
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

type invalidateRequest struct {
	Caches []string `json:"caches"`
	// Scope is "replica" (this replica) or "all" (every replica through the
	// shared store).
	Scope   string `json:"scope"`
	Confirm string `json:"confirm"`
}

type cacheResult struct {
	Name  string `json:"name"`
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

func (s *Server) applyInvalidation(ctx context.Context, names []string) ([]cacheResult, []string) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var res []cacheResult
	var errs []string
	for _, d := range s.cacheDefs() {
		if !slices.Contains(names, d.name) {
			continue
		}
		cr := cacheResult{Name: d.name, OK: true}
		if err := d.invalidate(ctx); err != nil {
			cr.OK, cr.Error = false, err.Error()
			errs = append(errs, d.name+": "+err.Error())
		}
		res = append(res, cr)
	}
	return res, errs
}

func (s *Server) handleInvalidateCaches(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	if !s.authorize(w, r, rc, rbac.Cache, rbac.Delete, "*") {
		return
	}
	var req invalidateRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	known := []string{}
	for _, d := range s.cacheDefs() {
		known = append(known, d.name)
	}
	if len(req.Caches) == 0 || len(req.Caches) > len(known) || slices.ContainsFunc(req.Caches, func(n string) bool { return !slices.Contains(known, n) }) {
		writeError(w, r, http.StatusBadRequest, "invalid_input", "caches must name one or more of: "+strings.Join(known, ", "))
		return
	}
	if req.Scope == "" {
		req.Scope = "all"
	}
	if req.Scope != "all" && req.Scope != "replica" {
		writeError(w, r, http.StatusBadRequest, "invalid_input", "scope must be all or replica")
		return
	}
	if req.Confirm != "invalidate" {
		writeError(w, r, http.StatusPreconditionRequired, "confirmation_required", `Type "invalidate" to confirm`)
		return
	}
	results, errs := s.applyInvalidation(r.Context(), req.Caches)
	resp := map[string]any{"results": results, "pod": s.Pod, "scope": req.Scope}
	if req.Scope == "all" {
		switch {
		case s.Invalidations == nil:
			resp["note"] = "No shared store is configured: applied on this replica only. Other replicas refresh on their own schedule."
		default:
			ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
			defer cancel()
			now := time.Now().UTC()
			id, err := s.Invalidations.Publish(ctx, store.Invalidation{Caches: req.Caches, RequestedBy: rc.user(), Origin: s.Pod, At: now,
				Applied: []store.Applied{{Pod: s.Pod, At: now, Errors: errs}}})
			if err != nil {
				resp["note"] = "The shared store is not available: applied on this replica only."
			} else {
				resp["id"] = id
				resp["note"] = "Applied here; other replicas apply it within " + s.Config.Cache.SyncInterval.String() + "."
			}
		}
	}
	outcome := audit.Success
	if len(errs) > 0 {
		outcome = audit.Failure
	}
	e := s.baseEvent(rc, "cache_invalidate", outcome, strings.Join(errs, "; "))
	e.Target = req.Scope + ": " + strings.Join(req.Caches, ",")
	s.Audit.Record(r.Context(), e)
	writeJSON(w, http.StatusOK, resp)
}

// RunCacheSync applies invalidations requested on other replicas until ctx
// ends.
func (s *Server) RunCacheSync(ctx context.Context, every time.Duration) {
	if s.Invalidations == nil {
		return
	}
	// Invalidations from before this replica started are irrelevant: its
	// caches are fresh. A minute of tolerance covers clock differences.
	since := time.Now().UTC().Add(-time.Minute)
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.SyncCaches(ctx, since)
		}
	}
}

// SyncCaches applies pending invalidations once (tests).
func (s *Server) SyncCaches(ctx context.Context, since time.Time) int {
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	pending, err := s.Invalidations.Pending(cctx, s.Pod, since)
	if err != nil {
		return 0
	}
	for _, inv := range pending {
		_, errs := s.applyInvalidation(cctx, inv.Caches)
		if err := s.Invalidations.Ack(cctx, inv.ID, store.Applied{Pod: s.Pod, At: time.Now().UTC(), Errors: errs}); err != nil {
			s.Logger.Warn("cache invalidation not acknowledged", "id", inv.ID.Hex(), "error", err.Error())
		}
		s.Logger.Info("cache invalidation applied", "id", inv.ID.Hex(), "caches", strings.Join(inv.Caches, ","), "requested_by", inv.RequestedBy, "origin", inv.Origin)
	}
	return len(pending)
}
