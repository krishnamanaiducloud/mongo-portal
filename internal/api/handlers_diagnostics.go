package api

import (
	"context"
	"net/http"
	"time"

	"github.com/krishnamanaiducloud/mongo-portal/internal/audit"
	"github.com/krishnamanaiducloud/mongo-portal/internal/preflight"
	"github.com/krishnamanaiducloud/mongo-portal/internal/rbac"
)

// diagnoseSem bounds concurrent connection diagnostics per replica: each
// one opens network connections to the profile's hosts.
var diagnoseSem = make(chan struct{}, 2)

// handleProfileDiagnostics runs the read-only preflight checks of one
// connection profile: name resolution, reachability, TLS verification,
// topology and version, and for MONGODB-OIDC the provider MongoDB trusts.
// No credentials or tokens are sent to MongoDB.
func (s *Server) handleProfileDiagnostics(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	name := r.PathValue("name")
	if _, ok := s.Config.Profile(name); !ok {
		writeError(w, r, http.StatusNotFound, "unknown_profile", "Unknown connection profile")
		return
	}
	if !s.authorize(w, r, rc, rbac.Monitoring, rbac.Get, name) {
		return
	}
	select {
	case diagnoseSem <- struct{}{}:
		defer func() { <-diagnoseSem }()
	default:
		writeError(w, r, http.StatusTooManyRequests, "rate_limited", "Diagnostics are already running; try again in a moment")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	rep := preflight.ProfileReport(ctx, s.Config, name, preflight.Options{Timeout: 8 * time.Second, Logger: s.Logger})
	outcome := audit.Success
	if rep.Failed() {
		outcome = audit.Failure
	}
	e := s.baseEvent(rc, "profile_diagnostics", outcome, "")
	e.Profile = name
	s.Audit.Record(r.Context(), e)
	writeJSON(w, http.StatusOK, rep)
}
