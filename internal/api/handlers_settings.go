package api

import (
	"context"
	"net/http"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/krishnamanaiducloud/mongo-portal/internal/config"
	"github.com/krishnamanaiducloud/mongo-portal/internal/identity"
	"github.com/krishnamanaiducloud/mongo-portal/internal/rbac"
)

// handleIndexStats reports index usage ($indexStats): operations served by
// each index since the server started or the index was created.
func (s *Server) handleIndexStats(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	db, coll, ok := nsParams(w, r, true)
	if !ok {
		return
	}
	if !s.authorize(w, r, rc, rbac.Indexes, rbac.Get, rbac.Namespace(db, coll)) {
		return
	}
	var rows []bson.M
	err := s.op(r.Context(), "indexStats", s.defaultTimeout(), func(ctx context.Context) error {
		cur, err := rc.sess.Client.Database(db).Collection(coll).Aggregate(ctx, bson.A{bson.D{{Key: "$indexStats", Value: bson.D{}}}})
		if err != nil {
			return err
		}
		return cur.All(ctx, &rows)
	})
	if err != nil {
		s.mongoError(w, r, rc, "indexStats", err)
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for _, x := range rows {
		acc := msub(x, "accesses")
		item := map[string]any{"name": mstr(x, "name"), "host": mstr(x, "host"), "ops": mnum(acc, "ops")}
		if t := mdate(acc, "since"); !t.IsZero() {
			item["since"] = t.UTC()
		}
		out = append(out, item)
	}
	writeJSON(w, http.StatusOK, map[string]any{"indexes": out,
		"note": "Counts are per member and reset when the member restarts or the index is rebuilt."})
}

// handleSettings shows the effective configuration without secrets: file
// paths are reported as configured or not, never their contents.
func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	if !s.authorize(w, r, rc, rbac.Settings, rbac.Get, "*") {
		return
	}
	c := s.Config
	set := func(path string) bool { return path != "" }
	providers := []map[string]any{}
	for _, p := range c.Identity.OIDC.Providers {
		st := identity.Status{}
		if pr := s.Identity.Provider(p.Name); pr != nil {
			st = pr.Status()
		}
		providers = append(providers, map[string]any{"name": p.Name, "displayName": p.DisplayName, "enabled": p.Enabled, "issuer": p.Issuer,
			"clientID": p.ClientID, "confidentialClient": set(p.ClientSecretFile), "scopes": p.Scopes, "usernameClaim": p.UsernameClaim,
			"groupsClaim": p.GroupsClaim, "requiredGroups": len(p.RequiredGroups), "sessionMaxAge": p.SessionMaxAge.String(), "status": st})
	}
	profiles := []map[string]any{}
	for _, p := range c.Profiles {
		pv := map[string]any{"name": p.Name, "displayName": p.DisplayName, "hosts": config.ProfileHosts(p.URI), "replicaSet": p.ReplicaSet,
			"authMechanisms": p.AuthMechanisms, "defaultAuthSource": p.DefaultAuthSource, "readPreference": p.ReadPreference,
			"tls":         map[string]any{"mode": p.TLS.Mode, "customCA": set(p.TLS.CAFile), "clientCertificate": set(p.TLS.ClientCertFile), "minVersion": p.TLS.MinVersion},
			"maxPoolSize": p.MaxPoolSize, "plaintextApproved": p.PlaintextApproved, "health": s.profileHealth(p.Name)}
		if o := p.OIDC; o != nil {
			pv["oidc"] = map[string]any{"issuer": o.Issuer, "clientID": o.ClientID, "scopes": o.Scopes, "allowedHosts": o.AllowedHosts, "confidentialClient": set(o.ClientSecretFile)}
		}
		profiles = append(profiles, pv)
	}
	store := map[string]any{"enabled": c.Store.Enabled}
	if c.Store.Enabled {
		store["profile"], store["database"], store["mechanism"] = c.Store.Profile, c.Store.Database, c.Store.Mechanism
		if s.StoreStatus != nil {
			store["status"] = s.StoreStatus()
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"environment": c.Environment, "production": c.IsProduction(), "pod": s.Pod,
		"identity": map[string]any{
			"requireSSO": c.Identity.RequireSSO,
			"openshift":  map[string]any{"enabled": c.Identity.OpenShift.Enabled, "status": s.Identity.OpenShift.Status(), "scopes": c.Identity.OpenShift.Scopes},
			"oidc":       providers,
			"header":     c.Identity.Header.Enabled,
			"dev":        c.Identity.Dev.Enabled,
		},
		"rbac":    s.RBAC.Status(),
		"session": map[string]any{"idleTimeout": c.Session.IdleTimeout.String(), "absoluteTimeout": c.Session.AbsoluteTimeout.String(), "maxPerUser": c.Session.MaxPerUser, "maxTotal": c.Session.MaxTotal, "registry": c.Session.Registry, "sharedKey": set(c.Session.KeyFile)},
		"audit":   map[string]any{"persist": c.Audit.Persist, "retention": c.Audit.Retention.String(), "bufferSize": c.Audit.BufferSize, "sink": s.Audit.SinkStatus()},
		"store":   store,
		"transfer": map[string]any{"enabled": c.TransferEnabled(), "maxImportBytes": c.Transfer.MaxImportBytes, "maxExportDocuments": c.Transfer.MaxExportDocuments,
			"batchSize": c.Transfer.BatchSize, "maxConcurrentJobs": c.Transfer.MaxConcurrentJobs, "maxErrors": c.Transfer.MaxErrors},
		"shell":       map[string]any{"enabled": c.ShellEnabled(), "maxCursors": c.Shell.MaxCursors, "allowDropDatabase": c.Shell.AllowDropDatabase},
		"query":       map[string]any{"maxLimit": c.Query.MaxLimit, "defaultMaxTime": c.Query.DefaultMaxTime.String(), "maxMaxTime": c.Query.MaxMaxTime.String(), "allowWriteStages": c.Query.AllowWriteStages},
		"monitoring":  map[string]any{"profileHealthInterval": c.Monitoring.ProfileHealthInterval.String(), "slowOperation": c.Monitoring.SlowOperation.String()},
		"tracing":     s.Tracing,
		"profiles":    profiles,
		"generatedAt": time.Now().UTC(),
	})
}
