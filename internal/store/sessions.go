package store

import (
	"context"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

const sessionsColl = "sessions"

// SessionMeta is the registry entry of one portal session. It never holds
// credentials, tokens or the session secret: only what an administrator
// needs to see and revoke sessions across replicas.
type SessionMeta struct {
	Handle     string     `bson:"_id" json:"handle"`
	Owner      string     `bson:"owner" json:"owner"`
	User       string     `bson:"user" json:"user"`
	Identity   string     `bson:"identity" json:"identity"`
	Provider   string     `bson:"provider,omitempty" json:"provider,omitempty"`
	Profile    string     `bson:"profile" json:"profile"`
	MongoUser  string     `bson:"mongoUser" json:"mongoUser"`
	AuthSource string     `bson:"authSource" json:"authSource"`
	Mechanism  string     `bson:"mechanism" json:"mechanism"`
	Pod        string     `bson:"pod" json:"pod"`
	ClientIP   string     `bson:"clientIP,omitempty" json:"clientIP,omitempty"`
	UserAgent  string     `bson:"userAgent,omitempty" json:"userAgent,omitempty"`
	TLS        bool       `bson:"tls" json:"tls"`
	CreatedAt  time.Time  `bson:"createdAt" json:"createdAt"`
	LastSeen   time.Time  `bson:"lastSeen" json:"lastSeen"`
	ExpiresAt  time.Time  `bson:"expiresAt" json:"expiresAt"`
	Revoked    bool       `bson:"revoked" json:"revoked"`
	RevokedBy  string     `bson:"revokedBy,omitempty" json:"revokedBy,omitempty"`
	RevokedAt  *time.Time `bson:"revokedAt,omitempty" json:"revokedAt,omitempty"`
}

// Registry is the shared session registry.
type Registry struct{ s *Store }

// Sessions returns the session registry.
func (s *Store) Sessions() *Registry { return &Registry{s: s} }

func (r *Registry) coll() (*mongo.Collection, error) {
	db, err := r.s.database()
	if err != nil {
		return nil, err
	}
	return db.Collection(sessionsColl), nil
}

// Upsert publishes local sessions (new ones and activity of existing ones).
// A revoked flag set by an administrator is never cleared.
func (r *Registry) Upsert(ctx context.Context, metas []SessionMeta) error {
	if len(metas) == 0 {
		return nil
	}
	c, err := r.coll()
	if err != nil {
		return err
	}
	models := make([]mongo.WriteModel, 0, len(metas))
	for _, m := range metas {
		set := bson.D{{Key: "lastSeen", Value: m.LastSeen}, {Key: "pod", Value: m.Pod}}
		ins := bson.D{
			{Key: "owner", Value: m.Owner}, {Key: "user", Value: m.User}, {Key: "identity", Value: m.Identity}, {Key: "provider", Value: m.Provider},
			{Key: "profile", Value: m.Profile}, {Key: "mongoUser", Value: m.MongoUser}, {Key: "authSource", Value: m.AuthSource},
			{Key: "mechanism", Value: m.Mechanism}, {Key: "clientIP", Value: m.ClientIP}, {Key: "userAgent", Value: m.UserAgent},
			{Key: "tls", Value: m.TLS}, {Key: "createdAt", Value: m.CreatedAt}, {Key: "expiresAt", Value: m.ExpiresAt}, {Key: "revoked", Value: false},
		}
		models = append(models, mongo.NewUpdateOneModel().SetFilter(bson.D{{Key: "_id", Value: m.Handle}}).
			SetUpdate(bson.D{{Key: "$set", Value: set}, {Key: "$setOnInsert", Value: ins}}).SetUpsert(true))
	}
	_, err = c.BulkWrite(ctx, models, options.BulkWrite().SetOrdered(false))
	return err
}

// Remove deletes registry entries of closed sessions.
func (r *Registry) Remove(ctx context.Context, handles []string) error {
	if len(handles) == 0 {
		return nil
	}
	c, err := r.coll()
	if err != nil {
		return err
	}
	_, err = c.DeleteMany(ctx, bson.D{{Key: "_id", Value: bson.D{{Key: "$in", Value: handles}}}})
	return err
}

// List returns live sessions, newest first, optionally of one owner.
func (r *Registry) List(ctx context.Context, owner string, limit int64) ([]SessionMeta, error) {
	c, err := r.coll()
	if err != nil {
		return nil, err
	}
	q := bson.D{{Key: "revoked", Value: false}, {Key: "expiresAt", Value: bson.D{{Key: "$gt", Value: time.Now()}}}}
	if owner != "" {
		q = append(q, bson.E{Key: "owner", Value: owner})
	}
	cur, err := c.Find(ctx, q, options.Find().SetSort(bson.D{{Key: "lastSeen", Value: -1}}).SetLimit(limit))
	if err != nil {
		return nil, err
	}
	var out []SessionMeta
	if err := cur.All(ctx, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// Revoke marks sessions revoked, by handle or by owner. Replicas holding
// them close them at their next sync.
func (r *Registry) Revoke(ctx context.Context, handle, owner, by string) (int64, error) {
	c, err := r.coll()
	if err != nil {
		return 0, err
	}
	q := bson.D{{Key: "revoked", Value: false}}
	switch {
	case handle != "":
		q = append(q, bson.E{Key: "_id", Value: handle})
	case owner != "":
		q = append(q, bson.E{Key: "owner", Value: owner})
	default:
		return 0, nil
	}
	now := time.Now().UTC()
	res, err := c.UpdateMany(ctx, q, bson.D{{Key: "$set", Value: bson.D{{Key: "revoked", Value: true}, {Key: "revokedBy", Value: by}, {Key: "revokedAt", Value: now}}}})
	if err != nil {
		return 0, err
	}
	return res.ModifiedCount, nil
}

// RevokedOn returns revoked handles held by a replica.
func (r *Registry) RevokedOn(ctx context.Context, pod string) ([]string, error) {
	c, err := r.coll()
	if err != nil {
		return nil, err
	}
	cur, err := c.Find(ctx, bson.D{{Key: "pod", Value: pod}, {Key: "revoked", Value: true}}, options.Find().SetProjection(bson.D{{Key: "_id", Value: 1}}))
	if err != nil {
		return nil, err
	}
	var rows []struct {
		ID string `bson:"_id"`
	}
	if err := cur.All(ctx, &rows); err != nil {
		return nil, err
	}
	out := make([]string, len(rows))
	for i, x := range rows {
		out[i] = x.ID
	}
	return out, nil
}
