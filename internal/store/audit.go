package store

import (
	"context"
	"errors"
	"regexp"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/krishnamanaiducloud/mongo-portal/internal/audit"
)

// AuditSink stores audit events in the store's audit collection.
type AuditSink struct{ s *Store }

// Audit returns the audit sink.
func (s *Store) Audit() *AuditSink { return &AuditSink{s: s} }

// Write inserts a batch. Events already stored (same id) are skipped, so a
// retried batch is not duplicated.
func (a *AuditSink) Write(ctx context.Context, events []audit.Event) error {
	db, err := a.s.database()
	if err != nil {
		return err
	}
	docs := make([]any, len(events))
	for i := range events {
		docs[i] = events[i]
	}
	_, err = db.Collection(a.s.audit.Collection).InsertMany(ctx, docs, options.InsertMany().SetOrdered(false))
	var bwe mongo.BulkWriteException
	if errors.As(err, &bwe) && bwe.WriteConcernError == nil {
		for _, we := range bwe.WriteErrors {
			if we.Code != 11000 {
				return err
			}
		}
		return nil
	}
	return err
}

// Query returns events newest first.
func (a *AuditSink) Query(ctx context.Context, f audit.Filter) ([]audit.Event, error) {
	db, err := a.s.database()
	if err != nil {
		return nil, err
	}
	q := bson.D{}
	eq := func(k, v string) {
		if v != "" {
			q = append(q, bson.E{Key: k, Value: v})
		}
	}
	eq("owner", f.Owner)
	eq("action", f.Action)
	eq("outcome", f.Outcome)
	eq("profile", f.Profile)
	eq("database", f.Database)
	eq("collection", f.Collection)
	tm := bson.D{}
	if !f.From.IsZero() {
		tm = append(tm, bson.E{Key: "$gte", Value: f.From})
	}
	if !f.To.IsZero() {
		tm = append(tm, bson.E{Key: "$lt", Value: f.To})
	}
	if len(tm) > 0 {
		q = append(q, bson.E{Key: "time", Value: tm})
	}
	var and bson.A
	if !f.Before.IsZero() {
		and = append(and, bson.D{{Key: "$or", Value: bson.A{
			bson.D{{Key: "time", Value: bson.D{{Key: "$lt", Value: f.Before}}}},
			bson.D{{Key: "time", Value: f.Before}, {Key: "_id", Value: bson.D{{Key: "$lt", Value: f.BeforeID}}}},
		}}})
	}
	if f.User != "" {
		re := bson.Regex{Pattern: regexp.QuoteMeta(f.User), Options: "i"}
		and = append(and, bson.D{{Key: "$or", Value: bson.A{bson.D{{Key: "ssoUser", Value: re}}, bson.D{{Key: "mongoUser", Value: re}}}}})
	}
	if f.Text != "" {
		re := bson.Regex{Pattern: regexp.QuoteMeta(f.Text), Options: "i"}
		and = append(and, bson.D{{Key: "$or", Value: bson.A{bson.D{{Key: "action", Value: re}}, bson.D{{Key: "target", Value: re}}, bson.D{{Key: "reason", Value: re}}}}})
	}
	if len(and) > 0 {
		q = append(q, bson.E{Key: "$and", Value: and})
	}
	limit := int64(f.Limit)
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	cur, err := db.Collection(a.s.audit.Collection).Find(ctx, q,
		options.Find().SetSort(bson.D{{Key: "time", Value: -1}, {Key: "_id", Value: -1}}).SetLimit(limit))
	if err != nil {
		return nil, err
	}
	var out []audit.Event
	if err := cur.All(ctx, &out); err != nil {
		return nil, err
	}
	if out == nil {
		out = []audit.Event{}
	}
	return out, nil
}

// Chain returns stored events of one replica in sequence order (for chain
// verification), starting at sequence from.
func (a *AuditSink) Chain(ctx context.Context, pod string, from int64, limit int64) ([]audit.Event, error) {
	db, err := a.s.database()
	if err != nil {
		return nil, err
	}
	cur, err := db.Collection(a.s.audit.Collection).Find(ctx, bson.D{{Key: "pod", Value: pod}, {Key: "seq", Value: bson.D{{Key: "$gte", Value: from}}}},
		options.Find().SetSort(bson.D{{Key: "seq", Value: 1}}).SetLimit(limit))
	if err != nil {
		return nil, err
	}
	var out []audit.Event
	err = cur.All(ctx, &out)
	return out, err
}
