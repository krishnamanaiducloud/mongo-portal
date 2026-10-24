package store

import (
	"context"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

const cachesColl = "cache_invalidations"

// Invalidation is a request to drop or refresh portal caches on every
// replica. Replicas record what they applied.
type Invalidation struct {
	ID          bson.ObjectID `bson:"_id,omitempty" json:"id"`
	Caches      []string      `bson:"caches" json:"caches"`
	RequestedBy string        `bson:"requestedBy" json:"requestedBy"`
	Origin      string        `bson:"origin" json:"origin"`
	At          time.Time     `bson:"at" json:"at"`
	Applied     []Applied     `bson:"applied" json:"applied"`
}

// Applied is one replica's result of an invalidation.
type Applied struct {
	Pod    string    `bson:"pod" json:"pod"`
	At     time.Time `bson:"at" json:"at"`
	Errors []string  `bson:"errors,omitempty" json:"errors,omitempty"`
}

// Invalidations is the shared invalidation log.
type Invalidations struct{ s *Store }

// Invalidations returns the shared invalidation log.
func (s *Store) Invalidations() *Invalidations { return &Invalidations{s: s} }

// Publish records an invalidation (already applied on its origin).
func (v *Invalidations) Publish(ctx context.Context, inv Invalidation) (bson.ObjectID, error) {
	db, err := v.s.database()
	if err != nil {
		return bson.ObjectID{}, err
	}
	inv.ID = bson.NewObjectID()
	_, err = db.Collection(cachesColl).InsertOne(ctx, inv)
	return inv.ID, err
}

// Pending returns invalidations after since that pod has not applied.
func (v *Invalidations) Pending(ctx context.Context, pod string, since time.Time) ([]Invalidation, error) {
	db, err := v.s.database()
	if err != nil {
		return nil, err
	}
	cur, err := db.Collection(cachesColl).Find(ctx, bson.D{{Key: "at", Value: bson.D{{Key: "$gt", Value: since}}}, {Key: "applied.pod", Value: bson.D{{Key: "$ne", Value: pod}}}},
		options.Find().SetSort(bson.D{{Key: "at", Value: 1}}).SetLimit(100))
	if err != nil {
		return nil, err
	}
	var out []Invalidation
	err = cur.All(ctx, &out)
	return out, err
}

// Ack records that pod applied an invalidation.
func (v *Invalidations) Ack(ctx context.Context, id bson.ObjectID, a Applied) error {
	db, err := v.s.database()
	if err != nil {
		return err
	}
	_, err = db.Collection(cachesColl).UpdateOne(ctx, bson.D{{Key: "_id", Value: id}}, bson.D{{Key: "$push", Value: bson.D{{Key: "applied", Value: a}}}})
	return err
}

// Recent returns the latest invalidations, newest first.
func (v *Invalidations) Recent(ctx context.Context, limit int64) ([]Invalidation, error) {
	db, err := v.s.database()
	if err != nil {
		return nil, err
	}
	cur, err := db.Collection(cachesColl).Find(ctx, bson.D{}, options.Find().SetSort(bson.D{{Key: "at", Value: -1}}).SetLimit(limit))
	if err != nil {
		return nil, err
	}
	out := []Invalidation{}
	err = cur.All(ctx, &out)
	return out, err
}
