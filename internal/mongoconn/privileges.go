package mongoconn

import (
	"context"
	"slices"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

// ConnectionStatus is the subset of the connectionStatus command response the
// portal uses. It is used for display and UI hints only; MongoDB enforces
// permissions on every operation.
type ConnectionStatus struct {
	AuthInfo struct {
		AuthenticatedUsers []UserRef   `bson:"authenticatedUsers" json:"authenticatedUsers"`
		AuthenticatedRoles []RoleRef   `bson:"authenticatedUserRoles" json:"authenticatedUserRoles"`
		Privileges         []Privilege `bson:"authenticatedUserPrivileges" json:"authenticatedUserPrivileges"`
	} `bson:"authInfo" json:"authInfo"`
}

type UserRef struct {
	User string `bson:"user" json:"user"`
	DB   string `bson:"db" json:"db"`
}

type RoleRef struct {
	Role string `bson:"role" json:"role"`
	DB   string `bson:"db" json:"db"`
}

type Privilege struct {
	Resource Resource `bson:"resource" json:"resource"`
	Actions  []string `bson:"actions" json:"actions"`
}

type Resource struct {
	DB          *string `bson:"db,omitempty" json:"db,omitempty"`
	Collection  *string `bson:"collection,omitempty" json:"collection,omitempty"`
	Cluster     bool    `bson:"cluster,omitempty" json:"cluster,omitempty"`
	AnyResource bool    `bson:"anyResource,omitempty" json:"anyResource,omitempty"`
}

// GetConnectionStatus runs connectionStatus with privileges.
func GetConnectionStatus(ctx context.Context, c *mongo.Client) (*ConnectionStatus, error) {
	var st ConnectionStatus
	err := c.Database("admin").RunCommand(ctx, bson.D{{Key: "connectionStatus", Value: 1}, {Key: "showPrivileges", Value: true}}).Decode(&st)
	if err != nil {
		return nil, err
	}
	return &st, nil
}

// HasUser reports whether user@db is authenticated on this connection.
func (s *ConnectionStatus) HasUser(user, db string) bool {
	for _, u := range s.AuthInfo.AuthenticatedUsers {
		if u.User == user && u.DB == db {
			return true
		}
	}
	return false
}

// Capabilities summarises what the MongoDB user may do on a namespace.
type Capabilities struct {
	Find             bool `json:"find"`
	Insert           bool `json:"insert"`
	Update           bool `json:"update"`
	Remove           bool `json:"remove"`
	CreateIndex      bool `json:"createIndex"`
	DropIndex        bool `json:"dropIndex"`
	CreateCollection bool `json:"createCollection"`
	DropCollection   bool `json:"dropCollection"`
	ListCollections  bool `json:"listCollections"`
	ListIndexes      bool `json:"listIndexes"`
	DBStats          bool `json:"dbStats"`
	CollStats        bool `json:"collStats"`
}

// CapabilitiesFor evaluates privileges for db (and optionally coll).
// Collection "" asks about database-level actions.
func (s *ConnectionStatus) CapabilitiesFor(db, coll string) Capabilities {
	has := func(action string) bool {
		for _, p := range s.AuthInfo.Privileges {
			if p.Resource.matches(db, coll) && slices.Contains(p.Actions, action) {
				return true
			}
		}
		return false
	}
	return Capabilities{
		Find:             has("find"),
		Insert:           has("insert"),
		Update:           has("update"),
		Remove:           has("remove"),
		CreateIndex:      has("createIndex"),
		DropIndex:        has("dropIndex"),
		CreateCollection: has("createCollection") || has("insert"),
		DropCollection:   has("dropCollection"),
		ListCollections:  has("listCollections"),
		ListIndexes:      has("listIndexes"),
		DBStats:          has("dbStats"),
		CollStats:        has("collStats"),
	}
}

// matches implements MongoDB resource document semantics for a
// non-system namespace. An empty string in a resource is a wildcard.
func (r Resource) matches(db, coll string) bool {
	if r.AnyResource {
		return true
	}
	if r.Cluster || r.DB == nil {
		return false
	}
	if *r.DB != "" && *r.DB != db {
		return false
	}
	if r.Collection == nil {
		return false
	}
	if coll == "" {
		// Database-level question: a collection-scoped grant on a specific
		// collection does not cover database-level actions.
		return *r.Collection == ""
	}
	return *r.Collection == "" || *r.Collection == coll
}

// Databases lists database names that privileges explicitly reference. It is
// used when listDatabases is not permitted for the user.
func (s *ConnectionStatus) Databases() []string {
	var out []string
	for _, p := range s.AuthInfo.Privileges {
		if p.Resource.DB != nil && *p.Resource.DB != "" && !slices.Contains(out, *p.Resource.DB) {
			out = append(out, *p.Resource.DB)
		}
	}
	slices.Sort(out)
	return out
}
