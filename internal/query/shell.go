package query

import (
	"slices"
	"strings"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// Value validates an arbitrary value (document, array or scalar) for
// server-side JavaScript and size limits. Used for update documents,
// replacement documents, command bodies and index options.
func Value(v any) error {
	w := &walker{}
	return w.value(v, 0)
}

// updateStages are allowed in pipeline-style updates.
var updateStages = []string{"$addFields", "$set", "$project", "$unset", "$replaceRoot", "$replaceWith"}

// Update validates an update specification: either an update-operator
// document ({"$set": ...}) or an update pipeline (array of stages).
func Update(u any) error {
	switch t := u.(type) {
	case bson.D:
		if len(t) == 0 {
			return errf("update document must not be empty")
		}
		for _, e := range t {
			if !strings.HasPrefix(e.Key, "$") {
				return errf("update document must contain only update operators (use replaceOne to replace a document)")
			}
		}
		return Value(t)
	case bson.A:
		if len(t) == 0 || len(t) > maxPipelineLen {
			return errf("update pipeline must have between 1 and %d stages", maxPipelineLen)
		}
		for i, s := range t {
			d, ok := s.(bson.D)
			if !ok || len(d) != 1 || !slices.Contains(updateStages, d[0].Key) {
				return errf("update pipeline stage %d is not permitted", i)
			}
		}
		return Value(t)
	}
	return errf("update must be a document or a pipeline")
}

// Replacement validates a replacement document.
func Replacement(d bson.D) error {
	for _, e := range d {
		if strings.HasPrefix(e.Key, "$") {
			return errf("replacement document must not contain update operators")
		}
	}
	return Value(d)
}

// CommandClass is the authorization class of a database command.
type CommandClass int

const (
	// CommandDenied is never forwarded.
	CommandDenied CommandClass = iota
	// CommandRead may be run by any portal role.
	CommandRead
	// CommandAdmin requires the SRE portal role.
	CommandAdmin
)

// readCommands are informational commands any role may run through
// db.runCommand(). MongoDB still enforces the user's privileges.
var readCommands = map[string]bool{
	"ping": true, "hello": true, "isMaster": true, "ismaster": true,
	"buildInfo": true, "buildinfo": true, "connectionStatus": true,
	"dbStats": true, "dbstats": true, "collStats": true, "collstats": true,
	"dataSize": true, "datasize": true, "listCollections": true, "listIndexes": true,
	"count": true, "distinct": true, "serverStatus": true, "hostInfo": true,
	"replSetGetStatus": true, "replSetGetConfig": true, "getLog": true,
	"getCmdLineOpts": true, "getParameter": true, "listCommands": true,
	"usersInfo": true, "rolesInfo": true, "top": true, "whatsmyuri": true,
	"connPoolStats": true, "listShards": true, "balancerStatus": true,
	"getDefaultRWConcern": true, "isdbgrid": true, "features": true,
	"getShardMap": true, "lockInfo": true, "explain": true, "profile": true,
}

// adminCommands are administrative commands limited to the SRE role.
var adminCommands = map[string]bool{
	"collMod": true, "create": true, "createIndexes": true, "dropIndexes": true,
	"currentOp": true, "killOp": true, "validate": true, "renameCollection": true,
}

// ClassifyCommand returns the authorization class of a command document.
func ClassifyCommand(cmd bson.D) (string, CommandClass) {
	if len(cmd) == 0 {
		return "", CommandDenied
	}
	name := cmd[0].Key
	if name == "profile" {
		// Reading the profiler level is informational; changing it is admin.
		if n := toFloat(cmd[0].Value); n == -1 {
			return name, CommandRead
		}
		return name, CommandAdmin
	}
	if readCommands[name] {
		return name, CommandRead
	}
	if adminCommands[name] {
		return name, CommandAdmin
	}
	return name, CommandDenied
}

// Command validates a command body: no server-side JavaScript anywhere and,
// for commands that embed queries or pipelines, the same rules as helpers.
func Command(cmd bson.D, p Policy) error {
	if err := Value(cmd); err != nil {
		return err
	}
	name := cmd[0].Key
	switch name {
	case "explain":
		inner, ok := cmd[0].Value.(bson.D)
		if !ok || len(inner) == 0 {
			return errf("explain requires a command document")
		}
		switch inner[0].Key {
		case "find", "count", "distinct":
		case "aggregate":
			for _, e := range inner {
				if e.Key == "pipeline" {
					ps, err := toPipeline(e.Value)
					if err != nil {
						return err
					}
					if err := Pipeline(ps, Policy{}); err != nil {
						return err
					}
				}
			}
		default:
			return errf("explain of %q is not permitted", inner[0].Key)
		}
	case "collMod", "create":
		for _, e := range cmd {
			if e.Key == "pipeline" || e.Key == "viewOn" {
				// Views are defined by pipelines; validate them like aggregations.
				if ps, err := toPipeline(e.Value); err == nil {
					if err := Pipeline(ps, Policy{}); err != nil {
						return err
					}
				}
			}
		}
	case "renameCollection":
		// Only renames within one database are permitted.
		from, _ := cmd[0].Value.(string)
		var to string
		for _, e := range cmd {
			if e.Key == "to" {
				to, _ = e.Value.(string)
			}
		}
		fdb, _, ok1 := strings.Cut(from, ".")
		tdb, _, ok2 := strings.Cut(to, ".")
		if !ok1 || !ok2 || fdb != tdb {
			return errf("renameCollection is only permitted within the same database")
		}
	}
	return nil
}
