package api

import (
	"slices"
	"strings"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// waitFields are $project expressions that classify operations which wait
// by design. Only the command name, the name of the first pipeline stage
// and cursor flags are read, never command or query values.
var waitFields = bson.D{
	{Key: "cmdName", Value: bson.D{{Key: "$let", Value: bson.D{
		{Key: "vars", Value: bson.D{{Key: "k", Value: bson.D{{Key: "$objectToArray", Value: bson.D{{Key: "$ifNull", Value: bson.A{"$command", bson.D{}}}}}}}}},
		{Key: "in", Value: bson.D{{Key: "$arrayElemAt", Value: bson.A{"$$k.k", 0}}}},
	}}}},
	// The first stage of the operation's pipeline, or for a getMore of the
	// pipeline that opened the cursor (a change stream, for example).
	{Key: "firstStage", Value: bson.D{{Key: "$let", Value: bson.D{
		{Key: "vars", Value: bson.D{{Key: "s", Value: bson.D{{Key: "$objectToArray", Value: bson.D{{Key: "$ifNull", Value: bson.A{
			bson.D{{Key: "$arrayElemAt", Value: bson.A{bson.D{{Key: "$ifNull", Value: bson.A{"$command.pipeline",
				bson.D{{Key: "$ifNull", Value: bson.A{"$cursor.originatingCommand.pipeline", bson.A{}}}}}}}, 0}}}, bson.D{}}}}}}}}},
		{Key: "in", Value: bson.D{{Key: "$arrayElemAt", Value: bson.A{"$$s.k", 0}}}},
	}}}},
	{Key: "awaitable", Value: bson.D{{Key: "$gt", Value: bson.A{"$command.maxAwaitTimeMS", nil}}}},
	{Key: "tailable", Value: "$cursor.tailable"},
	{Key: "awaitData", Value: "$cursor.awaitData"},
}

// expectedWait explains why a long-running operation is normal, or returns
// "" for an operation that may really be slow.
func expectedWait(d bson.M, ignoreApps []string) string {
	cmd, stage, app := mstr(d, "cmdName"), mstr(d, "firstStage"), mstr(d, "appName")
	switch {
	case (cmd == "hello" || strings.EqualFold(cmd, "isMaster")) && mbool(d, "awaitable"):
		return "awaitable hello: driver topology monitoring waits for changes"
	case stage == "$changeStream":
		return "change stream waiting for events"
	case mbool(d, "awaitData") || mbool(d, "tailable"):
		return "tailable cursor waiting for new data"
	case mstr(d, "ns") == "local.oplog.rs":
		return "oplog tailing (replication, backup or change streams)"
	case slices.ContainsFunc(ignoreApps, func(p string) bool { return p != "" && strings.HasPrefix(app, p) }):
		return "expected long-running application (monitoring.slowOperationIgnoreApps)"
	}
	return ""
}

// projectWith adds the wait classification fields to a $project document.
func projectWith(fields bson.D) bson.D {
	return append(slices.Clone(fields), waitFields...)
}
