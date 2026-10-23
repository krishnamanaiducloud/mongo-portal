package audit

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
)

func TestRingBufferAndFilter(t *testing.T) {
	var buf bytes.Buffer
	l := New(slog.New(slog.NewJSONHandler(&buf, nil)), 3)
	for _, u := range []string{"a", "b", "a", "b"} {
		l.Record(context.Background(), Event{SSOUser: u, Owner: "sso:" + u, Action: "x", Outcome: Success})
	}
	all := l.Recent("", 10)
	if len(all) != 3 || all[0].SSOUser != "b" || all[2].SSOUser != "b" {
		t.Fatalf("recent: %+v", all)
	}
	if a := l.Recent("sso:a", 10); len(a) != 1 {
		t.Fatalf("filter: %+v", a)
	}
	if !strings.Contains(buf.String(), `"audit":true`) {
		t.Fatal("audit log line missing")
	}
}
