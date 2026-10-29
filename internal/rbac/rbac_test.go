package rbac

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func mustParse(t *testing.T, csv, def string) *Policy {
	t.Helper()
	p, err := Parse(csv, def)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestBuiltinRoles(t *testing.T) {
	p := mustParse(t, `
g, devs, role:readonly
g, editors, role:editor
g, sres, role:admin
`, "")
	cases := []struct {
		subj []string
		res  Resource
		act  Action
		obj  string
		want bool
	}{
		{[]string{"devs"}, Documents, Get, "app/orders", true},
		{[]string{"devs"}, Documents, Create, "app/orders", false},
		{[]string{"devs"}, Shell, Use, "*", true},
		{[]string{"devs"}, Shell, Admin, "admin", false},
		{[]string{"devs"}, Audit, Get, "self", true},
		{[]string{"devs"}, Audit, Get, "all", false},
		{[]string{"editors"}, Documents, Delete, "app/orders", true},
		{[]string{"editors"}, Collections, Delete, "app/orders", false},
		{[]string{"editors"}, Databases, Delete, "app", false},
		{[]string{"sres"}, Databases, Delete, "app", true},
		{[]string{"sres"}, Audit, Get, "all", true},
		{[]string{"nobody"}, Documents, Get, "app/orders", false},
	}
	for _, c := range cases {
		if got := p.Allowed(c.subj, c.res, c.act, c.obj); got != c.want {
			t.Errorf("%v %s %s %s = %v, want %v", c.subj, c.res, c.act, c.obj, got, c.want)
		}
	}
}

func TestDefaultRoleAndInheritance(t *testing.T) {
	p := mustParse(t, "g, role:team, role:editor\ng, team-a, role:team\n", RoleReadOnly)
	if !p.Allowed([]string{"anyone"}, Documents, Get, "x/y") {
		t.Error("default role should allow reads")
	}
	if p.Allowed([]string{"anyone"}, Documents, Update, "x/y") {
		t.Error("default role must not allow writes")
	}
	if !p.Allowed([]string{"team-a"}, Documents, Update, "x/y") {
		t.Error("inherited editor role should allow updates")
	}
	roles := p.Roles([]string{"team-a"})
	for _, r := range []string{"role:team", RoleEditor, RoleReadOnly} {
		if !slices.Contains(roles, r) {
			t.Errorf("roles %v missing %s", roles, r)
		}
	}
}

// The default role is only for unmapped users: a mapping restricts.
func TestDefaultRoleOnlyForUnmappedUsers(t *testing.T) {
	p := mustParse(t, "g, devs, role:readonly\n", RoleMongoDB)
	if !p.Allowed([]string{"stranger"}, Documents, Delete, "app/x") {
		t.Error("unmapped users follow their MongoDB privileges")
	}
	if p.Allowed([]string{"stranger"}, Audit, Get, "all") {
		t.Error("role:mongodb must not grant other users' audit events")
	}
	if p.Allowed([]string{"alice", "devs"}, Documents, Delete, "app/x") {
		t.Error("a mapped read-only group must not inherit the default role")
	}
	if got := p.Roles([]string{"alice", "devs"}); !slices.Equal(got, []string{RoleReadOnly}) {
		t.Errorf("mapped roles: %v", got)
	}
}

// Portal administration and data access are separate: platform admins and
// auditors get no data, database admins get no portal administration.
func TestAdministrativeRolesAreSeparated(t *testing.T) {
	p := mustParse(t, `
g, platform, role:platform-admin
g, auditors, role:auditor
g, ops, role:monitoring
g, dbas, role:dbadmin
`, "")
	cases := []struct {
		subj string
		res  Resource
		act  Action
		obj  string
		want bool
	}{
		{"platform", Sessions, Delete, "all", true},
		{"platform", Settings, Get, "*", true},
		{"platform", Audit, Get, "all", true},
		{"platform", Documents, Get, "app/orders", false},
		{"platform", Databases, Delete, "app", false},
		{"auditors", Audit, Get, "all", true},
		{"auditors", Sessions, Get, "all", true},
		{"auditors", Sessions, Delete, "all", false},
		{"auditors", Export, Create, "app/orders", false},
		{"ops", Monitoring, Get, "prod", true},
		{"ops", Operations, Get, "prod", true},
		{"ops", Operations, Kill, "prod", false},
		{"ops", Documents, Get, "app/orders", false},
		{"dbas", Databases, Delete, "app", true},
		{"dbas", Operations, Kill, "prod", true},
		{"dbas", Import, Create, "app/orders", true},
		{"dbas", Sessions, Delete, "all", false},
		{"dbas", Audit, Get, "all", false},
	}
	for _, c := range cases {
		if got := p.Allowed([]string{c.subj}, c.res, c.act, c.obj); got != c.want {
			t.Errorf("%s %s %s %s = %v, want %v", c.subj, c.res, c.act, c.obj, got, c.want)
		}
	}
	// Bulk import and export are for users who may write: read-only users
	// may do neither, editors may do both.
	ro := mustParse(t, "g, devs, role:readonly\ng, writers, role:editor\n", "")
	if ro.Allowed([]string{"devs"}, Export, Create, "app/x") || ro.Allowed([]string{"devs"}, Import, Create, "app/x") {
		t.Error("readonly must neither export nor import")
	}
	if !ro.Allowed([]string{"writers"}, Export, Create, "app/x") || !ro.Allowed([]string{"writers"}, Import, Create, "app/x") {
		t.Error("editor must export and import")
	}
}

// A profile-scoped rule applies only in sessions of matching profiles.
func TestProfileScopedRules(t *testing.T) {
	p := mustParse(t, `
p, role:dev-writer, documents, *, *, allow, dev-*
p, role:dev-writer, documents, get, *, allow
p, role:no-prod-delete, documents, delete, *, deny, prod
g, devs, role:dev-writer
g, devs, role:no-prod-delete
`, "")
	s := []string{"devs"}
	if !p.AllowedIn(s, "dev-eu", Documents, Update, "app/x") {
		t.Error("profile-scoped allow should apply to dev-eu")
	}
	if p.AllowedIn(s, "prod", Documents, Update, "app/x") || p.AllowedIn(s, "", Documents, Update, "app/x") {
		t.Error("profile-scoped allow leaked to another or no profile")
	}
	if !p.AllowedIn(s, "prod", Documents, Get, "app/x") {
		t.Error("unscoped rule must apply in every profile")
	}
	if !p.PossibleIn(s, "dev-eu", Documents, Delete) || p.PossibleIn(s, "prod", Documents, Delete) {
		t.Error("PossibleIn must follow profile scope")
	}
	if _, err := Parse("p, role:x, documents, get, *, allow, ", ""); err == nil {
		t.Error("empty profile field must be rejected")
	}
	if _, err := Parse("p, role:x, operations, kill, *, allow, prod, extra", ""); err == nil {
		t.Error("too many fields must be rejected")
	}
}

func TestNamespaceScopedRulesAndDeny(t *testing.T) {
	p := mustParse(t, `
p, role:orders-rw, documents, *, app/orders*, allow
p, role:orders-rw, documents, delete, app/orders_archive, deny
g, group:payments, role:orders-rw
`, RoleReadOnly)
	s := []string{"group:payments"}
	if !p.Allowed(s, Documents, Update, "app/orders") || !p.Allowed(s, Documents, Create, "app/orders_2024") {
		t.Error("scoped allow failed")
	}
	if p.Allowed(s, Documents, Update, "app/customers") {
		t.Error("rule leaked to another collection")
	}
	if p.Allowed(s, Documents, Delete, "app/orders_archive") {
		t.Error("deny must override allow")
	}
	if !p.Possible(s, Documents, Delete) {
		t.Error("Possible should report a scoped grant")
	}
	if p.Possible([]string{"x"}, Documents, Delete) {
		t.Error("Possible without grant")
	}
}

func TestParseErrors(t *testing.T) {
	bad := []string{
		"p, admin, documents, get, *",         // role prefix
		"p, role:x, nothing, get, *",          // resource
		"p, role:x, documents, use, *",        // action
		"p, role:x, documents, get, *, maybe", // effect
		"p, role:x, documents, get",           // arity
		"g, devs",                             // arity
		"g, devs, admins",                     // role prefix
		"x, y, z",                             // kind
		"p, role:x, documents, get, , allow",  // empty object
	}
	for _, line := range bad {
		if _, err := Parse(line, ""); err == nil {
			t.Errorf("expected error for %q", line)
		}
	}
	if _, err := Parse("", "readonly"); err == nil {
		t.Error("default role without role: prefix must fail")
	}
}

func TestGlob(t *testing.T) {
	cases := []struct {
		p, s string
		want bool
	}{
		{"*", "a/b", true},
		{"app/*", "app/orders", true},
		{"app/*", "apps/orders", false},
		{"app*", "app/orders", true},
		{"a?c", "abc", true},
		{"a?c", "abbc", false},
		{"*/logs", "x/logs", true},
		{"*/logs", "x/logs2", false},
		{"", "", true},
		{"a*b*c", "aXXbYYc", true},
	}
	for _, c := range cases {
		if got := Glob(c.p, c.s); got != c.want {
			t.Errorf("Glob(%q,%q)=%v want %v", c.p, c.s, got, c.want)
		}
	}
}

func TestStoreReloadKeepsLastGoodPolicy(t *testing.T) {
	dir := t.TempDir()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	write := func(name, v string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(v), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// Missing directory contents: built-in policy with the configured default.
	s, err := NewStore(Source{Dir: dir, DefaultRole: RoleReadOnly}, log)
	if err != nil {
		t.Fatal(err)
	}
	if st := s.Status(); st.Source != "built-in" || st.DefaultRole != RoleReadOnly {
		t.Fatalf("status %+v", st)
	}

	write("policy.csv", "g, sres, role:admin\n")
	write("policy.default", "")
	s.reload(false)
	if !s.Policy().Allowed([]string{"sres"}, Databases, Delete, "x") || s.Status().Source != "file" {
		t.Fatalf("file policy not applied: %+v", s.Status())
	}
	if s.Policy().Allowed([]string{"other"}, Documents, Get, "x/y") {
		t.Fatal("empty policy.default should remove the default role")
	}

	write("policy.csv", "this is not a policy\n")
	s.reload(false)
	if st := s.Status(); st.Error == "" {
		t.Fatal("expected error status")
	}
	if !s.Policy().Allowed([]string{"sres"}, Databases, Delete, "x") {
		t.Fatal("previous policy must stay active after a bad update")
	}
}

func TestStoreRejectsInvalidInline(t *testing.T) {
	if _, err := NewStore(Source{Inline: "p, broken"}, slog.New(slog.NewTextHandler(io.Discard, nil))); err == nil {
		t.Fatal("invalid inline policy must be rejected")
	}
}
