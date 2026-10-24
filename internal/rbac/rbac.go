// Package rbac implements role-based access control for the portal.
//
// A policy is a CSV document with two kinds of lines:
//
//	p, <role>, <resource>, <action>, <object>[, allow|deny[, <profile>]]
//	g, <subject>, <role>
//
// Roles are named "role:<name>". A subject is an SSO user or group name
// (matched as given), or a qualified name: "user:<name>",
// "group:<name>" or "mongodb:<user>[@<authSource>]" for sessions opened with
// MongoDB credentials only. A "g" line may also make one role inherit
// another. Objects are glob patterns ('*' matches any text, '?' one
// character) over "<database>" or "<database>/<collection>" (data resources),
// a profile name (server, monitoring, operations) or "self"/"all" (audit,
// sessions). The optional last field limits a rule to connection profiles
// matching a glob (default "*", every profile); profile-scoped rules apply
// only to requests made in a MongoDB session of a matching profile.
//
// A request is allowed when at least one rule of the subject's roles allows
// it and none denies it. Portal RBAC only narrows access: MongoDB still
// authorizes every operation with the user's own credentials.
package rbac

import (
	"bufio"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// Resource is a kind of object the portal acts on.
type Resource string

// Action is an operation on a resource.
type Action string

const (
	Databases   Resource = "databases"
	Collections Resource = "collections"
	Documents   Resource = "documents"
	Indexes     Resource = "indexes"
	Shell       Resource = "shell"
	Server      Resource = "server"
	Audit       Resource = "audit"
	// Export and Import move data out of and into collections.
	Export Resource = "export"
	Import Resource = "import"
	// Monitoring is the deployment monitoring page and API (object: profile).
	Monitoring Resource = "monitoring"
	// Operations are running MongoDB operations (object: profile); kill ends
	// one with killOp.
	Operations Resource = "operations"
	// Sessions are portal sessions (object: "self" or "all").
	Sessions Resource = "sessions"
	// Settings is the effective portal configuration view (object: "*").
	Settings Resource = "settings"
)

const (
	Get    Action = "get"
	Create Action = "create"
	Update Action = "update"
	Delete Action = "delete"
	Use    Action = "use"   // shell: open the shell
	Admin  Action = "admin" // shell: administrative commands (currentOp, killOp, ...)
	Kill   Action = "kill"  // operations: end a running operation (killOp)
)

// Actions lists the actions valid for each resource.
var Actions = map[Resource][]Action{
	Databases:   {Get, Delete},
	Collections: {Get, Create, Update, Delete},
	Documents:   {Get, Create, Update, Delete},
	Indexes:     {Get, Create, Delete},
	Shell:       {Use, Admin},
	Server:      {Get},
	Audit:       {Get},
	Export:      {Create},
	Import:      {Create},
	Monitoring:  {Get},
	Operations:  {Get, Kill},
	Sessions:    {Get, Delete},
	Settings:    {Get},
}

// Built-in role names.
const (
	RoleReadOnly = "role:readonly"
	RoleEditor   = "role:editor"
	RoleAdmin    = "role:admin"
	// RoleMongoDB follows the user's MongoDB privileges: the portal offers
	// every data operation and MongoDB decides. It differs from role:admin
	// only in portal-level permissions (other users' audit events).
	RoleMongoDB = "role:mongodb"
	// RoleAuditor reads every audit event and the session inventory, no data.
	RoleAuditor = "role:auditor"
	// RoleMonitoring sees monitoring and running operations, no data.
	RoleMonitoring = "role:monitoring"
	// RolePlatformAdmin administers the portal (sessions, audit, settings,
	// monitoring); it grants no data access.
	RolePlatformAdmin = "role:platform-admin"
	// RoleDBAdmin manages data, indexes and collections and may end
	// operations, without portal administration.
	RoleDBAdmin = "role:dbadmin"
)

// BuiltinPolicy defines the built-in roles. Policies may add rules to them
// or define their own roles.
const BuiltinPolicy = `
p, role:readonly, databases, get, *, allow
p, role:readonly, collections, get, *, allow
p, role:readonly, documents, get, *, allow
p, role:readonly, indexes, get, *, allow
p, role:readonly, shell, use, *, allow
p, role:readonly, server, get, *, allow
p, role:readonly, audit, get, self, allow
p, role:readonly, export, create, *, allow
p, role:readonly, monitoring, get, *, allow
p, role:readonly, sessions, get, self, allow
p, role:readonly, sessions, delete, self, allow

g, role:editor, role:readonly
p, role:editor, documents, create, *, allow
p, role:editor, documents, update, *, allow
p, role:editor, documents, delete, *, allow
p, role:editor, indexes, create, *, allow
p, role:editor, indexes, delete, *, allow
p, role:editor, collections, create, *, allow
p, role:editor, import, create, *, allow

p, role:admin, *, *, *, allow

p, role:mongodb, databases, *, *, allow
p, role:mongodb, collections, *, *, allow
p, role:mongodb, documents, *, *, allow
p, role:mongodb, indexes, *, *, allow
p, role:mongodb, shell, *, *, allow
p, role:mongodb, server, get, *, allow
p, role:mongodb, audit, get, self, allow
p, role:mongodb, export, create, *, allow
p, role:mongodb, import, create, *, allow
p, role:mongodb, monitoring, get, *, allow
p, role:mongodb, operations, *, *, allow
p, role:mongodb, sessions, get, self, allow
p, role:mongodb, sessions, delete, self, allow

p, role:monitoring, server, get, *, allow
p, role:monitoring, monitoring, get, *, allow
p, role:monitoring, operations, get, *, allow
p, role:monitoring, sessions, get, self, allow
p, role:monitoring, sessions, delete, self, allow

g, role:auditor, role:monitoring
p, role:auditor, audit, get, *, allow
p, role:auditor, sessions, get, all, allow

g, role:platform-admin, role:auditor
p, role:platform-admin, sessions, delete, all, allow
p, role:platform-admin, settings, get, *, allow

g, role:dbadmin, role:editor
p, role:dbadmin, databases, *, *, allow
p, role:dbadmin, collections, *, *, allow
p, role:dbadmin, shell, admin, *, allow
p, role:dbadmin, operations, *, *, allow
`

// Rule is one "p" line.
type Rule struct {
	Role     string `json:"role"`
	Resource string `json:"resource"`
	Action   string `json:"action"`
	Object   string `json:"object"`
	Effect   string `json:"effect"`
	// Profile limits the rule to connection profiles matching this glob.
	Profile string `json:"profile"`
}

// Policy is a parsed, immutable policy.
type Policy struct {
	rules       map[string][]Rule   // role -> rules
	grants      map[string][]string // subject or role -> roles
	defaultRole string
}

// Parse builds a policy from the built-in roles followed by csv.
// defaultRole applies to principals no "g" line maps; "" grants nothing.
func Parse(csv, defaultRole string) (*Policy, error) {
	p := &Policy{rules: map[string][]Rule{}, grants: map[string][]string{}, defaultRole: strings.TrimSpace(defaultRole)}
	if err := p.add(BuiltinPolicy, "built-in policy"); err != nil {
		return nil, err
	}
	if err := p.add(csv, "policy"); err != nil {
		return nil, err
	}
	if p.defaultRole != "" && !strings.HasPrefix(p.defaultRole, "role:") {
		return nil, fmt.Errorf("default role %q must start with \"role:\"", p.defaultRole)
	}
	return p, nil
}

func (p *Policy) add(csv, name string) error {
	var errs []error
	sc := bufio.NewScanner(strings.NewReader(csv))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, ",")
		for i := range f {
			f[i] = strings.TrimSpace(f[i])
		}
		if err := p.addLine(f); err != nil {
			errs = append(errs, fmt.Errorf("%s line %d: %w", name, n, err))
		}
	}
	if err := sc.Err(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func (p *Policy) addLine(f []string) error {
	switch f[0] {
	case "p":
		if len(f) < 5 || len(f) > 7 {
			return errors.New(`"p" lines need: p, role, resource, action, object[, allow|deny[, profile]]`)
		}
		r := Rule{Role: f[1], Resource: f[2], Action: f[3], Object: f[4], Effect: "allow", Profile: "*"}
		if len(f) >= 6 {
			r.Effect = strings.ToLower(f[5])
		}
		if len(f) == 7 {
			r.Profile = f[6]
			if r.Profile == "" {
				return errors.New("profile must not be empty (use * for every profile)")
			}
		}
		if !strings.HasPrefix(r.Role, "role:") || len(r.Role) == len("role:") {
			return fmt.Errorf("role %q must be named role:<name>", r.Role)
		}
		if r.Effect != "allow" && r.Effect != "deny" {
			return fmt.Errorf("effect %q must be allow or deny", r.Effect)
		}
		if r.Resource != "*" {
			acts, ok := Actions[Resource(r.Resource)]
			if !ok {
				return fmt.Errorf("unknown resource %q", r.Resource)
			}
			if r.Action != "*" && !slices.Contains(acts, Action(r.Action)) {
				return fmt.Errorf("action %q is not valid for %s", r.Action, r.Resource)
			}
		}
		if r.Object == "" {
			return errors.New("object must not be empty (use * for all)")
		}
		p.rules[r.Role] = append(p.rules[r.Role], r)
	case "g":
		if len(f) != 3 {
			return errors.New(`"g" lines need: g, subject, role`)
		}
		if f[1] == "" || !strings.HasPrefix(f[2], "role:") {
			return fmt.Errorf("g line must map a subject to a role:<name>")
		}
		if !slices.Contains(p.grants[f[1]], f[2]) {
			p.grants[f[1]] = append(p.grants[f[1]], f[2])
		}
	default:
		return fmt.Errorf("line must start with p or g, not %q", f[0])
	}
	return nil
}

// DefaultRole returns the role of principals the policy does not map.
func (p *Policy) DefaultRole() string { return p.defaultRole }

// Roles returns the roles of subjects, including inherited roles, sorted.
// The default role applies only when no "g" line maps any of the subjects,
// so mapping a group (for example to role:readonly) really restricts it.
func (p *Policy) Roles(subjects []string) []string {
	seen := map[string]bool{}
	var walk func(string)
	walk = func(role string) {
		if seen[role] {
			return
		}
		seen[role] = true
		for _, r := range p.grants[role] {
			walk(r)
		}
	}
	for _, s := range subjects {
		for _, r := range p.grants[s] {
			walk(r)
		}
	}
	if len(seen) == 0 && p.defaultRole != "" {
		walk(p.defaultRole)
	}
	out := make([]string, 0, len(seen))
	for r := range seen {
		out = append(out, r)
	}
	slices.Sort(out)
	return out
}

// DirectRoles returns the roles granted to subjects by "g" lines (without
// inheritance or the default role), sorted. Used to explain decisions.
func (p *Policy) DirectRoles(subjects []string) []string {
	var out []string
	for _, s := range subjects {
		for _, r := range p.grants[s] {
			if !slices.Contains(out, r) {
				out = append(out, r)
			}
		}
	}
	slices.Sort(out)
	return out
}

// Allowed reports whether subjects may perform action on resource/object
// outside a connection profile (profile-scoped rules do not apply).
func (p *Policy) Allowed(subjects []string, res Resource, act Action, object string) bool {
	return p.AllowedIn(subjects, "", res, act, object)
}

// AllowedIn reports whether subjects may perform action on resource/object
// in a session of the given connection profile ("" for none).
func (p *Policy) AllowedIn(subjects []string, profile string, res Resource, act Action, object string) bool {
	allowed := false
	for _, role := range p.Roles(subjects) {
		for _, r := range p.rules[role] {
			if !match(r.Resource, string(res)) || !match(r.Action, string(act)) || !Glob(r.Object, object) || !profileMatch(r.Profile, profile) {
				continue
			}
			if r.Effect == "deny" {
				return false
			}
			allowed = true
		}
	}
	return allowed
}

// Possible reports whether any allow rule of subjects grants action on
// resource for some object. It is a UI hint for global controls; requests
// are always checked with Allowed against the concrete object.
func (p *Policy) Possible(subjects []string, res Resource, act Action) bool {
	return p.PossibleIn(subjects, "", res, act)
}

// PossibleIn is Possible within a session of the given profile.
func (p *Policy) PossibleIn(subjects []string, profile string, res Resource, act Action) bool {
	for _, role := range p.Roles(subjects) {
		for _, r := range p.rules[role] {
			if r.Effect == "allow" && match(r.Resource, string(res)) && match(r.Action, string(act)) && profileMatch(r.Profile, profile) {
				if !p.deniedEverywhere(subjects, profile, res, act) {
					return true
				}
			}
		}
	}
	return false
}

func (p *Policy) deniedEverywhere(subjects []string, profile string, res Resource, act Action) bool {
	for _, role := range p.Roles(subjects) {
		for _, r := range p.rules[role] {
			if r.Effect == "deny" && r.Object == "*" && match(r.Resource, string(res)) && match(r.Action, string(act)) && profileMatch(r.Profile, profile) {
				return true
			}
		}
	}
	return false
}

// RulesFor returns the rules that apply to subjects, grouped by role order.
func (p *Policy) RulesFor(subjects []string) []Rule {
	var out []Rule
	for _, role := range p.Roles(subjects) {
		out = append(out, p.rules[role]...)
	}
	return out
}

// Subjects lists every subject named in "g" lines (not roles). Used to keep
// only relevant groups in SSO cookies.
func (p *Policy) Subjects() []string {
	var out []string
	for s := range p.grants {
		if !strings.HasPrefix(s, "role:") {
			out = append(out, s)
		}
	}
	slices.Sort(out)
	return out
}

func match(pattern, v string) bool { return pattern == "*" || pattern == v }

// profileMatch applies a rule's profile glob. Rules for every profile ("*")
// always apply; profile-scoped rules need a matching session profile.
func profileMatch(pattern, profile string) bool {
	if pattern == "*" || pattern == "" {
		return true
	}
	return profile != "" && Glob(pattern, profile)
}

// Glob matches s against pattern, where '*' matches any (possibly empty)
// text including '/', and '?' matches exactly one character.
func Glob(pattern, s string) bool {
	if pattern == "*" {
		return true
	}
	p, t := []rune(pattern), []rune(s)
	pi, ti, star, mark := 0, 0, -1, 0
	for ti < len(t) {
		switch {
		case pi < len(p) && (p[pi] == '?' || p[pi] == t[ti]):
			pi++
			ti++
		case pi < len(p) && p[pi] == '*':
			star, mark = pi, ti
			pi++
		case star >= 0:
			pi = star + 1
			mark++
			ti = mark
		default:
			return false
		}
	}
	for pi < len(p) && p[pi] == '*' {
		pi++
	}
	return pi == len(p)
}

// Namespace returns the object name for a collection.
func Namespace(db, coll string) string { return db + "/" + coll }
