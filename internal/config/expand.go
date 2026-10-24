package config

import (
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Placeholders let one configuration file serve every organization and
// environment: string values may reference environment variables as
// ${NAME} or ${NAME:-default}, and "$${" stands for a literal "${".
// Expansion works on the parsed document, so a variable's value is always a
// plain value and can never add YAML structure. Mapping keys are not
// expanded. A referenced variable that is unset and has no default is an
// error, never an empty string.
var placeholderRe = regexp.MustCompile(`\$\$\{|\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}`)

// expand replaces placeholders in raw YAML and returns the resulting YAML.
func expand(raw []byte, lookup func(string) (string, bool)) ([]byte, []string, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, nil, fmt.Errorf("parse config: %w", err)
	}
	if doc.Kind == 0 {
		return raw, nil, nil
	}
	var used, missing []string
	var walk func(n *yaml.Node)
	walk = func(n *yaml.Node) {
		switch n.Kind {
		case yaml.DocumentNode, yaml.SequenceNode:
			for _, c := range n.Content {
				walk(c)
			}
		case yaml.MappingNode:
			for i := 1; i < len(n.Content); i += 2 {
				walk(n.Content[i])
			}
		case yaml.ScalarNode:
			if !strings.Contains(n.Value, "${") {
				return
			}
			n.Value = placeholderRe.ReplaceAllStringFunc(n.Value, func(m string) string {
				if m == "$${" {
					return "${"
				}
				sub := placeholderRe.FindStringSubmatch(m)
				name := sub[1]
				if !slices.Contains(used, name) {
					used = append(used, name)
				}
				if v, ok := lookup(name); ok && v != "" {
					return v
				}
				if strings.Contains(m, ":-") {
					return sub[2]
				}
				if !slices.Contains(missing, name) {
					missing = append(missing, name)
				}
				return ""
			})
			// An unquoted placeholder takes the type of its value (a number,
			// a boolean or a duration); a quoted one stays a string.
			if n.Style&(yaml.DoubleQuotedStyle|yaml.SingleQuotedStyle) == 0 {
				n.Tag = ""
			}
		}
	}
	walk(&doc)
	if len(missing) > 0 {
		return nil, used, fmt.Errorf("configuration references unset or empty environment variables without a default: %s", strings.Join(missing, ", "))
	}
	out, err := yaml.Marshal(&doc)
	if err != nil {
		return nil, used, fmt.Errorf("parse config: %w", err)
	}
	return out, used, nil
}

// Placeholders returns the environment variables a configuration file
// references, for diagnostics (values are never returned).
func Placeholders(raw []byte) []string {
	_, used, _ := expand(raw, func(string) (string, bool) { return "x", true })
	return used
}

func lookupEnv(name string) (string, bool) { return os.LookupEnv(name) }
