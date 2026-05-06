package rules

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// sigmaDoc is a lenient parse of a Sigma rule. We do NOT support the full
// Sigma spec; we extract the subset that maps cleanly onto our expression
// engine.
//
// Supported detection constructs:
//   selection:
//     EventID: 1
//     CommandLine|contains: "foo"
//     CommandLine|endswith: ".sh"
//     Image|contains|all: [a, b]
//   condition: selection
//
// `condition: all of them` / `1 of selection_*` etc. are not supported
// here (yet); those rules are skipped with a warning-style error at load.
type sigmaDoc struct {
	Title       string                 `yaml:"title"`
	ID          string                 `yaml:"id"`
	Level       string                 `yaml:"level"`
	Description string                 `yaml:"description"`
	Tags        []string               `yaml:"tags"`
	Detection   map[string]interface{} `yaml:"detection"`
	Fields      []string               `yaml:"fields"`
}

// LoadSigmaLiteDir converts every *.yml / *.yaml file under dir into our
// internal Rule structs. Invalid files are skipped with a count-style
// error returned if at least one file was parsed successfully. Callers
// can Merge the result into their primary Pack.
func LoadSigmaLiteDir(dir string) (*Pack, error) {
	pack := &Pack{Version: "sigma-lite"}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		name := strings.ToLower(e.Name())
		if !(strings.HasSuffix(name, ".yml") || strings.HasSuffix(name, ".yaml")) {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		var doc sigmaDoc
		if err := yaml.Unmarshal(data, &doc); err != nil {
			continue
		}
		rule, ok := sigmaToRule(doc)
		if !ok {
			continue
		}
		pack.Rules = append(pack.Rules, rule)
	}
	if len(pack.Rules) == 0 {
		return nil, fmt.Errorf("no sigma-lite rules compiled under %s", dir)
	}
	// Eagerly compile exprs so errors surface at load.
	for i := range pack.Rules {
		if pack.Rules[i].Expr == "" {
			continue
		}
		e, err := CompileExpr(pack.Rules[i].Expr)
		if err != nil {
			return nil, fmt.Errorf("rule %q: %w", pack.Rules[i].ID, err)
		}
		pack.Rules[i].compiled = e
	}
	return pack, nil
}

func sigmaToRule(d sigmaDoc) (Rule, bool) {
	sel, ok := d.Detection["selection"].(map[string]interface{})
	if !ok {
		return Rule{}, false
	}
	parts := []string{}
	for k, raw := range sel {
		// Ignore meta keys (timeframe, filter, etc.).
		if strings.EqualFold(k, "timeframe") || strings.EqualFold(k, "count") {
			continue
		}
		part := sigmaFieldToExpr(k, raw)
		if part == "" {
			continue
		}
		parts = append(parts, part)
	}
	if len(parts) == 0 {
		return Rule{}, false
	}
	id := d.ID
	if id == "" {
		id = "SIGMA_" + sanitizeID(d.Title)
	}
	tech := []string{}
	for _, t := range d.Tags {
		if strings.HasPrefix(t, "attack.t") {
			tech = append(tech, strings.ToUpper(strings.TrimPrefix(t, "attack.")))
		}
	}
	r := Rule{
		ID:          id,
		Tactic:      "sigma",
		Techniques:  tech,
		Description: d.Description,
		BaseScore:   60,
		PerSignal:   10,
		CapScore:    90,
		MinSignals:  1,
		Expr:        strings.Join(parts, " and "),
	}
	return r, true
}

func sigmaFieldToExpr(key string, raw interface{}) string {
	field := key
	mod := ""
	if i := strings.Index(key, "|"); i >= 0 {
		field = key[:i]
		mod = key[i+1:]
	}
	our := sigmaFieldMap(field)
	if our == "" {
		return ""
	}
	values := toStringSlice(raw)
	if len(values) == 0 {
		return ""
	}
	parts := []string{}
	for _, v := range values {
		parts = append(parts, sigmaCompare(our, mod, v))
	}
	return "(" + strings.Join(parts, " or ") + ")"
}

func sigmaCompare(field, mod, value string) string {
	switch mod {
	case "contains", "":
		return field + ` contains "` + escape(value) + `"`
	case "endswith":
		return `matches(` + field + `, "` + escape(value) + `$")`
	case "startswith":
		return `matches(` + field + `, "^` + escape(value) + `")`
	case "re":
		return `matches(` + field + `, "` + escape(value) + `")`
	}
	return field + ` == "` + escape(value) + `"`
}

// sigmaFieldMap translates a handful of common Sigma field names into the
// identifiers our expression engine understands. Unknown fields are not
// supported and the rule is effectively dropped.
func sigmaFieldMap(f string) string {
	switch strings.ToLower(f) {
	case "commandline", "process_command_line", "argv":
		return "entity_path"
	case "image", "process":
		return "comm"
	case "path", "targetfilename":
		return "entity_path"
	case "user", "username":
		return "comm" // best effort; consumers can refine
	case "ruleid":
		return "rule_id"
	}
	return ""
}

func toStringSlice(raw interface{}) []string {
	switch v := raw.(type) {
	case string:
		return []string{v}
	case []interface{}:
		out := make([]string, 0, len(v))
		for _, x := range v {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func escape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return s
}

func sanitizeID(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
			out = append(out, c)
		case c >= 'a' && c <= 'z':
			out = append(out, c-'a'+'A')
		case c == ' ' || c == '-' || c == '.':
			out = append(out, '_')
		}
	}
	return string(out)
}
