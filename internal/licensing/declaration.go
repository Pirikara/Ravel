package licensing

import (
	"bytes"
	"encoding/json"
	"sort"
	"strconv"
	"strings"

	"github.com/Pirikara/Ravel/internal/model"
	"github.com/Pirikara/Ravel/internal/safeurl"
)

func Declare(value, kind string, evidence model.Evidence) []model.LicenseDeclaration {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	if (kind == "license" || kind == "expression") && (strings.HasPrefix(strings.TrimSpace(value), "https://") || strings.HasPrefix(strings.TrimSpace(value), "http://")) {
		kind = "url"
		value = strings.TrimSpace(value)
	}
	if kind == "url" {
		value = safeurl.Clean(value)
		if value == "" {
			return nil
		}
	}
	return Normalize([]model.LicenseDeclaration{{Value: value, Kind: kind, Evidence: []model.Evidence{evidence}}})
}

func JSONFields(data []byte, evidence model.Evidence) []model.LicenseDeclaration {
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil {
		return nil
	}
	prefix := strings.TrimRight(evidence.Pointer, "/")
	return Normalize(append(JSON(fields["license"], evidence, prefix+"/license", false), JSON(fields["licenses"], evidence, prefix+"/licenses", false)...))
}

// JSON handles modern strings, legacy npm objects/lists, and Composer arrays.
// Only formats explicitly defining a choice pass alternatives=true. Other
// arrays remain independent declarations without an invented AND/OR relation.
func JSON(raw json.RawMessage, evidence model.Evidence, pointer string, alternatives bool) []model.LicenseDeclaration {
	return jsonDeclarations(raw, evidence, pointer, alternatives, 0)
}

func jsonDeclarations(raw json.RawMessage, evidence model.Evidence, pointer string, alternatives bool, depth int) []model.LicenseDeclaration {
	evidence.Pointer = pointer
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return nil
	}
	if depth > 16 {
		return Declare(string(raw), "notice", evidence)
	}
	var value string
	if json.Unmarshal(raw, &value) == nil {
		return Declare(value, "license", evidence)
	}
	var values []json.RawMessage
	if json.Unmarshal(raw, &values) == nil {
		if len(values) > 256 {
			return Declare(string(raw), "notice", evidence)
		}
		if alternatives && len(values) > 1 {
			var names []string
			for _, entry := range values {
				var name string
				if json.Unmarshal(entry, &name) != nil {
					names = nil
					break
				}
				names = append(names, name)
			}
			if len(names) == len(values) {
				return Declare(string(raw), "alternatives", evidence)
			}
		}
		var out []model.LicenseDeclaration
		for i, entry := range values {
			out = append(out, jsonDeclarations(entry, evidence, pointer+"/"+strconv.Itoa(i), false, depth+1)...)
		}
		return Normalize(out)
	}
	var object struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	}
	if json.Unmarshal(raw, &object) == nil && (object.Type != "" || object.URL != "") {
		out := JSON(mustJSON(object.Type), evidence, pointer+"/type", false)
		evidence.Pointer = pointer + "/url"
		return Normalize(append(out, Declare(object.URL, "url", evidence)...))
	}
	return Declare(string(raw), "notice", evidence)
}

func mustJSON(value any) []byte { data, _ := json.Marshal(value); return data }

func Normalize(input []model.LicenseDeclaration) []model.LicenseDeclaration {
	if len(input) == 0 {
		return nil
	}
	byKey := map[string]model.LicenseDeclaration{}
	for _, d := range input {
		if strings.TrimSpace(d.Value) == "" {
			continue
		}
		d.Expression = ""
		switch d.Kind {
		case "expression", "license":
			d.Expression = Expression(d.Value)
		case "alternatives":
			var names []string
			if json.Unmarshal([]byte(d.Value), &names) == nil && len(names) > 0 && len(names) <= 256 {
				parts := []string{}
				for _, name := range names {
					value := Expression(name)
					if value == "" {
						parts = nil
						break
					}
					parts = append(parts, "("+value+")")
				}
				if len(parts) > 0 {
					d.Expression = strings.Join(parts, " OR ")
				}
			}
		case "url":
			d.Value = safeurl.Clean(d.Value)
			if d.Value == "" {
				continue
			}
		}
		key := string(mustJSON([2]string{d.Kind, d.Value}))
		if prior, ok := byKey[key]; ok {
			d.Evidence = append(append([]model.Evidence{}, prior.Evidence...), d.Evidence...)
		}
		seen := map[string]model.Evidence{}
		for _, e := range d.Evidence {
			seen[string(mustJSON(e))] = e
		}
		keys := make([]string, 0, len(seen))
		for key := range seen {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		d.Evidence = make([]model.Evidence, 0, len(keys))
		for _, key := range keys {
			d.Evidence = append(d.Evidence, seen[key])
		}
		byKey[key] = d
	}
	keys := make([]string, 0, len(byKey))
	if len(byKey) == 0 {
		return nil
	}
	for key := range byKey {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]model.LicenseDeclaration, 0, len(keys))
	for _, key := range keys {
		out = append(out, byKey[key])
	}
	return out
}

// Semantic removes evidence without modifying caller-owned slices.
func Semantic(input []model.LicenseDeclaration) []model.LicenseDeclaration {
	out := Normalize(input)
	for i := range out {
		out[i].Evidence = nil
	}
	return out
}

// DeclaredExpression requires a single unambiguous expression. Multiple
// statements with no defined combination, named licenses, and unresolved refs
// remain NOASSERTION in SPDX; their exact declarations are exported separately.
func DeclaredExpression(input []model.LicenseDeclaration) string {
	input = Normalize(input)
	set := map[string]bool{}
	for _, d := range input {
		if d.Kind == "file" || d.Kind == "url" || d.Kind == "classifier" {
			continue
		}
		if d.Expression == "" {
			return "NOASSERTION"
		}
		set[d.Expression] = true
	}
	if len(set) == 1 {
		for expression := range set {
			return expression
		}
	}
	return "NOASSERTION"
}
