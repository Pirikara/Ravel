package bundler

import (
	"bytes"
	"regexp"
	"strconv"
	"strings"

	"github.com/Pirikara/Ravel/internal/licensing"
	"github.com/Pirikara/Ravel/internal/model"
	"gopkg.in/yaml.v3"
)

// DeclaredLicenses reads literal gemspec assignments without evaluating Ruby.
// Array members are separate observations: RubyGems does not define AND/OR.
func DeclaredLicenses(data []byte, variable string, evidence model.Evidence) ([]model.LicenseDeclaration, bool) {
	pattern := regexp.MustCompile(`(?m)^[ \t]*` + regexp.QuoteMeta(variable) + `\.(licenses?)[ \t]*=[ \t]*`)
	var declarations []model.LicenseDeclaration
	unresolved := false
	for _, match := range pattern.FindAllSubmatchIndex(data, -1) {
		rest := string(data[match[1]:])
		end := strings.IndexByte(rest, '\n')
		if end < 0 {
			end = len(rest)
		}
		// Generated gemspecs normally use one line; literal multiline arrays
		// are also accepted, with a bounded source file supplied by the caller.
		if strings.HasPrefix(strings.TrimSpace(rest), "[") {
			if close := strings.IndexByte(rest, ']'); close >= 0 {
				if next := strings.IndexByte(rest[close:], '\n'); next >= 0 {
					end = close + next
				} else {
					end = len(rest)
				}
			}
		}
		rhs := strings.TrimSpace(rest[:end])
		values, ok := literalLicenseValues(rhs)
		if !ok {
			unresolved = true
			continue
		}
		e := evidence
		e.Pointer = "Gem::Specification/" + string(data[match[2]:match[3]])
		e.Line = bytes.Count(data[:match[0]], []byte("\n")) + 1
		for _, value := range values {
			declarations = append(declarations, licensing.Declare(value, "license", e)...)
		}
	}
	return licensing.Normalize(declarations), unresolved
}

func literalLicenseValues(value string) ([]string, bool) {
	value = strings.TrimSpace(value)
	// Strip a comment only outside quoted literals.
	quote := byte(0)
	for i := 0; i < len(value); i++ {
		c := value[i]
		if quote != 0 {
			if c == '\\' {
				i++
				continue
			}
			if c == quote {
				quote = 0
			}
			continue
		}
		if c == '\'' || c == '"' {
			quote = c
		} else if c == '#' {
			value = strings.TrimSpace(value[:i])
			break
		}
	}
	value = strings.TrimSpace(strings.TrimSuffix(value, ".freeze"))
	if strings.HasPrefix(value, "%w[") && strings.HasSuffix(value, "]") {
		inner := value[3 : len(value)-1]
		if strings.ContainsAny(inner, "\\[]#") {
			return nil, false
		}
		return strings.Fields(inner), true
	}
	if strings.HasPrefix(value, "[") && strings.HasSuffix(value, "]") {
		inner := strings.TrimSpace(value[1 : len(value)-1])
		if inner == "" {
			return nil, true
		}
		var values []string
		for inner != "" {
			if inner[0] != '\'' && inner[0] != '"' {
				return nil, false
			}
			quote := inner[0]
			end := strings.IndexByte(inner[1:], quote)
			if end < 0 {
				return nil, false
			}
			end += 2
			literal := inner[:end]
			name := rubyLiteral(literal)
			if name == "" || strings.Contains(name, "#{") {
				return nil, false
			}
			values = append(values, name)
			inner = strings.TrimSpace(inner[end:])
			inner = strings.TrimSpace(strings.TrimPrefix(inner, ".freeze"))
			if inner == "" {
				break
			}
			if inner[0] != ',' {
				return nil, false
			}
			inner = strings.TrimSpace(inner[1:])
		}
		return values, true
	}
	name := rubyLiteral(value)
	if name == "" || strings.Contains(name, "#{") {
		return nil, false
	}
	return []string{name}, true
}

func archiveLicenses(data []byte, evidence model.Evidence) []model.LicenseDeclaration {
	var document yaml.Node
	if yaml.Unmarshal(data, &document) != nil || len(document.Content) != 1 {
		return nil
	}
	spec := document.Content[0]
	var declarations []model.LicenseDeclaration
	for _, field := range []string{"license", "licenses"} {
		node := gemField(spec, field)
		if node == nil {
			continue
		}
		e := evidence
		e.Pointer += "/" + field
		if node.Kind == yaml.ScalarNode {
			declarations = append(declarations, licensing.Declare(gemScalar(node), "license", e)...)
		}
		if node.Kind == yaml.SequenceNode {
			for i, item := range node.Content {
				entry := e
				entry.Pointer += "/" + strconv.Itoa(i)
				declarations = append(declarations, licensing.Declare(gemScalar(item), "license", entry)...)
			}
		}
	}
	return licensing.Normalize(declarations)
}
