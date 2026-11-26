package bundler

import (
	"bytes"
	"regexp"
	"strings"

	"github.com/Pirikara/Ravel/internal/collectors/common"
	"github.com/Pirikara/Ravel/internal/model"
)

// CollectDevelopment reads literal gemspec declarations without running Ruby.
func CollectDevelopment(doc *model.Document, occurrence string, data []byte, variable string, evidence model.Evidence) {
	prefix := regexp.QuoteMeta(variable)
	assigned := regexp.MustCompile(`(?m)^[ \t]*` + prefix + `\.metadata[ \t]*=[ \t]*`)
	explicit := false
	for _, match := range assigned.FindAllIndex(data, -1) {
		values, ok := literalMetadataHash(string(data[match[1]:]), variable)
		if !ok {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "development_source_unresolved", Scope: occurrence})
			continue
		}
		if value := values["source_code_uri"]; value != "" {
			e := evidence
			e.Pointer = "Gem::Specification/metadata/source_code_uri"
			e.Line = bytes.Count(data[:match[0]], []byte("\n")) + 1
			before := len(doc.Development)
			common.AddDevelopment(doc, occurrence, value, "declared", e)
			explicit = explicit || len(doc.Development) > before
		}
	}
	indexed := regexp.MustCompile(`(?m)^[ \t]*` + prefix + `\.metadata\[[ \t]*["']source_code_uri["'](?:\.freeze)?[ \t]*\][ \t]*=[ \t]*([^\r\n]+)`)
	for _, match := range indexed.FindAllSubmatchIndex(data, -1) {
		value, rest, ok := rubyMetadataString(string(data[match[2]:match[3]]))
		if !ok || !rubyEndOfStatement(rest) {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "development_source_unresolved", Scope: occurrence})
			continue
		}
		e := evidence
		e.Pointer = "Gem::Specification/metadata/source_code_uri"
		e.Line = bytes.Count(data[:match[0]], []byte("\n")) + 1
		before := len(doc.Development)
		common.AddDevelopment(doc, occurrence, value, "declared", e)
		explicit = explicit || len(doc.Development) > before
	}
	if explicit {
		return
	}
	homepage := regexp.MustCompile(`(?m)^[ \t]*` + prefix + `\.homepage[ \t]*=[ \t]*([^\r\n]+)`)
	for _, match := range homepage.FindAllSubmatchIndex(data, -1) {
		value, rest, ok := rubyMetadataString(string(data[match[2]:match[3]]))
		if !ok || !rubyEndOfStatement(rest) {
			continue
		}
		if candidate := common.RepositoryHomepage(value); candidate != "" {
			e := evidence
			e.Pointer = "Gem::Specification/homepage"
			e.Line = bytes.Count(data[:match[0]], []byte("\n")) + 1
			common.AddDevelopment(doc, occurrence, candidate, "inferred_from_homepage", e)
		}
	}
}

func rubyMetadataString(input string) (string, string, bool) {
	input = strings.TrimSpace(input)
	if len(input) < 2 || input[0] != '\'' && input[0] != '"' {
		return "", input, false
	}
	end := strings.IndexByte(input[1:], input[0])
	if end < 0 {
		return "", input, false
	}
	end += 2
	value := input[1 : end-1]
	if strings.ContainsAny(value, "\\\r\n") || strings.Contains(value, "#{") {
		return "", input, false
	}
	rest := strings.TrimSpace(input[end:])
	rest = strings.TrimPrefix(rest, ".freeze")
	return value, strings.TrimSpace(rest), true
}

func rubyEndOfStatement(rest string) bool {
	return strings.TrimSpace(rest) == "" || strings.HasPrefix(strings.TrimSpace(rest), "#")
}

func rubyMetadataSpace(input string) string {
	for {
		input = strings.TrimSpace(input)
		if !strings.HasPrefix(input, "#") {
			return input
		}
		i := strings.IndexByte(input, '\n')
		if i < 0 {
			return ""
		}
		input = input[i+1:]
	}
}

func literalMetadataHash(input, variable string) (map[string]string, bool) {
	input = rubyMetadataSpace(input)
	if !strings.HasPrefix(input, "{") {
		return nil, false
	}
	input = input[1:]
	values := map[string]string{}
	for count := 0; count < 256; count++ {
		input = rubyMetadataSpace(input)
		if strings.HasPrefix(input, "}") {
			rest := input[1:]
			if end := strings.IndexByte(rest, '\n'); end >= 0 {
				rest = rest[:end]
			}
			rest = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(rest), ".freeze"))
			// RubyGems writes this API-availability guard in generated specs.
			// Accept the literal declaration without evaluating the condition.
			guard := regexp.MustCompile(`^if[ \t]+` + regexp.QuoteMeta(variable) + `\.respond_to\?[ \t]*(?::metadata=?|\([ \t]*:metadata=?[ \t]*\))[ \t]*(?:#.*)?$`)
			return values, rubyEndOfStatement(rest) || guard.MatchString(rest)
		}
		key, rest, ok := rubyMetadataString(input)
		if !ok { // Ruby's literal symbol-key hash syntax.
			if i := strings.IndexByte(input, ':'); i > 0 {
				key = input[:i]
				ok = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`).MatchString(key)
				rest = input[i:]
			}
		}
		if !ok {
			return nil, false
		}
		if strings.HasPrefix(rest, "=>") {
			rest = rest[2:]
		} else if strings.HasPrefix(rest, ":") {
			rest = rest[1:]
		} else {
			return nil, false
		}
		value, rest, ok := rubyMetadataString(rest)
		if !ok {
			return nil, false
		}
		values[key] = value
		input = rubyMetadataSpace(rest)
		if strings.HasPrefix(input, ",") {
			input = input[1:]
		} else if !strings.HasPrefix(input, "}") {
			return nil, false
		}
	}
	return nil, false
}
