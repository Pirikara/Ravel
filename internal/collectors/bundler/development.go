package bundler

import (
	"bytes"
	"regexp"
	"strings"

	"github.com/Pirikara/Ravel/internal/collectors/common"
	"github.com/Pirikara/Ravel/internal/model"
)

var rubySimpleInterpolation = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.:]*$`)

// CollectDevelopment reads literal gemspec declarations without running Ruby.
func CollectDevelopment(doc *model.Document, occurrence string, data []byte, variable string, evidence model.Evidence) {
	prefix := regexp.QuoteMeta(variable)
	homepage := regexp.MustCompile(`(?m)^[ \t]*` + prefix + `\.homepage[ \t]*=[ \t]*([^\r\n]+)`)
	homepages := homepage.FindAllSubmatchIndex(data, -1)
	literalHomepage := ""
	if len(homepages) == 1 {
		match := homepages[0]
		if value, rest, ok := rubyMetadataString(string(data[match[2]:match[3]])); ok && rubyEndOfStatement(rest) {
			literalHomepage = value
		}
	}
	assigned := regexp.MustCompile(`(?m)^[ \t]*` + prefix + `\.metadata[ \t]*=[ \t]*`)
	explicit := false
	for _, match := range assigned.FindAllIndex(data, -1) {
		values, ok := literalMetadataHash(string(data[match[1]:]), variable, literalHomepage)
		if !ok {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "development_source_unresolved", Scope: occurrence})
			continue
		}
		if value, present := values["source_code_uri"]; present && value == "" {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "development_source_unresolved", Scope: occurrence})
		} else if value != "" {
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
		value, rest, ok := rubyMetadataValue(string(data[match[2]:match[3]]), variable, literalHomepage)
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
	for _, match := range homepages {
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
	// Non-interpolating percent strings are common in source gemspecs.
	if strings.HasPrefix(input, "%q") && len(input) > 3 {
		open, close := input[2], input[2]
		switch open {
		case '{':
			close = '}'
		case '[':
			close = ']'
		case '(':
			close = ')'
		case '<':
			close = '>'
		case '|', '/', '!':
		default:
			return "", input, false
		}
		end := strings.IndexByte(input[3:], close)
		if end < 0 {
			return "", input, false
		}
		end += 3
		value := input[3:end]
		if strings.ContainsAny(value, "\\\r\n") || open != close && strings.IndexByte(value, open) >= 0 {
			return "", input, false
		}
		rest := strings.TrimSpace(input[end+1:])
		return value, strings.TrimSpace(strings.TrimPrefix(rest, ".freeze")), true
	}
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

func rubyMetadataValue(input, variable, homepage string) (string, string, bool) {
	if value, rest, ok := rubyMetadataString(input); ok {
		return value, rest, true
	}
	input = strings.TrimSpace(input)
	if homepage != "" && strings.HasPrefix(input, variable+".homepage") {
		return homepage, strings.TrimSpace(strings.TrimPrefix(input, variable+".homepage")), true
	}
	return "", input, false
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

func literalMetadataHash(input, variable, homepage string) (map[string]string, bool) {
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
		expression, remaining, ok := rubyMetadataExpression(rest)
		if !ok {
			return nil, false
		}
		value, tail, literal := rubyMetadataValue(expression, variable, homepage)
		if !literal || !rubyEndOfStatement(tail) {
			value = ""
		}
		values[key] = value
		input = rubyMetadataSpace(remaining)
		if strings.HasPrefix(input, ",") {
			input = input[1:]
		} else if !strings.HasPrefix(input, "}") {
			return nil, false
		}
	}
	return nil, false
}

// Split one bounded hash value, retaining literal siblings of computed values.
// Unsupported Ruby syntax (including heredocs) rejects the hash. This is a
// delimiter scanner, not a Ruby evaluator.
func rubyMetadataExpression(input string) (string, string, bool) {
	var stack []byte
	for i := 0; i < len(input); i++ {
		c := input[i]
		if c == ',' && len(stack) == 0 || c == '}' && len(stack) == 0 {
			return input[:i], input[i:], true
		}
		switch c {
		case '\'', '"':
			quote := c
			i++
			for ; i < len(input); i++ {
				if input[i] == '\\' {
					i++
					continue
				}
				if quote == '"' && strings.HasPrefix(input[i:], "#{") {
					end := strings.IndexByte(input[i+2:], '}')
					if end < 0 || !rubySimpleInterpolation.MatchString(input[i+2:i+2+end]) {
						return "", input, false
					}
					i += 2 + end
					continue
				}
				if input[i] == quote {
					break
				}
			}
			if i >= len(input) {
				return "", input, false
			}
		case '#':
			for i < len(input) && input[i] != '\n' {
				i++
			}
		case '(', '[', '{':
			if len(stack) >= 32 {
				return "", input, false
			}
			stack = append(stack, c)
		case ')', ']', '}':
			if len(stack) == 0 {
				return "", input, false
			}
			open := stack[len(stack)-1]
			if c == ')' && open != '(' || c == ']' && open != '[' || c == '}' && open != '{' {
				return "", input, false
			}
			stack = stack[:len(stack)-1]
		case '%':
			// Only the same bounded, non-interpolating strings as above.
			if !strings.HasPrefix(input[i:], "%q") || i+3 >= len(input) {
				return "", input, false
			}
			close := input[i+2]
			switch close {
			case '{':
				close = '}'
			case '[':
				close = ']'
			case '(':
				close = ')'
			case '<':
				close = '>'
			}
			end := strings.IndexByte(input[i+3:], close)
			if end < 0 {
				return "", input, false
			}
			end += i + 4
			_, _, ok := rubyMetadataString(input[i:end])
			if !ok {
				return "", input, false
			}
			i = end - 1
		case '<', '`', '/':
			return "", input, false
		}
	}
	return "", input, false
}
