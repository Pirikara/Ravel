package licensing

import (
	_ "embed"
	"encoding/json"
	"strings"
	"unicode"
)

// Identifier data only, from SPDX license-list-data v3.29.0. No license text or
// license-detection rules are used. See README.md for the pinned source URLs.
//
//go:embed spdx.json
var identifiers []byte

var licenseIDs, exceptionIDs = identifierMaps()

func Identifier(value string) string { return licenseIDs[strings.ToLower(value)] }

func identifierMaps() (map[string]string, map[string]string) {
	var data struct{ Licenses, Exceptions []string }
	if err := json.Unmarshal(identifiers, &data); err != nil {
		panic(err)
	}
	licenses, exceptions := map[string]string{}, map[string]string{}
	for _, id := range data.Licenses {
		licenses[strings.ToLower(id)] = id
	}
	for _, id := range data.Exceptions {
		exceptions[strings.ToLower(id)] = id
	}
	return licenses, exceptions
}

// Expression validates known SPDX identifiers, operators, exceptions and
// parentheses. Unresolved LicenseRefs and informal names return an empty value;
// callers retain the original declaration rather than guessing an identifier.
func Expression(value string) string {
	if len(value) > 16384 {
		return ""
	}
	var tokens []string
	for _, r := range value {
		if !unicode.IsSpace(r) && r != '(' && r != ')' && !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-' || r == '+') {
			return ""
		}
	}
	value = strings.NewReplacer("(", " ( ", ")", " ) ").Replace(value)
	tokens = strings.Fields(value)
	if len(tokens) == 0 || len(tokens) > 512 {
		return ""
	}
	p := expressionParser{tokens: tokens}
	text, ok := p.or(0)
	if !ok || p.position != len(tokens) {
		return ""
	}
	return text
}

type expressionParser struct {
	tokens   []string
	position int
}

func (p *expressionParser) take(token string) bool {
	if p.position < len(p.tokens) && strings.EqualFold(p.tokens[p.position], token) {
		p.position++
		return true
	}
	return false
}

func (p *expressionParser) or(depth int) (string, bool) {
	left, ok := p.and(depth)
	if !ok {
		return "", false
	}
	for p.take("OR") {
		right, ok := p.and(depth)
		if !ok {
			return "", false
		}
		left += " OR " + right
	}
	return left, true
}

func (p *expressionParser) and(depth int) (string, bool) {
	left, ok := p.term(depth)
	if !ok {
		return "", false
	}
	for p.take("AND") {
		right, ok := p.term(depth)
		if !ok {
			return "", false
		}
		left += " AND " + right
	}
	return left, true
}

func (p *expressionParser) term(depth int) (string, bool) {
	if depth > 32 || p.position >= len(p.tokens) {
		return "", false
	}
	if p.take("(") {
		inner, ok := p.or(depth + 1)
		if !ok || !p.take(")") {
			return "", false
		}
		return "(" + inner + ")", true
	}
	value := p.tokens[p.position]
	p.position++
	canonical := licenseIDs[strings.ToLower(value)]
	if canonical == "" && strings.HasSuffix(value, "+") {
		if base := licenseIDs[strings.ToLower(strings.TrimSuffix(value, "+"))]; base != "" {
			canonical = base + "+"
		}
	}
	if canonical == "" {
		return "", false
	}
	if p.take("WITH") {
		if p.position >= len(p.tokens) {
			return "", false
		}
		exception := exceptionIDs[strings.ToLower(p.tokens[p.position])]
		p.position++
		if exception == "" {
			return "", false
		}
		canonical += " WITH " + exception
	}
	return canonical, true
}
