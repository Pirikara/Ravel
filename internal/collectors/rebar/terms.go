package rebar

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

type term struct {
	kind  byte
	value string
	items []term
}

type termParser struct {
	input []byte
	pos   int
	nodes int
}

func parseTerms(input []byte) ([]term, error) {
	p := &termParser{input: input}
	var result []term
	for {
		p.space()
		if p.pos >= len(p.input) {
			return result, nil
		}
		item, err := p.parse(0)
		if err != nil {
			return nil, err
		}
		p.space()
		if !p.consume('.') {
			return nil, errors.New("Erlang term is missing final period")
		}
		result = append(result, item)
		if len(result) > 8 {
			return nil, errors.New("too many Erlang terms in rebar.lock")
		}
	}
}

func (p *termParser) parse(depth int) (term, error) {
	if depth > 64 || p.nodes >= 100000 {
		return term{}, errors.New("rebar.lock term nesting or count exceeds limit")
	}
	p.nodes++
	p.space()
	if p.pos >= len(p.input) {
		return term{}, errors.New("unexpected end of rebar.lock")
	}
	if p.consume('{') {
		return p.sequence('}', '{', depth)
	}
	if p.consume('[') {
		return p.sequence(']', '[', depth)
	}
	if p.has("<<") {
		p.pos += 2
		p.space()
		value, err := p.quoted()
		if err != nil {
			return term{}, err
		}
		p.space()
		if !p.has(">>") {
			return term{}, errors.New("unterminated Erlang binary")
		}
		p.pos += 2
		return term{kind: 'b', value: value}, nil
	}
	if p.input[p.pos] == '"' {
		value, err := p.quoted()
		return term{kind: 's', value: value}, err
	}
	if isAtomStart(p.input[p.pos]) || p.input[p.pos] >= '0' && p.input[p.pos] <= '9' {
		start := p.pos
		for p.pos < len(p.input) && isAtomPart(p.input[p.pos]) {
			p.pos++
		}
		value := string(p.input[start:p.pos])
		if _, err := strconv.ParseUint(value, 10, 32); err == nil {
			return term{kind: 'i', value: value}, nil
		}
		return term{kind: 'a', value: value}, nil
	}
	return term{}, fmt.Errorf("unsupported Erlang term at byte %d", p.pos)
}

func (p *termParser) sequence(end, kind byte, depth int) (term, error) {
	result := term{kind: kind}
	p.space()
	if p.consume(end) {
		return result, nil
	}
	for {
		item, err := p.parse(depth + 1)
		if err != nil {
			return term{}, err
		}
		result.items = append(result.items, item)
		p.space()
		if p.consume(end) {
			return result, nil
		}
		if !p.consume(',') {
			return term{}, fmt.Errorf("expected comma or %q at byte %d", end, p.pos)
		}
	}
}

func (p *termParser) quoted() (string, error) {
	if !p.consume('"') {
		return "", errors.New("expected Erlang string")
	}
	var value strings.Builder
	for p.pos < len(p.input) {
		char := p.input[p.pos]
		p.pos++
		if char == '"' {
			return value.String(), nil
		}
		if char == '\\' {
			if p.pos >= len(p.input) {
				return "", errors.New("unterminated Erlang string escape")
			}
			char = p.input[p.pos]
			p.pos++
			switch char {
			case 'n':
				char = '\n'
			case 'r':
				char = '\r'
			case 't':
				char = '\t'
			}
		}
		value.WriteByte(char)
	}
	return "", errors.New("unterminated Erlang string")
}

func (p *termParser) space() {
	for p.pos < len(p.input) {
		char := p.input[p.pos]
		if unicode.IsSpace(rune(char)) {
			p.pos++
			continue
		}
		if char == '%' {
			for p.pos < len(p.input) && p.input[p.pos] != '\n' {
				p.pos++
			}
			continue
		}
		return
	}
}

func (p *termParser) has(value string) bool {
	return bytes.HasPrefix(p.input[p.pos:], []byte(value))
}

func (p *termParser) consume(value byte) bool {
	if p.pos < len(p.input) && p.input[p.pos] == value {
		p.pos++
		return true
	}
	return false
}

func isAtomStart(char byte) bool {
	return char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char == '_'
}

func isAtomPart(char byte) bool {
	return isAtomStart(char) || char >= '0' && char <= '9' || char == '@'
}

func (t term) at(index int) term {
	if index < 0 || index >= len(t.items) {
		return term{}
	}
	return t.items[index]
}

func (t term) text() string {
	if t.kind == 's' || t.kind == 'b' || t.kind == 'a' || t.kind == 'i' {
		return t.value
	}
	return ""
}
