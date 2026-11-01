package mix

import (
	"errors"
	"fmt"
	"strconv"
)

// mix.lock is written as an Elixir literal. This parser accepts only literal
// maps, tuples, lists, atoms, strings, numbers, and keyword pairs. It never
// evaluates Elixir expressions or interpolates strings.
type token struct {
	kind, value string
	line        int
}

type term struct {
	kind, value string
	line        int
	elems       []term
	pairs       []termPair
}

type termPair struct {
	key, value term
}

func lex(data []byte) ([]token, error) {
	out := make([]token, 0, len(data)/8)
	line := 1
	for i := 0; i < len(data); {
		c := data[i]
		if c == '\n' {
			line++
			i++
			continue
		}
		if c == ' ' || c == '\t' || c == '\r' {
			i++
			continue
		}
		if c == '#' {
			for i < len(data) && data[i] != '\n' {
				i++
			}
			continue
		}
		if c == '"' {
			start, at := i, line
			i++
			for i < len(data) {
				if data[i] == '\\' {
					i += 2
					continue
				}
				if data[i] == '\n' {
					line++
				}
				if data[i] == '"' {
					i++
					break
				}
				i++
			}
			if i > len(data) || data[i-1] != '"' {
				return nil, fmt.Errorf("unterminated Mix string at line %d", at)
			}
			value, err := strconv.Unquote(string(data[start:i]))
			if err != nil {
				return nil, fmt.Errorf("invalid Mix string at line %d: %w", at, err)
			}
			out = append(out, token{kind: "string", value: value, line: at})
			continue
		}
		if isWord(c) {
			start := i
			for i < len(data) && isWord(data[i]) {
				i++
			}
			out = append(out, token{kind: "word", value: string(data[start:i]), line: line})
			continue
		}
		if c == '%' || c == '{' || c == '}' || c == '[' || c == ']' || c == ':' || c == ',' || c == '=' || c == '>' {
			out = append(out, token{kind: string(c), line: line})
			i++
			continue
		}
		return nil, fmt.Errorf("unsupported Mix literal token %q at line %d", c, line)
	}
	if len(out) > 500000 {
		return nil, errors.New("Mix lockfile has too many tokens")
	}
	return out, nil
}

func isWord(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '!' || c == '?' || c == '.' || c == '-'
}

type termParser struct {
	tokens []token
	at     int
}

func parseLiteral(data []byte) (term, error) {
	tokens, err := lex(data)
	if err != nil {
		return term{}, err
	}
	p := termParser{tokens: tokens}
	value, err := p.parse(0)
	if err != nil {
		return term{}, err
	}
	if p.at != len(tokens) || value.kind != "map" {
		return term{}, errors.New("Mix lockfile must contain one literal map")
	}
	return value, nil
}

func (p *termParser) peek(kind string) bool {
	return p.at < len(p.tokens) && p.tokens[p.at].kind == kind
}

func (p *termParser) take(kind string) (token, error) {
	if !p.peek(kind) {
		return token{}, fmt.Errorf("expected %s in Mix literal at token %d", kind, p.at)
	}
	t := p.tokens[p.at]
	p.at++
	return t, nil
}

func (p *termParser) parse(depth int) (term, error) {
	if depth > 64 || p.at >= len(p.tokens) {
		return term{}, errors.New("Mix literal nesting or end of input is invalid")
	}
	if p.peek("%") {
		p.at++
		open, err := p.take("{")
		if err != nil {
			return term{}, err
		}
		result := term{kind: "map", line: open.line}
		for !p.peek("}") {
			key, err := p.parse(depth + 1)
			if err != nil {
				return term{}, err
			}
			if key.kind == "keyword" && len(key.elems) == 1 {
				result.pairs = append(result.pairs, termPair{key: term{kind: "word", value: key.value, line: key.line}, value: key.elems[0]})
				if !p.peek(",") {
					break
				}
				p.at++
				continue
			}
			if p.peek("=") {
				p.at++
				if _, err := p.take(">"); err != nil {
					return term{}, err
				}
			} else if _, err := p.take(":"); err != nil {
				return term{}, err
			}
			value, err := p.parse(depth + 1)
			if err != nil {
				return term{}, err
			}
			result.pairs = append(result.pairs, termPair{key: key, value: value})
			if !p.peek(",") {
				break
			}
			p.at++
		}
		if _, err := p.take("}"); err != nil {
			return term{}, err
		}
		return result, nil
	}
	if p.peek("{") || p.peek("[") {
		open := p.tokens[p.at]
		p.at++
		close, kind := "}", "tuple"
		if open.kind == "[" {
			close, kind = "]", "list"
		}
		result := term{kind: kind, line: open.line}
		for !p.peek(close) {
			value, err := p.parse(depth + 1)
			if err != nil {
				return term{}, err
			}
			result.elems = append(result.elems, value)
			if !p.peek(",") {
				break
			}
			p.at++
		}
		if _, err := p.take(close); err != nil {
			return term{}, err
		}
		return result, nil
	}
	if p.peek(":") {
		colon := p.tokens[p.at]
		p.at++
		word, err := p.take("word")
		if err != nil {
			return term{}, err
		}
		return term{kind: "atom", value: word.value, line: colon.line}, nil
	}
	if p.peek("word") || p.peek("string") {
		value := p.tokens[p.at]
		p.at++
		if value.kind == "word" && p.peek(":") {
			p.at++
			right, err := p.parse(depth + 1)
			if err != nil {
				return term{}, err
			}
			return term{kind: "keyword", value: value.value, line: value.line, elems: []term{right}}, nil
		}
		return term{kind: value.kind, value: value.value, line: value.line}, nil
	}
	return term{}, fmt.Errorf("unexpected Mix literal token %s at token %d", p.tokens[p.at].kind, p.at)
}
