package deno

// esbuild's metafile omits TypeScript imports erased from JavaScript output.
// This lexer supplements those imports without treating text in comments or
// quoted examples as source declarations. Ordinary imports remain covered by
// esbuild; only declarations containing the `type` modifier are returned.
func typeOnlyImportSpecifiers(data []byte) []string {
	tokens := lexModuleTokens(data)
	seen := map[string]bool{}
	var specs []string
	for i, token := range tokens {
		if token.kind != "ident" || token.value != "import" && token.value != "export" || i+1 >= len(tokens) {
			continue
		}
		if i > 0 && tokens[i-1].value == "." {
			continue
		}
		next := tokens[i+1].value
		if next == "(" || next == "." || token.value == "export" && next != "type" && next != "{" && next != "*" {
			continue
		}
		depth := 0
		hasType := false
		for j := i + 1; j < len(tokens) && j < i+120; j++ {
			t := tokens[j]
			if depth == 0 && (t.value == ";" || j > i+1 && (t.value == "import" || t.value == "export")) {
				break
			}
			if t.value == "{" {
				depth++
			} else if t.value == "}" && depth > 0 {
				depth--
			}
			if t.kind == "ident" && t.value == "type" {
				hasType = true
			}
			if depth == 0 && t.value == "from" && j+1 < len(tokens) && tokens[j+1].kind == "string" {
				spec := tokens[j+1].value
				if hasType && !seen[spec] {
					seen[spec] = true
					specs = append(specs, spec)
				}
				break
			}
		}
	}
	return specs
}

type moduleToken struct{ kind, value string }

func lexModuleTokens(data []byte) []moduleToken {
	var tokens []moduleToken
	for i := 0; i < len(data); {
		c := data[i]
		if c == '/' && i+1 < len(data) && data[i+1] == '/' {
			i += 2
			for i < len(data) && data[i] != '\n' {
				i++
			}
			continue
		}
		if c == '/' && i+1 < len(data) && data[i+1] == '*' {
			i += 2
			for i+1 < len(data) && (data[i] != '*' || data[i+1] != '/') {
				i++
			}
			if i+1 < len(data) {
				i += 2
			}
			continue
		}
		if c == '/' && regexCanStart(tokens) {
			i++
			inClass := false
			for i < len(data) {
				if data[i] == '\\' && i+1 < len(data) {
					i += 2
					continue
				}
				if data[i] == '[' {
					inClass = true
				} else if data[i] == ']' {
					inClass = false
				} else if data[i] == '/' && !inClass {
					i++
					for i < len(data) && moduleIdent(data[i]) {
						i++
					}
					break
				}
				i++
			}
			continue
		}
		if c == '\'' || c == '"' || c == '`' {
			quote := c
			i++
			start := i
			value := make([]byte, 0, 64)
			for i < len(data) && data[i] != quote {
				if data[i] == '\\' && i+1 < len(data) {
					value = append(value, data[start:i]...)
					value = append(value, data[i+1])
					i += 2
					start = i
					continue
				}
				i++
			}
			value = append(value, data[start:i]...)
			if i < len(data) {
				i++
			}
			if quote != '`' {
				tokens = append(tokens, moduleToken{kind: "string", value: string(value)})
			}
			continue
		}
		if moduleIdent(c) {
			start := i
			i++
			for i < len(data) && moduleIdent(data[i]) {
				i++
			}
			tokens = append(tokens, moduleToken{kind: "ident", value: string(data[start:i])})
			continue
		}
		if c > ' ' {
			tokens = append(tokens, moduleToken{value: string(c)})
		}
		i++
	}
	return tokens
}

func moduleIdent(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '$'
}

func regexCanStart(tokens []moduleToken) bool {
	if len(tokens) == 0 {
		return true
	}
	last := tokens[len(tokens)-1]
	if last.kind == "ident" {
		switch last.value {
		case "return", "throw", "case", "yield", "await", "typeof", "void", "delete":
			return true
		}
		return false
	}
	switch last.value {
	case "=", "(", "[", "{", ":", ",", "!", "?", ";", ">":
		return true
	}
	return false
}
