package mix

import "testing"

func TestMixLiteralParser(t *testing.T) {
	root, err := parseLiteral([]byte("%{\n  # comment\n  \"app\" => {:hex, :app, \"1.0\", [], [optional: false]},\n}\n"))
	if err != nil || len(root.pairs) != 1 || root.pairs[0].key.value != "app" || root.pairs[0].value.kind != "tuple" || root.pairs[0].value.elems[4].elems[0].kind != "keyword" {
		t.Fatalf("Mix literal parse: %#v %v", root, err)
	}
	for _, raw := range []string{
		`%{"app" => System.cmd("echo", ["oops"])}`,
		`%{"app" => {:hex, :app, "unterminated}}`,
		`%{"app" => {:hex, :app, "1.0"}`, // unbalanced tuple
		`[{:hex, :app, "1.0"}]`,
	} {
		if _, err := parseLiteral([]byte(raw)); err == nil {
			t.Fatalf("unsupported Mix expression accepted: %s", raw)
		}
	}
}
