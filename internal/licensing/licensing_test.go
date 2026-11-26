package licensing

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/Pirikara/Ravel/internal/model"
)

func TestExpressions(t *testing.T) {
	for input, want := range map[string]string{
		"mit": "MIT", "(mit or Apache-2.0) AND gpl-2.0+": "(MIT OR Apache-2.0) AND GPL-2.0+",
		"GPL-2.0-only with classpath-exception-2.0": "GPL-2.0-only WITH Classpath-exception-2.0",
		"MIT OR BSD-2-Clause AND Apache-2.0":        "MIT OR BSD-2-Clause AND Apache-2.0",
		"Apache License 2.0":                        "", "LicenseRef-Company": "", "NONE": "", "UNLICENSED": "",
		"MIT AND": "", "MIT OR OR MIT": "", "(MIT OR BSD-2-Clause) WITH Classpath-exception-2.0": "",
		"MIT WITH Unknown-exception": "", "MIT BSD-2-Clause": "", "MIT++": "", "MIT;Apache-2.0": "",
		strings.Repeat("(", 40) + "MIT" + strings.Repeat(")", 40): "",
		strings.Repeat("MIT OR ", 300) + "MIT":                    "",
	} {
		if got := Expression(input); got != want {
			t.Errorf("Expression(%q) = %q, want %q", input, got, want)
		}
	}
	for _, id := range licenseIDs {
		if Expression(id) != id {
			t.Errorf("embedded license ID rejected: %s", id)
		}
	}
	for _, id := range exceptionIDs {
		if Expression("GPL-2.0-only WITH "+id) != "GPL-2.0-only WITH "+id {
			t.Errorf("embedded exception rejected: %s", id)
		}
		if Identifier(id) != "" {
			t.Errorf("exception treated as license: %s", id)
		}
	}
}

func TestFormatSpecificDeclarations(t *testing.T) {
	ev := model.Evidence{InputPath: "composer.lock", Pointer: "/packages/0", InputDigest: "sha256:abc"}
	choice := JSON(json.RawMessage(`["MIT","Apache-2.0"]`), ev, "/packages/0/license", true)
	independent := JSON(json.RawMessage(`["MIT","Apache-2.0"]`), ev, "/licenses", false)
	if DeclaredExpression(choice) != "(MIT) OR (Apache-2.0)" || DeclaredExpression(independent) != "NOASSERTION" {
		t.Fatal("invented or lost array semantics", choice, independent)
	}
	unknown := JSON(json.RawMessage(`["MIT","Company terms"]`), ev, "/license", true)
	if len(unknown) != 1 || unknown[0].Kind != "alternatives" || DeclaredExpression(unknown) != "NOASSERTION" {
		t.Fatal(unknown)
	}
	legacy := JSONFields([]byte(`{"license":{"type":"MIT","url":"https://user:secret@example.com/LICENSE?token=secret"}}`), ev)
	if len(legacy) != 2 || DeclaredExpression(legacy) != "MIT" {
		t.Fatal(legacy)
	}
	encoded, _ := json.Marshal(legacy)
	if strings.Contains(string(encoded), "secret") || !strings.Contains(string(encoded), "/packages/0/license/type") {
		t.Fatal(string(encoded))
	}
	if got := JSON(json.RawMessage(`{"unexpected":true}`), ev, "/license", false); len(got) != 1 || got[0].Kind != "notice" {
		t.Fatal(got)
	}
}

func TestNormalizationAndAmbiguity(t *testing.T) {
	input := []model.LicenseDeclaration{
		{Value: "MIT", Kind: "license", Expression: "FAKE", Evidence: []model.Evidence{{InputPath: "a"}}},
		{Value: "MIT", Kind: "license", Evidence: []model.Evidence{{InputPath: "b"}, {InputPath: "a"}}},
		{Value: "LICENSE", Kind: "file"},
	}
	before, _ := json.Marshal(input)
	normalized := Normalize(input)
	if len(normalized) != 2 || DeclaredExpression(normalized) != "MIT" {
		t.Fatal(normalized)
	}
	for _, d := range normalized {
		if d.Kind == "license" && (len(d.Evidence) != 2 || d.Expression != "MIT") {
			t.Fatal(d)
		}
	}
	_ = Semantic(input)
	after, _ := json.Marshal(input)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("normalization mutated caller data")
	}
	for _, addition := range []model.LicenseDeclaration{{Value: "Apache-2.0", Kind: "expression"}, {Value: "Custom", Kind: "license"}} {
		if DeclaredExpression(append(normalized, addition)) != "NOASSERTION" {
			t.Fatal("contradictory declaration suppressed")
		}
	}
}
