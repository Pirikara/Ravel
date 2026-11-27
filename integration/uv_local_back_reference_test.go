package integration_test

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestUVLocalApplicationDependencyTarget(t *testing.T) {
	doc := scanDevelopmentSample(t, filepath.Join("..", "testdata", "fixtures", "uv-local-back-reference", "uv.lock"))
	if len(doc.Components) != 3 || len(doc.Edges) != 4 {
		t.Fatalf("components=%d edges=%d", len(doc.Components), len(doc.Edges))
	}
	local, registry, addon, context := "", "", "", ""
	for _, c := range doc.Components {
		switch {
		case c.Name == "addon":
			addon = c.ID
		case c.Name == "work-app" && c.Version == "1.0.0":
			local, context = c.ID, c.Context
			if c.Kind != "application" || c.PURL != "" {
				t.Fatal(c)
			}
		case c.Name == "work-app" && c.Version == "3.0.0":
			registry = c.ID
		default:
			t.Fatal(c)
		}
	}
	if local == "" || registry == "" || addon == "" || context == "" {
		t.Fatal(doc.Components)
	}
	expected := map[string]string{"root|" + local: "", local + "|" + registry: "", local + "|" + addon: "extra=feature", addon + "|" + local: ""}
	for _, edge := range doc.Edges {
		key := edge.From + "|" + edge.To
		required, ok := expected[key]
		if !ok || !strings.Contains(edge.Condition, required) {
			t.Fatal(edge)
		}
		delete(expected, key)
		if (edge.From == local || edge.To == local) && !strings.Contains(edge.Condition, context) {
			t.Fatal("local fork context lost", edge)
		}
	}
	if len(expected) > 0 {
		t.Fatal(expected)
	}
	for _, issue := range doc.Coverage.Issues {
		if issue.Code == "unresolved_dependency" || issue.Code == "ambiguous_dependency" {
			t.Fatal(issue)
		}
	}
	assertDevelopmentExports(t, doc)
}
