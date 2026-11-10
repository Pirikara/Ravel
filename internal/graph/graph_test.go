package graph

import (
	"strings"
	"testing"

	"github.com/Pirikara/Ravel/internal/model"
)

func graphFixture() model.Document {
	return model.Document{
		Project: "test <project>",
		Components: []model.Component{
			{ID: "a", Name: "A", Version: "1"},
			{ID: "b", Name: "B", Version: "1"},
			{ID: "shared", Name: "<script>alert(1)</script>", Version: "2", PURL: "pkg:npm/shared@2"},
			{ID: "orphan", Name: "orphan", Version: "1"},
		},
		Edges: []model.Edge{
			{From: "root", To: "a", Kind: "direct"},
			{From: "root", To: "b", Kind: "direct"},
			{From: "a", To: "shared", Kind: "transitive", Condition: "feature <on>"},
			{From: "b", To: "shared", Kind: "transitive"},
			{From: "shared", To: "a", Kind: "cycle"},
		},
		Origins:  []model.Origin{{Occurrence: "shared", Kind: "registry", SafeURL: "https://example.invalid/?x=<unsafe>", Status: "declared"}},
		Coverage: model.Coverage{GraphState: "partial", OriginState: "partial"},
	}
}

func TestBuildPreservesSharedDependenciesCyclesAndUnlinked(t *testing.T) {
	doc := graphFixture()
	view, err := Build(doc, Options{Direction: "dependencies", Depth: -1})
	if err != nil {
		t.Fatal(err)
	}
	if len(view.Nodes) != 5 || len(view.Edges) != 5 || view.Unlinked != 1 {
		t.Fatalf("nodes=%d edges=%d unlinked=%d", len(view.Nodes), len(view.Edges), view.Unlinked)
	}
	foundOrigin := false
	for _, node := range view.Nodes {
		foundOrigin = foundOrigin || node.ID == "shared" && len(node.Origins) == 1
	}
	if !foundOrigin {
		t.Fatal("registry provenance missing from shared dependency")
	}
	view, err = Build(doc, Options{Focus: "a", Direction: "dependencies", Depth: 1})
	if err != nil || len(view.Nodes) != 2 || len(view.Edges) != 2 {
		t.Fatalf("focused cycle: nodes=%d edges=%d error=%v", len(view.Nodes), len(view.Edges), err)
	}
	view, err = Build(doc, Options{Focus: "shared", Direction: "dependents", Depth: 1})
	if err != nil || len(view.Nodes) != 3 || len(view.Edges) != 3 {
		t.Fatalf("focused dependents: nodes=%d edges=%d error=%v", len(view.Nodes), len(view.Edges), err)
	}
	view, err = Build(doc, Options{Focus: "a", Direction: "dependencies", Depth: 0})
	if err != nil || len(view.Nodes) != 1 || view.Unlinked != 0 {
		t.Fatalf("focus depth zero mislabels connected package as unlinked: %#v, %v", view, err)
	}
}

func TestRenderHTMLAndDOTEscapeUntrustedContent(t *testing.T) {
	view, err := Build(graphFixture(), Options{Direction: "dependencies", Depth: -1})
	if err != nil {
		t.Fatal(err)
	}
	page, err := HTML(view)
	if err != nil {
		t.Fatal(err)
	}
	content := string(page)
	if strings.Contains(content, "<script>") || strings.Contains(content, "<unsafe>") || !strings.Contains(content, "&lt;script&gt;") || !strings.Contains(content, "class=\"edge conditional\"") || !strings.Contains(content, "graph is partial") {
		t.Fatalf("HTML escaped content or graph semantics missing: %s", content)
	}
	dot := string(DOT(view))
	if !strings.Contains(dot, "\"a\" -> \"shared\"") || !strings.Contains(dot, "feature <on>") || !strings.Contains(dot, "style=dashed") {
		t.Fatalf("DOT graph semantics missing: %s", dot)
	}
}

func TestBuildRejectsAmbiguityAndRenderCaps(t *testing.T) {
	doc := graphFixture()
	doc.Components = append(doc.Components, model.Component{ID: "another", Name: "A"})
	if _, err := Build(doc, Options{Focus: "A", Direction: "dependencies", Depth: -1}); err == nil {
		t.Fatal("ambiguous focus accepted")
	}
	view := View{Nodes: make([]Node, 301)}
	if _, err := HTML(view); err == nil {
		t.Fatal("oversized HTML graph accepted")
	}
}
