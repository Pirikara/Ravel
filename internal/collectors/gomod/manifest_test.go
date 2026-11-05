package gomod

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCollectManifestKeepsDeclaredModulesWithoutInventingTransitiveEdges(t *testing.T) {
	root := t.TempDir()
	mod := filepath.Join(root, "go.mod")
	content := `module example.com/app

go 1.25

require (
  example.com/local v1.0.0
  example.com/forked/v2 v2.0.0 // indirect
  example.com/registry/v3 v3.0.0 // indirect
)

replace example.com/local => ./local
replace example.com/forked/v2 => example.com/fork/v2 v2.1.0
`
	if err := os.WriteFile(mod, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "go.work"), []byte("go 1.25\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	doc, err := CollectManifest(mod, "app")
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Components) != 4 || len(doc.Edges) != 2 || doc.Coverage.Packages != 4 || doc.Coverage.GraphState != "partial" || doc.Coverage.OriginState != "partial" {
		t.Fatalf("manifest coverage or graph is wrong: %#v", doc)
	}
	if len(doc.Sources) != 1 || doc.Sources[0] != filepath.Join(root, "go.work") {
		t.Fatalf("workspace was not reported: %#v", doc.Sources)
	}
	components := map[string]string{}
	mainRef := ""
	for _, component := range doc.Components {
		components[component.Name] = component.PURL
		if component.Name == "example.com/app" {
			mainRef = component.ID
			if component.Kind != "application" || component.Version != "" || component.PURL != "pkg:golang/example.com/app" {
				t.Fatalf("main module identity is wrong: %#v", component)
			}
		}
		if component.Evidence[0].Method != "manifest-analysis" || component.Evidence[0].InputPath != mod {
			t.Fatalf("module evidence is wrong: %#v", component)
		}
	}
	if components["example.com/local"] != "" || components["example.com/forked/v2"] != "" || components["example.com/registry/v3"] != "pkg:golang/example.com/registry/v3@v3.0.0" {
		t.Fatalf("replacement identity was misrepresented: %#v", components)
	}
	if mainRef == "" {
		t.Fatal("main module missing")
	}
	var projectEdge, directEdge bool
	for _, edge := range doc.Edges {
		projectEdge = projectEdge || edge.From == "root" && edge.To == mainRef
		directEdge = directEdge || edge.From == mainRef && edge.Kind == "direct"
	}
	if !projectEdge || !directEdge {
		t.Fatalf("main module or direct requirement edge is wrong: %#v", doc.Edges)
	}
	origins := map[string]bool{}
	for _, origin := range doc.Origins {
		origins[origin.Kind+"|"+origin.Target] = true
	}
	if !origins["local|"] || !origins["module_replacement|example.com/fork/v2@v2.1.0"] {
		t.Fatalf("replacement origins are missing: %#v", doc.Origins)
	}
}

func TestCollectManifestAcceptsLocalMainModulePath(t *testing.T) {
	mod := filepath.Join(t.TempDir(), "go.mod")
	if err := os.WriteFile(mod, []byte("module local\n\ngo 1.23\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	doc, err := CollectManifest(mod, "local")
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Components) != 1 || doc.Components[0].Name != "local" || doc.Components[0].PURL != "" || len(doc.Edges) != 1 || doc.Edges[0].To != doc.Components[0].ID {
		t.Fatalf("local main module was misrepresented: %#v", doc)
	}
}
