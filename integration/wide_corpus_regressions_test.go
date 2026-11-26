package integration_test

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestWideCorpusRegressions(t *testing.T) {
	for _, sample := range []struct {
		fixture, file string
		count         int
	}{
		{"deno-v2-closure", "deno.lock", 2},
		{"bundler-linux-libc", "Gemfile.lock", 3},
		{"yarn-workspace-roots", "yarn.lock", 3},
	} {
		t.Run(sample.fixture, func(t *testing.T) {
			doc := scanDevelopmentSample(t, filepath.Join("..", "testdata", "fixtures", sample.fixture, sample.file))
			if len(doc.Components) != sample.count {
				t.Fatal(doc.Components, doc.Coverage.Issues)
			}
			names := map[string]string{}
			for _, c := range doc.Components {
				names[c.ID] = c.Name
				if c.Name == "unused" {
					t.Fatal("unreferenced external lock entry included")
				}
				if c.Name == "native" && (c.Version != "1.2.3" || !strings.HasPrefix(c.Platform, "aarch64-linux-") || !strings.Contains(c.PURL, "platform="+c.Platform)) {
					t.Fatal(c)
				}
				if c.Name == "pre" && (c.Version != "2.0.0-pre" || c.Platform != "") {
					t.Fatal(c)
				}
				if c.Name == "app" && (c.Version != "2.3.4" || c.Kind != "application") {
					t.Fatal(c)
				}
			}
			if sample.fixture == "yarn-workspace-roots" {
				if len(doc.Development) != 1 || doc.Development[0].SafeURL != "https://code.example.test/workspaces/app" {
					t.Fatal(doc.Development)
				}
				found := false
				for _, e := range doc.Edges {
					found = found || names[e.From] == "app" && names[e.To] == "app-library"
					if e.From == "root" && names[e.To] != "root-tool" {
						t.Fatal("workspace membership became a root dependency", e)
					}
				}
				if !found {
					t.Fatal(doc.Edges)
				}
			}
			if sample.fixture == "deno-v2-closure" {
				if len(doc.Edges) != 2 {
					t.Fatal(doc.Edges)
				}
				found := false
				for _, e := range doc.Edges {
					found = found || names[e.From] == "primary" && names[e.To] == "leaf"
				}
				if !found {
					t.Fatal(doc.Edges)
				}
			}
			assertDevelopmentExports(t, doc)
		})
	}
}
