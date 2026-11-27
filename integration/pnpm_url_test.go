package integration_test

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestPnpmNamedURLArchives(t *testing.T) {
	for _, sample := range []struct {
		fixture      string
		count, forks int
		version      string
	}{
		{"pnpm-url-occurrences", 7, 2, "1.0.0"},
		{"pnpm-v6-url", 2, 1, "2.0.0"},
	} {
		t.Run(sample.fixture, func(t *testing.T) {
			doc := scanDevelopmentSample(t, filepath.Join("..", "testdata", "fixtures", sample.fixture, "pnpm-lock.yaml"))
			if len(doc.Components) != sample.count {
				t.Fatal(doc.Components)
			}
			forks := map[string]bool{}
			helper := ""
			unknown := ""
			for _, c := range doc.Components {
				if c.Name == "helper" {
					helper = c.ID
				}
				if c.Name == "@scope/unversioned" {
					unknown = c.ID
					if c.Version != "" || c.PURL != "" {
						t.Fatal(c)
					}
				}
				if c.Name != "demo" {
					continue
				}
				for _, origin := range doc.Origins {
					if origin.Occurrence == c.ID && origin.Kind == "download_url" {
						if origin.SafeURL != "https://downloads.example.test/demo.tgz" || c.Version != sample.version || c.PURLBasis != "source_qualified" || !strings.Contains(c.PURL, "download_url=") {
							t.Fatal(c, origin)
						}
						forks[c.ID] = false
					}
				}
			}
			if len(forks) != sample.forks || helper == "" {
				t.Fatal(forks, helper)
			}
			for _, edge := range doc.Edges {
				if _, ok := forks[edge.From]; ok && edge.To == helper {
					forks[edge.From] = true
				}
			}
			for id, reached := range forks {
				if !reached {
					t.Fatalf("URL occurrence lost its helper edge: %s", id)
				}
			}
			if sample.fixture == "pnpm-url-occurrences" {
				unresolved := false
				for _, issue := range doc.Coverage.Issues {
					if issue.Code == "version_unresolved" && issue.Name == "@scope/unversioned" {
						unresolved = true
					}
				}
				if unknown == "" || !unresolved {
					t.Fatal("unknown URL version was not retained with coverage")
				}
			}
			assertDevelopmentExports(t, doc)
		})
	}
}
