package integration_test

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestMissingWorkspaceNameUsesMatchingManifest(t *testing.T) {
	doc := scanDevelopmentSample(t, filepath.Join("..", "testdata", "fixtures", "npm-workspace-missing-name", "package-lock.json"))
	if len(doc.Components) != 3 {
		t.Fatal(doc.Components)
	}
	app, helper, builder := "", "", ""
	for _, c := range doc.Components {
		switch c.Name {
		case "frontend":
			app = c.ID
			if c.Kind != "application" || c.Version != "0.1.0" || c.PURL != "" || len(c.Evidence) != 2 || c.Evidence[1].Collector != "npm-local-manifest" {
				t.Fatal(c)
			}
		case "helper":
			helper = c.ID
		case "builder":
			builder = c.ID
		}
	}
	found := map[string]string{}
	for _, e := range doc.Edges {
		if e.From == app {
			found[e.To] = e.Kind
		}
	}
	if app == "" || found[helper] != "depends_on" || found[builder] != "direct_dev" {
		t.Fatal(doc.Edges)
	}
	if len(doc.Development) != 1 || doc.Development[0].Occurrence != app || doc.Development[0].Status != "declared" {
		t.Fatal(doc.Development)
	}
	assertDevelopmentExports(t, doc)
}

func TestGenericRubyArtifactWithSpecificLinuxHosts(t *testing.T) {
	doc := scanDevelopmentSample(t, filepath.Join("..", "testdata", "fixtures", "bundler-generic-linux-artifact", "Gemfile.lock"))
	if len(doc.Components) != 3 {
		t.Fatal(doc.Components)
	}
	for _, c := range doc.Components {
		switch c.Name {
		case "generic":
			if c.Version != "1.2.3" || c.Platform != "x86_64-linux" || !strings.Contains(c.PURL, "platform=x86_64-linux") {
				t.Fatal(c)
			}
		case "native":
			if c.Version != "2.0.0" || c.Platform != "x86_64-linux-musl" {
				t.Fatal(c)
			}
		case "prerelease":
			if c.Version != "3.0.0.pre" || c.Platform != "" {
				t.Fatal(c)
			}
		}
	}
	assertDevelopmentExports(t, doc)
}
