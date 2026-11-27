package integration_test

import (
	"bytes"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Pirikara/Ravel/internal/export"
)

func TestUpstreamRegressionConditions(t *testing.T) {
	for _, tc := range []struct {
		name, file string
		count      int
	}{
		{"pnpm-v6-archive-metadata", "pnpm-lock.yaml", 6},
		{"pnpm-registry-prefixes", "pnpm-lock.yaml", 5},
		{"uv-package-resolution-forks", "uv.lock", 5},
		{"uv-version-pinned-forks", "uv.lock", 5},
		{"bundler-whitespace-lines", "Gemfile.lock", 3},
		{"pnpm-importer-overlap", "pnpm-lock.yaml", 6},
		{"npm-v1-bundled-tree", "package-lock.json", 3},
		{"yarn-classic-incomplete-values", "yarn.lock", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc := scanDevelopmentSample(t, filepath.Join("..", "testdata", "fixtures", tc.name, tc.file))
			if len(doc.Components) != tc.count {
				t.Fatalf("components: got %d, want %d", len(doc.Components), tc.count)
			}
			names, versions, contexts := map[string]string{}, map[string]string{}, map[string]string{}
			for _, c := range doc.Components {
				names[c.ID], versions[c.ID], contexts[c.ID] = c.Name, c.Version, c.Context
			}
			switch tc.name {
			case "npm-v1-bundled-tree":
				if len(doc.Edges) != 3 {
					t.Fatal(doc.Edges)
				}
			case "yarn-classic-incomplete-values":
				if len(doc.Edges) != 1 || doc.Coverage.GraphState == "complete_for_scope" {
					t.Fatal(doc.Edges, doc.Coverage)
				}
				unresolved := false
				for _, issue := range doc.Coverage.Issues {
					if issue.Code == "unresolved_dependency" {
						unresolved = true
					}
				}
				if !unresolved {
					t.Fatal("incomplete lock did not retain an unresolved condition")
				}

			case "pnpm-v6-archive-metadata":
				want := map[string]string{"tiny": "1.0.0", "forked": "2.0.0", "local-archive": "3.0.0", "local-app": "4.0.0", "unknown": "", "raw": "5.0.0"}
				for _, c := range doc.Components {
					if v, ok := want[c.Name]; !ok || v != c.Version {
						t.Fatal(c)
					}
					if strings.HasPrefix(c.Name, "local-") && c.PURL != "" {
						t.Fatal("local source became a registry assertion", c)
					}
					if c.Name == "local-app" && c.Kind != "application" {
						t.Fatal(c)
					}
					if c.Name == "forked" || c.Name == "raw" {
						if c.PURLBasis != "source_qualified" || !strings.Contains(c.PURL, "download_url=") {
							t.Fatal(c)
						}
					}
				}
				if len(doc.Edges) != 7 {
					t.Fatal(doc.Edges)
				}
			case "pnpm-registry-prefixes":
				if doc.Coverage.OriginState != "partial" {
					t.Fatal("unknown registry endpoint reported as complete")
				}
				issues := map[string]bool{}
				for _, issue := range doc.Coverage.Issues {
					issues[issue.Code] = true
				}
				if !issues["registry_url_unresolved"] || !issues["ambiguous_dependency"] {
					t.Fatal(doc.Coverage)
				}

				for _, c := range doc.Components {
					if c.Name == "plain" && c.PURL != "" {
						t.Fatal("unknown registry URL became the default registry", c)
					}
					if c.Name == "@team/leaf" && (!strings.Contains(c.PURL, "download_url=") || c.Version != "2.0.0") {
						t.Fatal(c)
					}
				}
				for _, e := range doc.Edges {
					if names[e.To] == "collision" {
						t.Fatal("ambiguous registry provider was chosen", e)
					}
				}
				if len(doc.Edges) != 3 {
					t.Fatal(doc.Edges)
				}
				found := false
				for _, o := range doc.Origins {
					if names[o.Occurrence] == "plain" && o.Kind == "registry_identity" && o.Target == "mirror.example.test" {
						found = true
					}
				}
				if !found {
					t.Fatal("registry host identity lost")
				}
				data, err := export.CycloneDX(doc)
				if err != nil {
					t.Fatal(err)
				}
				var bom struct {
					Components []struct {
						Ref        string `json:"bom-ref"`
						Properties []struct{ Name, Value string }
					}
				}
				if err := json.Unmarshal(data, &bom); err != nil {
					t.Fatal(err)
				}
				found = false
				for _, c := range bom.Components {
					if names[c.Ref] == "plain" {
						for _, p := range c.Properties {
							if p.Name == "ravel:registryIdentity" && p.Value == "mirror.example.test" {
								found = true
							}
						}
					}
				}
				if !found {
					t.Fatal("registry host lost from standard format")
				}

			case "uv-package-resolution-forks":
				for _, c := range doc.Components {
					if c.Name == "bridge" && c.Version == "1.0.0" && !strings.Contains(c.Context, "python_full_version < '3.11'") {
						t.Fatal(c)
					}
					if c.Name == "leaf" && c.Version == "2.0.0" && (!strings.Contains(c.Context, "python_full_version >= '3.11' and python_full_version < '3.12'") || !strings.Contains(c.Context, " || ") || !strings.Contains(c.Context, "python_full_version >= '3.12'")) {
						t.Fatal(c)
					}
				}
				bridgeEdge := false
				for _, e := range doc.Edges {
					if names[e.From] == "bridge" {
						bridgeEdge = true
						if !strings.Contains(e.Condition, contexts[e.From]) || contexts[e.From] == "" {
							t.Fatal("source fork condition lost", e)
						}
					}
					if names[e.To] == "bridge" || names[e.To] == "cache" {
						if contexts[e.To] == "" || !strings.Contains(e.Condition, contexts[e.To]) {
							t.Fatal("target fork condition lost", e)
						}
					}
				}
				if !bridgeEdge {
					t.Fatal("bridge dependency lost")
				}
			case "uv-version-pinned-forks":
				if len(doc.Edges) != 6 {
					t.Fatal(doc.Edges)
				}
				legacy := false
				for _, e := range doc.Edges {
					if names[e.From] == "adapter" && names[e.To] == "leaf" && versions[e.From] != versions[e.To] {
						t.Fatal("version forks crossed", e)
					}
					if names[e.From] == "app" && names[e.To] == "leaf" && versions[e.To] == "1.0.0" && strings.Contains(e.Condition, "extra=legacy") {
						legacy = true
					}
				}
				if !legacy {
					t.Fatal("versioned optional dependency lost")
				}
			case "bundler-whitespace-lines":
				if len(doc.Edges) != 3 || doc.Coverage.GraphState != "complete_for_scope" {
					t.Fatal(doc.Edges, doc.Coverage)
				}
			case "pnpm-importer-overlap":
				if len(doc.Edges) != 6 {
					t.Fatal(doc.Edges)
				}
				for _, e := range doc.Edges {
					if e.From == "root" && names[e.To] == "seed" && !strings.Contains(e.Condition, "boot") {
						t.Fatal(e)
					}
					if e.From == "root" && names[e.To] == "core" {
						expected := "workspace=apps/first"
						if versions[e.To] == "2.0.0" {
							expected = "workspace=apps/second"
						}
						if !strings.Contains(e.Condition, expected) {
							t.Fatal(e)
						}
					}
					if names[e.From] == "core" && versions[e.From] != versions[e.To] {
						t.Fatal("importer versions crossed", e)
					}
				}
			}
			assertDevelopmentExports(t, doc)
		})
	}
}

func TestPeerOccurrenceOutputDeterministic(t *testing.T) {
	fixture := filepath.Join("..", "testdata", "fixtures", "pnpm-alias-occurrences", "pnpm-lock.yaml")
	var first []byte
	for range 5 {
		data, err := exec.Command(executable, "scan", fixture, "--format", "ravel-json").Output()
		if err != nil {
			t.Fatal(err)
		}
		if first == nil {
			first = data
		} else if !bytes.Equal(first, data) {
			t.Fatal("same peer occurrences produced nondeterministic output")
		}
	}
}
