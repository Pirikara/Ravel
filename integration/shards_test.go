package integration_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"ravel/internal/model"
)

func scanShards(t *testing.T, input string, extra ...string) model.Document {
	t.Helper()
	args := append([]string{"scan", input, "--format", "ravel-json"}, extra...)
	out, err := exec.Command(executable, args...).Output()
	if err != nil {
		t.Fatalf("Shards scan %v: %v", args, err)
	}
	var doc model.Document
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func TestShardsLockAndManifest(t *testing.T) {
	fixture := filepath.Join("..", "testdata", "fixtures", "shards-v2")
	doc := scanShards(t, fixture)
	if doc.Coverage.Manager != "shards" || doc.Coverage.Packages != 3 || doc.Coverage.Edges != 3 || len(doc.Origins) != 3 || len(doc.Sources) != 1 {
		t.Fatalf("Shards v2 coverage: %#v", doc.Coverage)
	}
	ids := map[string]string{}
	for _, pkg := range doc.Components {
		ids[pkg.ID] = pkg.Name
		if pkg.PURL != "" || len(pkg.Evidence) != 1 || pkg.Evidence[0].InputDigest == "" {
			t.Fatalf("unverified Shards registry identity or evidence: %#v", pkg)
		}
	}
	development := 0
	for _, edge := range doc.Edges {
		if edge.From != "root" || ids[edge.To] == "" || edge.Kind != "direct" || edge.Evidence.Collector != "shards-manifest" {
			t.Fatalf("invalid Shards direct edge: %#v", edge)
		}
		if edge.Condition == "development" {
			development++
			if ids[edge.To] != "local" {
				t.Fatalf("development category lost: %#v", edge)
			}
		}
	}
	if development != 1 || !dotnetIssue(doc, "shards_transitive_graph_unavailable") {
		t.Fatalf("Shards graph: %#v", doc.Coverage)
	}
	for _, origin := range doc.Origins {
		if ids[origin.Occurrence] == "cli" && (origin.SafeURL != "https://example.org/cli.git" || origin.Revision != "abcdef1234567890abcdef1234567890abcdef12") {
			t.Fatalf("Shards Git origin: %#v", origin)
		}
		if ids[origin.Occurrence] == "local" && (origin.Kind != "local" || origin.LocalPath != "../local") {
			t.Fatalf("Shards local origin: %#v", origin)
		}
	}
	encoded, err := json.Marshal(doc)
	if err != nil || strings.Contains(string(encoded), "hidden") || strings.Contains(string(encoded), "secret") || strings.Contains(string(encoded), "?token=") {
		t.Fatalf("Shards URL credential leaked: %v", err)
	}
}

func TestShardsLegacyAndPartial(t *testing.T) {
	base := filepath.Join("..", "testdata", "fixtures")
	v1 := scanShards(t, filepath.Join(base, "shards-v1", "shard.lock"))
	if v1.Coverage.Packages != 2 || v1.Coverage.Edges != 0 || len(v1.Origins) != 2 || !dotnetIssue(v1, "missing_direct_dependencies") {
		t.Fatalf("Shards v1 coverage: %#v", v1.Coverage)
	}
	legacy := false
	for _, pkg := range v1.Components {
		if pkg.Name == "legacy" && pkg.Version == "abcdef1234567890abcdef1234567890abcdef12" {
			legacy = true
		}
	}
	if !legacy {
		t.Fatal("legacy commit-only lock identity missing")
	}
	partial := scanShards(t, filepath.Join(base, "shards-partial"))
	if partial.Coverage.Packages != 1 || partial.Coverage.Edges != 0 || len(partial.Origins) != 0 || !dotnetIssue(partial, "shards_package_invalid") || !dotnetIssue(partial, "shards_source_unresolved") || !dotnetIssue(partial, "unresolved_dependency") {
		t.Fatalf("Shards partial coverage: %#v", partial.Coverage)
	}
}

func TestShardsDiscoveryAndExports(t *testing.T) {
	fixture := filepath.Join("..", "testdata", "fixtures", "shards-v2")
	root := t.TempDir()
	nested := filepath.Join(root, "crystal")
	if err := os.Mkdir(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"shard.lock", "shard.yml"} {
		data, err := os.ReadFile(filepath.Join(fixture, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(nested, name), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, args := range [][]string{{nested}, {nested, "--manager", "shards"}, {root, "--all", "--recursive"}} {
		doc := scanShards(t, args[0], args[1:]...)
		if doc.Coverage.Packages != 3 || doc.Coverage.Edges != 3 {
			t.Fatalf("Shards discovery %v: %#v", args, doc.Coverage)
		}
	}
	for _, format := range []string{"cyclonedx-json", "spdx-json"} {
		out, err := exec.Command(executable, "scan", fixture, "--format", format).Output()
		if err != nil || !json.Valid(out) {
			t.Fatalf("Shards %s export: %v", format, err)
		}
	}
}
