package integration_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestYarnClassicWorkspaceClosure(t *testing.T) {
	fixture := filepath.Join("..", "testdata", "fixtures", "yarn-classic-workspace-closure")
	doc := scanDevelopmentSample(t, filepath.Join(fixture, "yarn.lock"))
	if len(doc.Components) != 10 || len(doc.Edges) != 9 {
		t.Fatalf("got %d components / %d edges", len(doc.Components), len(doc.Edges))
	}
	expected := map[string]bool{"tool-app@1.0.0": true, "client@1.0.0": true, "standalone@2.0.0": true, "local-core@1.2.0": true, "root-tool@1.0.0": true, "optional-lib@4.0.0": true, "shared@1.1.0": true, "independent@5.0.0": true, "client-lib@3.0.0": true, "local-core@2.1.0": true}
	ids := map[string]string{"root": "root"}
	for _, c := range doc.Components {
		coordinate := c.Name + "@" + c.Version
		if !expected[coordinate] {
			t.Fatalf("unexpected or repeated identity %s", coordinate)
		}
		delete(expected, coordinate)
		ids[c.ID] = coordinate
		if c.Kind == "application" && (c.PURL != "" || !strings.HasPrefix(c.Context, "workspace=")) {
			t.Fatalf("local application became registry package: %+v", c)
		}
	}
	if len(expected) > 0 {
		t.Fatal(expected)
	}
	edges := map[string]string{"root -> root-tool@1.0.0": "", "root -> local-core@2.1.0": "", "tool-app@1.0.0 -> shared@1.1.0": "", "client@1.0.0 -> local-core@1.2.0": "", "client@1.0.0 -> optional-lib@4.0.0": "optional", "client@1.0.0 -> client-lib@3.0.0": "", "standalone@2.0.0 -> independent@5.0.0": "", "local-core@1.2.0 -> shared@1.1.0": "", "client-lib@3.0.0 -> shared@1.1.0": ""}
	for _, edge := range doc.Edges {
		pair := ids[edge.From] + " -> " + ids[edge.To]
		condition, ok := edges[pair]
		if !ok || condition != edge.Condition {
			t.Fatalf("unexpected edge %s %q", pair, edge.Condition)
		}
		delete(edges, pair)
		if ids[edge.From] == "client@1.0.0" && !strings.HasSuffix(edge.Evidence.InputPath, "packages/client/package.json") {
			t.Fatal("workspace dependency lost manifest evidence", edge)
		}
	}
	if len(edges) > 0 {
		t.Fatal(edges)
	}
	for _, issue := range doc.Coverage.Issues {
		if issue.Code == "unreachable_graph" || issue.Code == "workspace_unresolved" {
			t.Fatal(issue)
		}
	}
	assertDevelopmentExports(t, doc)
	manifest := filepath.Join(fixture, "packages", "client", "package.json")
	before, err := os.ReadFile(manifest)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(executable, "scan", filepath.Join(fixture, "yarn.lock"), "--output", manifest)
	if out, err := cmd.CombinedOutput(); err == nil || !strings.Contains(string(out), "cannot overwrite") {
		t.Fatalf("workspace manifest overwrite guard: %v %s", err, out)
	}
	after, err := os.ReadFile(manifest)
	if err != nil || string(before) != string(after) {
		t.Fatal("workspace input changed")
	}
}
