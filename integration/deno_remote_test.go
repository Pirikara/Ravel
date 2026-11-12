package integration_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Pirikara/Ravel/internal/model"
)

func TestDenoUnlinkedRemoteLockRecords(t *testing.T) {
	fixture := filepath.Join("..", "testdata", "fixtures", "deno-remote-unlinked")
	output := filepath.Join(t.TempDir(), "ravel.json")
	if data, err := exec.Command(executable, "scan", fixture, "--format", "ravel-json", "--output", output).CombinedOutput(); err != nil {
		t.Fatalf("scan failed: %v: %s", err, data)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var doc model.Document
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Components) != 1 || doc.Components[0].Name != "https://cdn.example.test/direct.ts" ||
		len(doc.Edges) != 1 || doc.Coverage.GraphState != "partial" {
		t.Fatalf("unlinked lock records were included in the graph: %#v", doc)
	}
	unlinked := map[string]bool{}
	for _, issue := range doc.Coverage.Issues {
		if issue.Code == "lock_remote_reachability_unknown" {
			unlinked[issue.Name] = true
		}
	}
	if len(unlinked) != 2 || !unlinked["https://cdn.example.test/unlinked.ts"] || !unlinked["https://cdn.example.test/private.ts"] {
		t.Fatalf("unlinked remote records missing or unsafe: %#v", unlinked)
	}
	if strings.Contains(string(data), "secret") || strings.Contains(string(data), "hidden") {
		t.Fatal("remote lockfile credentials leaked")
	}
}

func TestDenoResolveCLIRejectsPrivateRemoteWithoutExecuting(t *testing.T) {
	fixture := t.TempDir()
	if err := os.WriteFile(filepath.Join(fixture, "main.ts"), []byte(`import "https://127.0.0.1/private.ts";`), 0o600); err != nil {
		t.Fatal(err)
	}
	lock := `{"version":"5","remote":{"https://127.0.0.1/private.ts":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}`
	if err := os.WriteFile(filepath.Join(fixture, "deno.lock"), []byte(lock), 0o600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "ravel.json")
	if data, err := exec.Command(executable, "scan", fixture, "--resolve", "--network", "allow", "--format", "ravel-json", "--output", output).CombinedOutput(); err != nil {
		t.Fatalf("Deno resolved scan failed: %v: %s", err, data)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var doc model.Document
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Components) != 1 || len(doc.Edges) != 1 {
		t.Fatalf("unexpected resolved graph: %d components, %d edges", len(doc.Components), len(doc.Edges))
	}
	found := false
	for _, issue := range doc.Coverage.Issues {
		found = found || issue.Code == "remote_source_unavailable" && issue.Name == "https://127.0.0.1/private.ts"
	}
	if !found {
		t.Fatalf("private remote was not reported unavailable: %#v", doc.Coverage.Issues)
	}
}
