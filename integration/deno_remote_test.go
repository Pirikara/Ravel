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
