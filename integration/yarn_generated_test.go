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

func TestYarnGeneratedWorkspaceManifestProtection(t *testing.T) {
	fixture := filepath.Join("..", "testdata", "fixtures", "yarn-generated-4")
	manifest := filepath.Join(fixture, "packages", "alpha", "package.json")
	before, err := os.ReadFile(manifest)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(executable, "scan", fixture, "--output", manifest)
	if output, err := cmd.CombinedOutput(); err == nil || !strings.Contains(string(output), "cannot overwrite") {
		t.Fatalf("Yarn workspace manifest overwritten: %v, %s", err, output)
	}
	after, err := os.ReadFile(manifest)
	if err != nil || string(after) != string(before) {
		t.Fatal("Yarn workspace manifest changed during scan")
	}

	copyRoot := t.TempDir()
	lock, err := os.ReadFile(filepath.Join(fixture, "yarn.lock"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(copyRoot, "yarn.lock"), lock, 0o600); err != nil {
		t.Fatal(err)
	}
	data, err := exec.Command(executable, "scan", copyRoot, "--format", "ravel-json").Output()
	if err != nil {
		t.Fatal(err)
	}
	var doc model.Document
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	for _, component := range doc.Components {
		if component.Version == "0.0.0-use.local" {
			t.Fatal("Yarn workspace sentinel was emitted as a package version")
		}
	}
	if !hasArchiveIssue(doc, "workspace_version_unresolved") {
		t.Fatal("missing Yarn workspace manifest was not reported")
	}
}
