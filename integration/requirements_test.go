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

func TestRequirementsIncludesAndUnidentifiedArtifact(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "requirements.txt")
	child := filepath.Join(dir, "nested.txt")
	if err := os.WriteFile(root, []byte("-r nested.txt\nhttps://downloads.example.test/unknown.whl\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(child, []byte("known==1.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(executable, "scan", root, "--format", "ravel-json")
	data, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	var doc model.Document
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Components) != 1 || doc.Components[0].Name != "known" {
		t.Fatalf("unnamed URL was incorrectly assigned a package identity: %#v", doc.Components)
	}
	found := false
	for _, issue := range doc.Coverage.Issues {
		found = found || issue.Code == "unnamed_artifact_unresolved"
	}
	if !found {
		t.Fatal("unidentified artifact not reported")
	}
	cmd = exec.Command(executable, "scan", root, "--output", child)
	if output, err := cmd.CombinedOutput(); err == nil || !strings.Contains(string(output), "cannot overwrite an included input") {
		t.Fatalf("included requirements file could be overwritten: %v %s", err, output)
	}
	unchanged, err := os.ReadFile(child)
	if err != nil || string(unchanged) != "known==1.0\n" {
		t.Fatal("included requirements file was modified")
	}
	if err := os.WriteFile(child, []byte("-r requirements.txt\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd = exec.Command(executable, "scan", root)
	if output, err := cmd.CombinedOutput(); err == nil || !strings.Contains(string(output), "cyclic or repeated requirements include") {
		t.Fatalf("cyclic requirements include accepted: %v %s", err, output)
	}
	if err := os.WriteFile(root, []byte{'c', 'a', 'f', '\xe9', '=', '=', '1', '.', '0', '\n'}, 0o644); err != nil {
		t.Fatal(err)
	}
	cmd = exec.Command(executable, "scan", root)
	if output, err := cmd.CombinedOutput(); err == nil || !strings.Contains(string(output), "not UTF-8") {
		t.Fatalf("invalid requirements encoding accepted: %v %s", err, output)
	}
}
