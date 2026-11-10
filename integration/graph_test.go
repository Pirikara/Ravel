package integration_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestGraphCommandFromScannedAndMergedInputs(t *testing.T) {
	root := t.TempDir()
	fixtures := []struct{ name, input string }{
		{"npm", "npm-generated-12"},
		{"cargo", "cargo-basic"},
		{"go", "go-vendor-basic"},
	}
	results := []string{}
	for _, fixture := range fixtures {
		input := filepath.Join("..", "testdata", "fixtures", fixture.input)
		result := filepath.Join(root, fixture.name+".ravel.json")
		cmd := exec.Command(executable, "scan", input, "--format", "ravel-json", "--output", result)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("scan %s: %v: %s", fixture.name, err, output)
		}
		results = append(results, result)
	}
	merged := filepath.Join(root, "merged.ravel.json")
	if output, err := exec.Command(executable, "merge", "--format", "ravel-json", "--output", merged, results[0], results[1]).CombinedOutput(); err != nil {
		t.Fatalf("merge for graph: %v: %s", err, output)
	}
	for _, input := range append(results, merged) {
		name := strings.TrimSuffix(filepath.Base(input), ".ravel.json")
		page := filepath.Join(root, name+".html")
		if output, err := exec.Command(executable, "graph", "--input", input, "--format", "html", "--output", page).CombinedOutput(); err != nil {
			t.Fatalf("graph HTML %s: %v: %s", name, err, output)
		}
		content, err := os.ReadFile(page)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(content), "<svg") || !strings.Contains(string(content), "Graph coverage:") || !strings.Contains(string(content), "Components and origins") {
			t.Fatalf("graph HTML incomplete for %s", name)
		}
		if name == "go" && !strings.Contains(string(content), "graph is partial") {
			t.Fatal("Go graph omitted partial-coverage notice")
		}
		if name == "cargo" && (!strings.Contains(string(content), "feature_or_target_unselected") || !strings.Contains(string(content), "class=\"edge conditional\"")) {
			t.Fatal("Cargo graph omitted conditional dependency")
		}
		if name == "npm" && !strings.Contains(string(content), "https://registry.npmjs.org/is-number/") {
			t.Fatal("npm graph omitted recorded package origin")
		}
	}
	dot, err := exec.Command(executable, "graph", "--input", results[0], "--format", "dot", "--focus", "root", "--depth", "1").Output()
	if err != nil || !strings.Contains(string(dot), "digraph ravel") || !strings.Contains(string(dot), "->") {
		t.Fatalf("focused DOT: %v: %s", err, dot)
	}
	if output, err := exec.Command(executable, "graph", "--input", results[0], "--output", results[0]).CombinedOutput(); err == nil || !strings.Contains(string(output), "usage:") {
		t.Fatalf("graph overwrote input: %v: %s", err, output)
	}
}
