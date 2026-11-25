package integration_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Pirikara/Ravel/internal/model"
	"github.com/Pirikara/Ravel/internal/report"
)

func diffFixtureProject(t *testing.T, directory string) {
	t.Helper()
	for _, name := range []string{"package.json", "package-lock.json"} {
		data, err := os.ReadFile(filepath.Join("..", "testdata", "fixtures", "npm-generated-12", name))
		if err != nil {
			t.Fatal(err)
		}
		runtimeTestWrite(t, directory, name, string(data))
	}
	runtimeTestWrite(t, directory, ".node-version", "22.0.0\n")
}

func diffScan(t *testing.T, directory string, extra ...string) (string, model.Document) {
	t.Helper()
	output := filepath.Join(t.TempDir(), "scan.json")
	args := append([]string{"scan", directory, "--format", "ravel-json", "--output", output}, extra...)
	if out, err := exec.Command(executable, args...).CombinedOutput(); err != nil {
		t.Fatalf("scan: %v: %s", err, out)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var doc model.Document
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	return output, doc
}

func cliDiff(t *testing.T, before, after string) (report.Diff, string) {
	t.Helper()
	data, err := exec.Command(executable, "diff", before, after, "--format", "json").CombinedOutput()
	if err != nil {
		t.Fatalf("JSON diff: %v: %s", err, data)
	}
	var diff report.Diff
	if err := json.Unmarshal(data, &diff); err != nil {
		t.Fatal(err)
	}
	text, err := exec.Command(executable, "diff", before, after).CombinedOutput()
	if err != nil {
		t.Fatalf("text diff: %v: %s", err, text)
	}
	return diff, string(text)
}

func TestDiffRepositoryRootAndRuntimeChanges(t *testing.T) {
	project := t.TempDir()
	diffFixtureProject(t, project)
	beforePath, before := diffScan(t, project)
	runtimeTestWrite(t, project, "package.json", `{"name":"ravel-npm-generated","version":"2.0.0","dependencies":{"is-number":"7.0.0"}}`)
	runtimeTestWrite(t, project, ".node-version", "24.0.0\n")
	afterPath, after := diffScan(t, project)
	if before.Root == nil || after.Root == nil || before.Root.Version != "1.0.0" || after.Root.Version != "2.0.0" || len(before.Runtimes) != 1 || len(after.Runtimes) != 1 {
		t.Fatalf("scan did not retain root/runtime declarations: before=%+v after=%+v", before, after)
	}
	diff, text := cliDiff(t, beforePath, afterPath)
	if diff.RootChange == nil || diff.RootChange.Before.Version != "1.0.0" || diff.RootChange.After.Version != "2.0.0" || len(diff.AddedRuntimes) != 1 || diff.AddedRuntimes[0].Requirement != "24.0.0" || len(diff.RemovedRuntimes) != 1 || diff.RemovedRuntimes[0].Requirement != "22.0.0" {
		t.Fatalf("root/runtime changes missing from JSON diff: %+v", diff)
	}
	if len(diff.AddedComponents)+len(diff.RemovedComponents)+len(diff.ChangedComponents)+len(diff.AddedEdges)+len(diff.RemovedEdges) != 0 {
		t.Fatalf("declaration changes altered unchanged dependency diff: %+v", diff)
	}
	for _, expected := range []string{"~ application ravel-npm-generated@1.0.0 -> ravel-npm-generated@2.0.0", "- runtime node selection \"22.0.0\"", "+ runtime node selection \"24.0.0\""} {
		if !strings.Contains(text, expected) {
			t.Fatalf("text diff lacks %q: %s", expected, text)
		}
	}
}

func TestDiffRecursiveScanAddingAndRemovingProject(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"b", "c"} {
		diffFixtureProject(t, filepath.Join(root, name))
	}
	beforePath, before := diffScan(t, root, "--all", "--recursive")
	addedProject := filepath.Join(root, "a") // Sorts before the existing inputs.
	diffFixtureProject(t, addedProject)
	afterPath, after := diffScan(t, root, "--all", "--recursive")
	if len(before.Components) != 4 || len(after.Components) != 6 {
		t.Fatalf("unexpected inventory: before=%d after=%d", len(before.Components), len(after.Components))
	}
	diff, _ := cliDiff(t, beforePath, afterPath)
	if len(diff.AddedComponents) != 2 || len(diff.RemovedComponents)+len(diff.ChangedComponents) != 0 || len(diff.AddedEdges) != 2 || len(diff.RemovedEdges) != 0 || len(diff.AddedOrigins) != 1 || len(diff.RemovedOrigins) != 0 || len(diff.AddedRuntimes) != 1 || len(diff.RemovedRuntimes) != 0 {
		t.Fatalf("added project changed existing occurrences: %+v", diff)
	}
	for _, component := range diff.AddedComponents {
		if len(component.Evidence) == 0 || !strings.HasPrefix(component.Evidence[0].InputPath, addedProject+string(filepath.Separator)) {
			t.Fatalf("an existing occurrence was reported as new: %+v", component)
		}
	}
	if err := os.RemoveAll(addedProject); err != nil {
		t.Fatal(err)
	}
	removedPath, _ := diffScan(t, root, "--all", "--recursive")
	diff, _ = cliDiff(t, afterPath, removedPath)
	if len(diff.RemovedComponents) != 2 || len(diff.AddedComponents)+len(diff.ChangedComponents) != 0 || len(diff.RemovedEdges) != 2 || len(diff.AddedEdges) != 0 || len(diff.RemovedOrigins) != 1 || len(diff.AddedOrigins) != 0 || len(diff.RemovedRuntimes) != 1 || len(diff.AddedRuntimes) != 0 {
		t.Fatalf("removed project changed remaining occurrences: %+v", diff)
	}
}
