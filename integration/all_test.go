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

func TestScanAllStaticManagers(t *testing.T) {
	dir := t.TempDir()
	for _, input := range []struct{ fixture, name string }{
		{"npm-generated-12", "package-lock.json"},
		{"requirements-basic", "requirements.txt"},
		{"requirements-basic", "nested.txt"},
	} {
		data, err := os.ReadFile(filepath.Join("..", "testdata", "fixtures", input.fixture, input.name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, input.name), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	output := filepath.Join(dir, "combined.ravel.json")
	report := filepath.Join(dir, "coverage.json")
	cmd := exec.Command(executable, "scan", dir, "--all", "--format", "ravel-json", "--output", output, "--report", report)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("scan --all failed: %v %s", err, out)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var doc model.Document
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Coverage.Manager != "multi" || doc.Coverage.Packages != 3 || doc.Coverage.Edges != 3 || len(doc.Coverage.Inputs) != 2 {
		t.Fatalf("unexpected multi-manager coverage: %#v", doc.Coverage)
	}
	if len(doc.Sources) != 3 || len(doc.Components) != 3 {
		t.Fatalf("source scopes or packages missing: %#v", doc)
	}
	names := map[string]bool{}
	for _, component := range doc.Components {
		names[component.Name] = true
	}
	if !names["is-number"] || !names["requests"] || !names["idna"] {
		t.Fatalf("multi-manager components missing: %#v", names)
	}
	spdxPath := filepath.Join(dir, "combined.spdx.json")
	cmd = exec.Command(executable, "scan", dir, "--all", "--strict", "--format", "spdx-json", "--output", spdxPath)
	if out, err := cmd.CombinedOutput(); err == nil || !strings.Contains(string(out), "3 packages") {
		t.Fatalf("strict scan did not report partial coverage: %v %s", err, out)
	}
	for _, result := range []struct{ format, path string }{{"spdx-json", spdxPath}, {"cyclonedx-json", filepath.Join(dir, "combined.cdx.json")}} {
		if result.format == "cyclonedx-json" {
			cmd = exec.Command(executable, "scan", dir, "--all", "--format", result.format, "--output", result.path)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("CycloneDX scan --all failed: %v %s", err, out)
			}
		}
		encoded, err := os.ReadFile(result.path)
		if err != nil {
			t.Fatal(err)
		}
		var raw map[string]any
		if err := json.Unmarshal(encoded, &raw); err != nil {
			t.Fatal(err)
		}
		validateMergedSBOMSchema(t, result.format, raw)
	}
	cmd = exec.Command(executable, "scan", dir, "--all", "--output", filepath.Join(dir, "nested.txt"))
	if out, err := cmd.CombinedOutput(); err == nil || !strings.Contains(string(out), "cannot overwrite an included input") {
		t.Fatalf("scan --all could overwrite an include: %v %s", err, out)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.test/app\n\ngo 1.22\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd = exec.Command(executable, "scan", dir, "--all", "--format", "ravel-json")
	data, err = cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, issue := range doc.Coverage.Issues {
		found = found || issue.Code == "collector_skipped_requires_resolve" && issue.Name == "go"
	}
	if !found || doc.Coverage.GraphState != "partial" {
		t.Fatal("Go manifest skipped without a coverage issue")
	}
	cmd = exec.Command(executable, "scan", dir, "--all", "--output", filepath.Join(dir, "go.mod"))
	if out, err := cmd.CombinedOutput(); err == nil || !strings.Contains(string(out), "cannot overwrite a discovered input") {
		t.Fatalf("skipped Go manifest could be overwritten: %v %s", err, out)
	}
	service := filepath.Join(dir, "service")
	ignored := filepath.Join(dir, "node_modules", "ignored")
	for _, directory := range []string{service, ignored} {
		if err := os.MkdirAll(directory, 0o755); err != nil {
			t.Fatal(err)
		}
		fixture, err := os.ReadFile(filepath.Join("..", "testdata", "fixtures", "npm-generated-12", "package-lock.json"))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, "package-lock.json"), fixture, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	manifestOnly := filepath.Join(dir, "unlocked")
	if err := os.MkdirAll(manifestOnly, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(manifestOnly, "Package.swift"), []byte("// no Package.resolved\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd = exec.Command(executable, "scan", dir, "--all", "--recursive", "--format", "ravel-json")
	data, err = cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Coverage.Inputs) != 3 || doc.Coverage.Packages != 4 || doc.Coverage.Edges != 4 {
		t.Fatalf("recursive scan missed a subproject or included generated files: %#v", doc.Coverage)
	}
	missingLock := false
	for _, issue := range doc.Coverage.Issues {
		missingLock = missingLock || issue.Code == "collector_skipped_missing_lockfile" && issue.Name == "Package.swift"
	}
	if !missingLock {
		t.Fatal("manifest-only Swift project was silently omitted")
	}
	cmd = exec.Command(executable, "scan", dir, "--recursive")
	if out, err := cmd.CombinedOutput(); err == nil || !strings.Contains(string(out), "requires --all") {
		t.Fatalf("--recursive without --all accepted: %v %s", err, out)
	}
}

func TestScanAllSelectsDeclaredJSManager(t *testing.T) {
	dir := t.TempDir()
	for _, input := range []struct{ fixture, name string }{
		{"npm-generated-12", "package-lock.json"},
		{"pnpm-generated-10", "pnpm-lock.yaml"},
	} {
		data, err := os.ReadFile(filepath.Join("..", "testdata", "fixtures", input.fixture, input.name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, input.name), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	manifest := filepath.Join(dir, "package.json")
	if err := os.WriteFile(manifest, []byte(`{"name":"polyglot","version":"1.0.0","packageManager":"pnpm@10.33.0"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(executable, "scan", dir, "--all", "--format", "ravel-json")
	data, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	var doc model.Document
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Components) != 1 || doc.Coverage.Manager != "pnpm" || !strings.HasSuffix(doc.Source, "pnpm-lock.yaml") {
		t.Fatalf("declared package manager not selected: %#v", doc)
	}
	found := false
	for _, issue := range doc.Coverage.Issues {
		found = found || issue.Code == "manager_lockfile_not_selected" && issue.Name == "npm"
	}
	if !found {
		t.Fatal("ignored JavaScript lockfile not reported")
	}
	cmd = exec.Command(executable, "scan", dir, "--all", "--output", manifest)
	if out, err := cmd.CombinedOutput(); err == nil || !strings.Contains(string(out), "cannot overwrite a discovered input") {
		t.Fatalf("package manager manifest could be overwritten: %v %s", err, out)
	}
	cmd = exec.Command(executable, "scan", dir, "--all", "--output", filepath.Join(dir, "package-lock.json"))
	if out, err := cmd.CombinedOutput(); err == nil || !strings.Contains(string(out), "cannot overwrite a lockfile") {
		t.Fatalf("unselected lockfile could be overwritten: %v %s", err, out)
	}
	if err := os.WriteFile(manifest, []byte(`{"name":"polyglot","version":"1.0.0"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd = exec.Command(executable, "scan", dir, "--all")
	if out, err := cmd.CombinedOutput(); err == nil || !strings.Contains(string(out), "multiple JavaScript lockfiles") {
		t.Fatalf("ambiguous JavaScript lockfiles accepted: %v %s", err, out)
	}
}
