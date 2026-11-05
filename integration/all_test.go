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
	if doc.Coverage.Manager != "multi" || doc.Coverage.Packages != 4 || doc.Coverage.Edges != 4 || len(doc.Coverage.Inputs) != 2 {
		t.Fatalf("unexpected multi-manager coverage: %#v", doc.Coverage)
	}
	if len(doc.Sources) != 3 || len(doc.Components) != 4 {
		t.Fatalf("source scopes or packages missing: %#v", doc)
	}
	names := map[string]bool{}
	for _, component := range doc.Components {
		names[component.Name] = true
	}
	if !names["ravel-npm-generated"] || !names["is-number"] || !names["requests"] || !names["idna"] {
		t.Fatalf("multi-manager components missing: %#v", names)
	}
	spdxPath := filepath.Join(dir, "combined.spdx.json")
	cmd = exec.Command(executable, "scan", dir, "--all", "--strict", "--format", "spdx-json", "--output", spdxPath)
	if out, err := cmd.CombinedOutput(); err == nil || !strings.Contains(string(out), "4 packages") {
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
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.test/app\n\ngo 1.22\n\nrequire example.test/go-dep v1.2.3\n"), 0o644); err != nil {
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
	for _, component := range doc.Components {
		found = found || component.Name == "example.test/go-dep" && component.Version == "v1.2.3"
	}
	if !found || doc.Coverage.Packages != 6 || doc.Coverage.GraphState != "partial" {
		t.Fatal("Go manifest modules were not included with partial graph coverage")
	}
	cmd = exec.Command(executable, "scan", dir, "--all", "--output", filepath.Join(dir, "go.mod"))
	if out, err := cmd.CombinedOutput(); err == nil || !strings.Contains(string(out), "cannot overwrite") {
		t.Fatalf("Go manifest could be overwritten: %v %s", err, out)
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
	if len(doc.Coverage.Inputs) != 4 || doc.Coverage.Packages != 8 || doc.Coverage.Edges != 8 {
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

func TestAlternateBundlerLockfiles(t *testing.T) {
	root := t.TempDir()
	fixture, err := os.ReadFile(filepath.Join("..", "testdata", "fixtures", "bundler-basic", "Gemfile.lock"))
	if err != nil {
		t.Fatal(err)
	}
	for _, relative := range []string{"Gemfile.lock", "Gemfile.next.lock", "nested/Gemfile.rails-8.lock"} {
		path := filepath.Join(root, relative)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, fixture, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	read := func(args ...string) model.Document {
		t.Helper()
		out, err := exec.Command(executable, append([]string{"scan"}, args...)...).Output()
		if err != nil {
			t.Fatalf("scan %q: %v %s", args, err, out)
		}
		var doc model.Document
		if err := json.Unmarshal(out, &doc); err != nil {
			t.Fatal(err)
		}
		return doc
	}
	doc := read(root, "--all", "--recursive", "--format", "ravel-json")
	if len(doc.Coverage.Inputs) != 3 || len(doc.Components) != 6 || len(doc.Edges) != 6 {
		t.Fatalf("alternate Bundler locks omitted: %#v", doc.Coverage)
	}
	ids := map[string]bool{}
	for _, component := range doc.Components {
		if ids[component.ID] {
			t.Fatalf("duplicate component ID across lockfiles: %s", component.ID)
		}
		ids[component.ID] = true
	}
	if out, err := exec.Command(executable, "scan", root, "--all", "--output", filepath.Join(root, "Gemfile.next.lock")).CombinedOutput(); err == nil || !strings.Contains(string(out), "cannot overwrite") {
		t.Fatalf("alternate lockfile could be overwritten: %v %s", err, out)
	}
	for _, input := range []string{filepath.Join(root, "Gemfile.next.lock"), filepath.Join(root, "nested"), filepath.Join(root, "nested", "Gemfile.rails-8.lock")} {
		doc := read(input, "--format", "ravel-json")
		if len(doc.Components) != 2 || doc.Coverage.Manager != "bundler" {
			t.Fatalf("auto scan missed alternate lock %s: %#v", input, doc.Coverage)
		}
	}
}

func TestIncludeTestAndVendor(t *testing.T) {
	root := t.TempDir()
	fixture, err := os.ReadFile(filepath.Join("..", "testdata", "fixtures", "bundler-basic", "Gemfile.lock"))
	if err != nil {
		t.Fatal(err)
	}
	for relative, content := range map[string][]byte{
		"Gemfile.lock":                fixture,
		"spec/fixtures/Gemfile.lock":  fixture,
		"vendor/example/Gemfile.lock": fixture,
		"tmp/broken/Gemfile.lock":     []byte("invalid fixture\n"),
		"node_modules/Gemfile.lock":   fixture,
	} {
		path := filepath.Join(root, relative)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, content, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	read := func(args ...string) model.Document {
		t.Helper()
		out, err := exec.Command(executable, append([]string{"scan", root, "--all", "--recursive", "--format", "ravel-json"}, args...)...).Output()
		if err != nil {
			t.Fatal(err)
		}
		var doc model.Document
		if err := json.Unmarshal(out, &doc); err != nil {
			t.Fatal(err)
		}
		return doc
	}
	ordinary := read()
	if len(ordinary.Components) != 2 || ordinary.Coverage.Manager != "bundler" {
		t.Fatalf("default scan included extra trees: %#v", ordinary.Coverage)
	}
	inclusive := read("--include-test-and-vendor")
	if len(inclusive.Coverage.Inputs) != 3 || len(inclusive.Components) != 6 || inclusive.Coverage.GraphState != "partial" {
		t.Fatalf("inclusive scan missed source trees: %#v", inclusive.Coverage)
	}
	foundInvalid := false
	for _, issue := range inclusive.Coverage.Issues {
		foundInvalid = foundInvalid || issue.Code == "collector_skipped_invalid_input" && strings.HasSuffix(issue.Scope, "tmp/broken/Gemfile.lock")
	}
	if !foundInvalid {
		t.Fatal("invalid lockfile in test tree was not reported")
	}
	if out, err := exec.Command(executable, "scan", root, "--include-test-and-vendor").CombinedOutput(); err == nil || !strings.Contains(string(out), "requires --all --recursive") {
		t.Fatalf("inclusive scan without recursive accepted: %v %s", err, out)
	}
}

func TestIncludeRepositoryGoBinary(t *testing.T) {
	root := t.TempDir()
	binary := filepath.Join(root, "ravel-binary")
	if err := os.Link(executable, binary); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "script"), []byte("#!/bin/sh\necho test\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(root, "main.go")
	if err := os.WriteFile(source, []byte("package main\nfunc main() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	macho := filepath.Join(root, "darwin-binary")
	build := exec.Command("go", "build", "-o", macho, source)
	build.Env = append(os.Environ(), "GOOS=darwin", "GOARCH=arm64", "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build Mach-O fixture: %v %s", err, out)
	}
	out, err := exec.Command(executable, "scan", root, "--all", "--recursive", "--include-binaries", "--format", "ravel-json").Output()
	if err != nil {
		t.Fatal(err)
	}
	var doc model.Document
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Coverage.Inputs) != 2 || len(doc.Components) < 4 {
		t.Fatalf("Go ELF binary was not scanned: %#v", doc.Coverage)
	}
	foundApp, foundMachO, foundStdlib := false, false, false
	for _, component := range doc.Components {
		foundApp = foundApp || component.Kind == "application" && component.Name == "ravel-binary"
		foundMachO = foundMachO || component.Kind == "application" && component.Name == "darwin-binary"
		foundStdlib = foundStdlib || component.Name == "stdlib" && strings.HasPrefix(component.Version, "go")
	}
	if !foundApp || !foundMachO || !foundStdlib {
		t.Fatalf("Go binary identity and toolchain missing: %#v", doc.Components)
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
