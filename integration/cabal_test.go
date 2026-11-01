package integration_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"ravel/internal/model"
)

func scanCabalFixture(t *testing.T, name string) model.Document {
	t.Helper()
	input := filepath.Join("..", "testdata", "fixtures", name, "cabal.project.freeze")
	out, err := exec.Command(executable, "scan", input, "--format", "ravel-json").Output()
	if err != nil {
		t.Fatalf("Cabal scan %s: %v", name, err)
	}
	var doc model.Document
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func TestCabalFreezeCLI(t *testing.T) {
	basic := scanCabalFixture(t, "cabal-freeze-basic")
	if basic.Coverage.Manager != "cabal" || basic.Coverage.Packages != 3 || basic.Coverage.Edges != 3 || basic.Coverage.GraphState != "partial" || basic.Coverage.OriginState != "partial" || !dotnetIssue(basic, "cabal_freeze_unversioned_constraint") {
		t.Fatalf("Cabal freeze coverage: %#v", basic.Coverage)
	}
	names := map[string]bool{}
	for _, pkg := range basic.Components {
		names[pkg.Name+"@"+pkg.Version] = true
		if pkg.PURL != "" || len(pkg.Evidence) != 1 || pkg.Evidence[0].InputDigest == "" {
			t.Fatalf("Cabal package origin or evidence: %#v", pkg)
		}
	}
	if !names["HTTP@4000.3.16"] || !names["Cabal@3.2.1.0"] || !names["HUnit@1.6.2.0"] {
		t.Fatalf("Cabal version pins missing: %#v", names)
	}
	repeat := scanCabalFixture(t, "cabal-freeze-repeat")
	if repeat.Coverage.Packages != 3 || repeat.Coverage.Edges != 3 || dotnetIssue(repeat, "duplicate_spec") {
		t.Fatalf("Cabal repeated identical pin: %#v", repeat.Coverage)
	}
}

func TestCabalFreezeDiscoveryAndExports(t *testing.T) {
	fixture := filepath.Join("..", "testdata", "fixtures", "cabal-freeze-basic", "cabal.project.freeze")
	root := t.TempDir()
	nested := filepath.Join(root, "haskell")
	if err := os.Mkdir(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nested, "cabal.project.freeze"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"scan", nested, "--format", "ravel-json"},
		{"scan", nested, "--manager", "cabal", "--format", "ravel-json"},
		{"scan", root, "--all", "--recursive", "--format", "ravel-json"},
	} {
		out, err := exec.Command(executable, args...).Output()
		if err != nil {
			t.Fatalf("Cabal discovery %v: %v", args, err)
		}
		var doc model.Document
		if err := json.Unmarshal(out, &doc); err != nil || doc.Coverage.Packages != 3 {
			t.Fatalf("Cabal discovery %v: %v %#v", args, err, doc.Coverage)
		}
	}
	for _, format := range []string{"cyclonedx-json", "spdx-json"} {
		out, err := exec.Command(executable, "scan", fixture, "--format", format).Output()
		if err != nil || !json.Valid(out) {
			t.Fatalf("Cabal %s export: %v", format, err)
		}
	}
	custom := filepath.Join(root, "custom.project.freeze")
	if err := os.WriteFile(custom, data, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{custom, root} {
		out, err := exec.Command(executable, "scan", input, "--format", "ravel-json").Output()
		if err != nil {
			t.Fatalf("custom Cabal freeze %s: %v", input, err)
		}
		var doc model.Document
		if err := json.Unmarshal(out, &doc); err != nil || doc.Coverage.Packages != 3 {
			t.Fatalf("custom Cabal freeze %s: %v %#v", input, err, doc.Coverage)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "cabal.project.freeze"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(executable, "scan", root, "--format", "ravel-json").CombinedOutput(); err == nil {
		t.Fatalf("ambiguous Cabal freeze files were silently selected: %s", out)
	}
}
