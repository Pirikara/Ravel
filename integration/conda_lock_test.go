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

func scanCondaLock(t *testing.T, input string, extra ...string) model.Document {
	t.Helper()
	args := append([]string{"scan", input, "--format", "ravel-json"}, extra...)
	out, err := exec.Command(executable, args...).Output()
	if err != nil {
		t.Fatalf("conda-lock scan %v: %v", args, err)
	}
	var doc model.Document
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func TestCondaLockCLI(t *testing.T) {
	base := filepath.Join("..", "testdata", "fixtures")
	basic := scanCondaLock(t, filepath.Join(base, "conda-lock-basic"))
	if basic.Coverage.Manager != "conda-lock" || basic.Coverage.Packages != 5 || basic.Coverage.Edges != 3 || basic.Coverage.GraphState != "partial" || basic.Coverage.OriginState != "partial" || len(basic.Coverage.Platforms) != 2 || len(basic.Origins) != 5 || !dotnetIssue(basic, "conda_virtual_requirement_unresolved") {
		t.Fatalf("conda-lock basic coverage: %#v", basic.Coverage)
	}
	ids := map[string]model.Component{}
	for _, pkg := range basic.Components {
		ids[pkg.ID] = pkg
		if len(pkg.Hashes) == 0 || len(pkg.Evidence) != 1 || pkg.Evidence[0].InputDigest == "" {
			t.Fatalf("conda-lock package hash/evidence: %#v", pkg)
		}
		if pkg.Name == "My_Package" && (pkg.PURL != "pkg:pypi/my-package@1.0.0" || pkg.Context != "manager=pip;category=dev;optional=true") {
			t.Fatalf("conda-lock Pip identity: %#v", pkg)
		}
		if pkg.Name == "python" && pkg.PURL != "" {
			t.Fatalf("unverified Conda PURL: %#v", pkg)
		}
	}
	for _, edge := range basic.Edges {
		from, to := ids[edge.From], ids[edge.To]
		if from.Platform != to.Platform || edge.Condition == "" {
			t.Fatalf("cross-platform or unconditional conda-lock edge: %#v -> %#v", from, to)
		}
	}
	ambiguous := scanCondaLock(t, filepath.Join(base, "conda-lock-ambiguous"))
	if ambiguous.Coverage.Packages != 3 || ambiguous.Coverage.Edges != 0 || !dotnetIssue(ambiguous, "ambiguous_dependency") {
		t.Fatalf("conda-lock ambiguous coverage: %#v", ambiguous.Coverage)
	}
	partial := scanCondaLock(t, filepath.Join(base, "conda-lock-partial"))
	if partial.Coverage.Packages != 1 || !dotnetIssue(partial, "conda_lock_package_invalid") || !dotnetIssue(partial, "conda_lock_hash_invalid") {
		t.Fatalf("conda-lock partial coverage: %#v", partial.Coverage)
	}
	encoded, err := json.Marshal(partial)
	if err != nil || strings.Contains(string(encoded), "secret") || strings.Contains(string(encoded), "hidden") {
		t.Fatalf("conda-lock URL credential leaked: %v", err)
	}
	custom := scanCondaLock(t, filepath.Join(base, "conda-lock-custom"))
	if custom.Coverage.Packages != 1 || custom.Components[0].Platform != "win-64" {
		t.Fatalf("conda-lock custom file: %#v", custom.Coverage)
	}
}

func TestCondaLockDiscoveryAndExports(t *testing.T) {
	fixture := filepath.Join("..", "testdata", "fixtures", "conda-lock-basic", "conda-lock.yml")
	root := t.TempDir()
	nested := filepath.Join(root, "conda")
	if err := os.Mkdir(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nested, "conda-lock.yml"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{nested},
		{nested, "--manager", "conda-lock"},
		{root, "--all", "--recursive"},
	} {
		doc := scanCondaLock(t, args[0], args[1:]...)
		if doc.Coverage.Packages != 5 {
			t.Fatalf("conda-lock discovery %v: %#v", args, doc.Coverage)
		}
	}
	for _, format := range []string{"cyclonedx-json", "spdx-json"} {
		out, err := exec.Command(executable, "scan", fixture, "--format", format).Output()
		if err != nil || !json.Valid(out) {
			t.Fatalf("conda-lock %s export: %v", format, err)
		}
	}
	if err := os.WriteFile(filepath.Join(nested, "other.conda-lock.yml"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"scan", nested, "--manager", "conda-lock"},
		{"scan", root, "--all", "--recursive"},
	} {
		out, err := exec.Command(executable, args...).CombinedOutput()
		if err == nil || !strings.Contains(string(out), "multiple conda-lock files") {
			t.Fatalf("expected conda-lock ambiguity for %v: %v %s", args, err, out)
		}
	}
}
