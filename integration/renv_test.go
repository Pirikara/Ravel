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

func scanRenv(t *testing.T, input string, extra ...string) model.Document {
	t.Helper()
	args := append([]string{"scan", input, "--format", "ravel-json"}, extra...)
	out, err := exec.Command(executable, args...).Output()
	if err != nil {
		t.Fatalf("renv scan %v: %v", args, err)
	}
	var doc model.Document
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func TestRenvLockCLI(t *testing.T) {
	base := filepath.Join("..", "testdata", "fixtures")
	basic := scanRenv(t, filepath.Join(base, "renv-basic"))
	if basic.Coverage.Manager != "renv" || basic.Coverage.Packages != 3 || basic.Coverage.Edges != 1 || basic.Coverage.GraphState != "partial" || basic.Coverage.OriginState != "partial" || !dotnetIssue(basic, "missing_direct_dependencies") {
		t.Fatalf("renv basic coverage: %#v", basic.Coverage)
	}
	ids := map[string]string{}
	for _, pkg := range basic.Components {
		ids[pkg.ID] = pkg.Name
		if pkg.PURL != "" || len(pkg.Hashes) != 0 || len(pkg.Evidence) != 1 || pkg.Evidence[0].InputDigest == "" {
			t.Fatalf("renv package evidence/hash: %#v", pkg)
		}
	}
	if edge := basic.Edges[0]; ids[edge.From] != "markdown" || ids[edge.To] != "mime" || edge.Condition == "" {
		t.Fatalf("renv conditional requirement: %#v", edge)
	}
	if len(basic.Origins) != 3 {
		t.Fatalf("renv origins: %#v", basic.Origins)
	}
	encoded, err := json.Marshal(basic)
	if err != nil || strings.Contains(string(encoded), "secret") || strings.Contains(string(encoded), "hidden") {
		t.Fatalf("renv credential leaked: %v", err)
	}
	old := scanRenv(t, filepath.Join(base, "renv-old", "renv.lock"))
	if old.Coverage.Packages != 2 || old.Coverage.Edges != 0 || len(old.Origins) != 2 || !dotnetIssue(old, "renv_requirements_unavailable") {
		t.Fatalf("renv old coverage: %#v", old.Coverage)
	}
	partial := scanRenv(t, filepath.Join(base, "renv-partial"))
	if partial.Coverage.Packages != 1 || partial.Coverage.Edges != 0 || !dotnetIssue(partial, "renv_package_invalid") || !dotnetIssue(partial, "unresolved_dependency") || !dotnetIssue(partial, "renv_repository_unresolved") {
		t.Fatalf("renv partial coverage: %#v", partial.Coverage)
	}
}

func TestRenvDiscoveryAndExports(t *testing.T) {
	fixture := filepath.Join("..", "testdata", "fixtures", "renv-basic", "renv.lock")
	root := t.TempDir()
	nested := filepath.Join(root, "r-project")
	if err := os.Mkdir(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nested, "renv.lock"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{nested},
		{nested, "--manager", "renv"},
		{root, "--all", "--recursive"},
	} {
		doc := scanRenv(t, args[0], args[1:]...)
		if doc.Coverage.Packages != 3 {
			t.Fatalf("renv discovery %v: %#v", args, doc.Coverage)
		}
	}
	for _, format := range []string{"cyclonedx-json", "spdx-json"} {
		out, err := exec.Command(executable, "scan", fixture, "--format", format).Output()
		if err != nil || !json.Valid(out) || strings.Contains(string(out), "secret") {
			t.Fatalf("renv %s export: %v", format, err)
		}
	}
}
