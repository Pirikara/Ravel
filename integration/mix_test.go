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

func scanMixFixture(t *testing.T, fixture string) model.Document {
	t.Helper()
	input := filepath.Join("..", "testdata", "fixtures", fixture, "mix.lock")
	data, err := exec.Command(executable, "scan", input, "--format", "ravel-json").Output()
	if err != nil {
		t.Fatalf("scan %s: %v", fixture, err)
	}
	var doc model.Document
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func TestMixLockCLI(t *testing.T) {
	basic := scanMixFixture(t, "mix-basic")
	if basic.Coverage.Manager != "mix" || basic.Coverage.Packages != 5 || basic.Coverage.Edges != 2 || basic.Coverage.GraphState != "partial" || basic.Coverage.OriginState != "partial" {
		t.Fatalf("Mix coverage: %#v", basic.Coverage)
	}
	ids := map[string]string{}
	for _, pkg := range basic.Components {
		ids[pkg.Name] = pkg.ID
		if pkg.Name == "cowboy" && (pkg.PURL != "pkg:hex/cowboy@2.9.0" || pkg.Version != "2.9.0") {
			t.Fatalf("Hex identity: %#v", pkg)
		}
		if pkg.Name == "my_git" && pkg.PURL != "" {
			t.Fatalf("Git dependency mislabeled as Hex: %#v", pkg)
		}
	}
	for _, edge := range basic.Edges {
		if edge.From != ids["cowboy"] || edge.Condition == "" || edge.To != ids["cowlib"] && edge.To != ids["ranch"] {
			t.Fatalf("Mix dependency should remain conditional: %#v", edge)
		}
	}
	encoded, err := json.Marshal(basic)
	if err != nil || strings.Contains(string(encoded), "secret") {
		t.Fatalf("Git credentials leaked: %v %s", err, encoded)
	}
	alias := scanMixFixture(t, "mix-alias")
	if alias.Coverage.Packages != 2 || !dotnetIssue(alias, "mix_registry_unverified") {
		t.Fatalf("Mix alias coverage: %#v", alias.Coverage)
	}
	for _, pkg := range alias.Components {
		if pkg.Name == "web" && (pkg.PURL != "pkg:hex/phoenix@1.7.0" || !strings.Contains(pkg.Context, "hex-package=phoenix")) || pkg.Name == "private_pkg" && pkg.PURL != "" {
			t.Fatalf("Mix alias or private registry identity: %#v", pkg)
		}
	}
	unresolved := scanMixFixture(t, "mix-unresolved")
	if unresolved.Coverage.Packages != 1 || unresolved.Coverage.Edges != 0 || !dotnetIssue(unresolved, "mix_dependency_unresolved") {
		t.Fatalf("Mix unresolved dependency coverage: %#v", unresolved.Coverage)
	}
	for _, issue := range unresolved.Coverage.Issues {
		if issue.Name == "missing_optional" {
			t.Fatalf("absent optional dependency reported missing: %#v", issue)
		}
	}
}

func TestMixLockDiscoveryAndExports(t *testing.T) {
	fixture := filepath.Join("..", "testdata", "fixtures", "mix-basic", "mix.lock")
	root := t.TempDir()
	nested := filepath.Join(root, "elixir")
	if err := os.Mkdir(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nested, "mix.lock"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"scan", nested, "--format", "ravel-json"},
		{"scan", nested, "--manager", "mix", "--format", "ravel-json"},
		{"scan", root, "--all", "--recursive", "--format", "ravel-json"},
	} {
		out, err := exec.Command(executable, args...).Output()
		if err != nil {
			t.Fatalf("Mix discovery %v: %v", args, err)
		}
		var doc model.Document
		if err := json.Unmarshal(out, &doc); err != nil || doc.Coverage.Packages != 5 {
			t.Fatalf("Mix discovery %v: %v %#v", args, err, doc.Coverage)
		}
	}
	for _, format := range []string{"cyclonedx-json", "spdx-json"} {
		out, err := exec.Command(executable, "scan", fixture, "--format", format).Output()
		if err != nil || !json.Valid(out) || strings.Contains(string(out), "secret") {
			t.Fatalf("Mix %s export failed or leaked credentials: %v", format, err)
		}
	}
}
