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

func scanStackFixture(t *testing.T, name string) model.Document {
	t.Helper()
	input := filepath.Join("..", "testdata", "fixtures", name, "stack.yaml.lock")
	out, err := exec.Command(executable, "scan", input, "--format", "ravel-json").Output()
	if err != nil {
		t.Fatalf("Stack scan %s: %v", name, err)
	}
	var doc model.Document
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func TestStackLockCLI(t *testing.T) {
	basic := scanStackFixture(t, "stack-basic")
	if basic.Coverage.Manager != "stack" || basic.Coverage.Packages != 3 || basic.Coverage.Edges != 0 || basic.Coverage.GraphState != "partial" || basic.Coverage.OriginState != "partial" || !dotnetIssue(basic, "stack_lock_selection_unverified") {
		t.Fatalf("Stack coverage: %#v", basic.Coverage)
	}
	for _, pkg := range basic.Components {
		if !strings.Contains(pkg.Context, "selection=unverified") || len(pkg.Evidence) != 1 || pkg.Evidence[0].InputDigest == "" {
			t.Fatalf("Stack package evidence/selection: %#v", pkg)
		}
		if pkg.Name == "acme-missiles" && (pkg.Version != "0.3" || pkg.PURL != "pkg:hackage/acme-missiles@0.3" || !strings.Contains(pkg.Context, "hackage-pin=sha256:")) {
			t.Fatalf("Stack Hackage pin: %#v", pkg)
		}
		if pkg.Name == "internal-lib" && (pkg.Version != "0.4.0" || pkg.PURL != "" || !strings.Contains(pkg.Context, "subdir=packages/internal-lib")) {
			t.Fatalf("Stack Git package: %#v", pkg)
		}
	}
	encoded, err := json.Marshal(basic)
	if err != nil || strings.Contains(string(encoded), "secret") {
		t.Fatalf("Stack source credential leaked: %v %s", err, encoded)
	}
	unhandled := scanStackFixture(t, "stack-unhandled")
	if unhandled.Coverage.Packages != 1 || !dotnetIssue(unhandled, "stack_lock_package_unhandled") {
		t.Fatalf("Stack unsupported location coverage: %#v", unhandled.Coverage)
	}
}

func TestStackLockDiscoveryAndExports(t *testing.T) {
	fixture := filepath.Join("..", "testdata", "fixtures", "stack-basic", "stack.yaml.lock")
	root := t.TempDir()
	nested := filepath.Join(root, "haskell")
	if err := os.Mkdir(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nested, "stack.yaml.lock"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"scan", nested, "--format", "ravel-json"},
		{"scan", nested, "--manager", "stack", "--format", "ravel-json"},
		{"scan", root, "--all", "--recursive", "--format", "ravel-json"},
	} {
		out, err := exec.Command(executable, args...).Output()
		if err != nil {
			t.Fatalf("Stack discovery %v: %v", args, err)
		}
		var doc model.Document
		if err := json.Unmarshal(out, &doc); err != nil || doc.Coverage.Packages != 3 {
			t.Fatalf("Stack discovery %v: %v %#v", args, err, doc.Coverage)
		}
	}
	for _, format := range []string{"cyclonedx-json", "spdx-json"} {
		out, err := exec.Command(executable, "scan", fixture, "--format", format).Output()
		if err != nil || !json.Valid(out) || strings.Contains(string(out), "secret") {
			t.Fatalf("Stack %s export failed or leaked credentials: %v", format, err)
		}
	}
	custom := filepath.Join(root, "custom.yaml.lock")
	if err := os.WriteFile(custom, data, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{custom, root} {
		out, err := exec.Command(executable, "scan", input, "--format", "ravel-json").Output()
		if err != nil {
			t.Fatalf("custom Stack lockfile %s: %v", input, err)
		}
		var doc model.Document
		if err := json.Unmarshal(out, &doc); err != nil || doc.Coverage.Packages != 3 {
			t.Fatalf("custom Stack lockfile %s: %v %#v", input, err, doc.Coverage)
		}
	}
}
