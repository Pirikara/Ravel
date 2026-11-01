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

func scanConanFixture(t *testing.T, fixture string) model.Document {
	t.Helper()
	input := filepath.Join("..", "testdata", "fixtures", fixture, "conan.lock")
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

func TestConanLockCLI(t *testing.T) {
	v1 := scanConanFixture(t, "conan-v1")
	if v1.Coverage.Manager != "conan" || v1.Coverage.Packages != 3 || v1.Coverage.Edges != 3 || v1.Coverage.GraphState != "complete_for_scope" || v1.Coverage.OriginState != "partial" {
		t.Fatalf("Conan 1 graph coverage: %#v", v1.Coverage)
	}
	ids := map[string]string{}
	for _, pkg := range v1.Components {
		ids[pkg.Name] = pkg.ID
		if pkg.Name == "openssl" {
			if pkg.Version != "3.0.5" || pkg.PURL != "pkg:conan/openssl@3.0.5?channel=stable&rrev=0123456789abcdef&user=acme" || !strings.Contains(pkg.Context, "package-id=abc123") {
				t.Fatalf("Conan 1 recipe identity: %#v", pkg)
			}
		}
	}
	graph := map[string]bool{}
	for _, edge := range v1.Edges {
		graph[edge.From+"->"+edge.To+";"+edge.Condition] = true
	}
	if !graph["root->"+ids["openssl"]+";"] || !graph[ids["openssl"]+"->"+ids["zlib"]+";"] || !graph["root->"+ids["cmake"]+";build context"] {
		t.Fatalf("Conan 1 graph: %#v", v1.Edges)
	}

	v2 := scanConanFixture(t, "conan-v2")
	if v2.Coverage.Packages != 5 || v2.Coverage.Edges != 0 || v2.Coverage.GraphState != "partial" || v2.Coverage.OriginState != "partial" || !dotnetIssue(v2, "conan_lock_selection_unverified") {
		t.Fatalf("Conan 2 candidate coverage: %#v", v2.Coverage)
	}
	versions := map[string]bool{}
	for _, pkg := range v2.Components {
		if !strings.Contains(pkg.Context, "selection=unverified") {
			t.Fatalf("Conan 2 candidate presented as selected: %#v", pkg)
		}
		versions[pkg.Name+"@"+pkg.Version] = true
	}
	if !versions["matrix@1.0"] || !versions["matrix@1.1"] || !versions["cmake@3.25.1"] || !versions["generator@0.2"] {
		t.Fatalf("Conan 2 alternatives missing: %#v", versions)
	}

	noRoot := scanConanFixture(t, "conan-v1-no-root")
	if noRoot.Coverage.Packages != 2 || noRoot.Coverage.Edges != 2 {
		t.Fatalf("Conan 1 reference-root graph: %#v", noRoot.Coverage)
	}
	invalid := scanConanFixture(t, "conan-v1-invalid-edge")
	if invalid.Coverage.Packages != 1 || invalid.Coverage.Edges != 1 || invalid.Coverage.GraphState != "partial" || !dotnetIssue(invalid, "conan_unresolved_node") {
		t.Fatalf("Conan 1 invalid edge coverage: %#v", invalid.Coverage)
	}
}

func TestConanLockDiscoveryAndExports(t *testing.T) {
	fixture := filepath.Join("..", "testdata", "fixtures", "conan-v1", "conan.lock")
	root := t.TempDir()
	nested := filepath.Join(root, "cpp")
	if err := os.Mkdir(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nested, "conan.lock"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"scan", nested, "--format", "ravel-json"},
		{"scan", nested, "--manager", "conan", "--format", "ravel-json"},
		{"scan", root, "--all", "--recursive", "--format", "ravel-json"},
	} {
		out, err := exec.Command(executable, args...).Output()
		if err != nil {
			t.Fatalf("Conan discovery %v: %v", args, err)
		}
		var doc model.Document
		if err := json.Unmarshal(out, &doc); err != nil || doc.Coverage.Packages != 3 {
			t.Fatalf("Conan discovery %v: %v %#v", args, err, doc.Coverage)
		}
	}
	for _, format := range []string{"cyclonedx-json", "spdx-json"} {
		out, err := exec.Command(executable, "scan", fixture, "--format", format).Output()
		if err != nil || !json.Valid(out) {
			t.Fatalf("Conan %s export: %v", format, err)
		}
		if format == "cyclonedx-json" {
			var bom struct {
				Components   []any `json:"components"`
				Dependencies []struct {
					Ref       string   `json:"ref"`
					DependsOn []string `json:"dependsOn"`
				} `json:"dependencies"`
			}
			if err := json.Unmarshal(out, &bom); err != nil || len(bom.Components) != 3 {
				t.Fatalf("Conan CycloneDX components: %v %#v", err, bom)
			}
			for _, dep := range bom.Dependencies {
				if dep.Ref == "root" && len(dep.DependsOn) != 1 {
					t.Fatalf("build dependency entered unconditional CycloneDX graph: %#v", dep)
				}
			}
		} else {
			var spdx struct {
				Packages      []any `json:"packages"`
				Relationships []any `json:"relationships"`
			}
			if err := json.Unmarshal(out, &spdx); err != nil || len(spdx.Packages) != 4 || len(spdx.Relationships) != 2 {
				t.Fatalf("Conan SPDX graph: %v %#v", err, spdx)
			}
		}
	}
}
