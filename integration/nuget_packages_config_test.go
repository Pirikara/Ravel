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

func TestNuGetPackagesConfigCLI(t *testing.T) {
	fixture := filepath.Join("..", "testdata", "fixtures", "nuget-packages-config-basic", "packages.config")
	for _, input := range []string{fixture, filepath.Dir(fixture)} {
		out, err := exec.Command(executable, "scan", input, "--format", "ravel-json").Output()
		if err != nil {
			t.Fatalf("packages.config scan: %v", err)
		}
		var doc model.Document
		if err := json.Unmarshal(out, &doc); err != nil {
			t.Fatal(err)
		}
		if doc.Coverage.Manager != "nuget" || doc.Coverage.Packages != 3 || doc.Coverage.Edges != 3 || doc.Coverage.GraphState != "partial" || doc.Coverage.OriginState != "partial" || !dotnetIssue(doc, "nuget_packages_config_graph_unavailable") {
			t.Fatalf("NuGet packages.config coverage: %#v", doc.Coverage)
		}
		for _, pkg := range doc.Components {
			if pkg.PURL != "" || len(pkg.Evidence) != 1 || pkg.Evidence[0].InputDigest == "" {
				t.Fatalf("unverified NuGet origin or missing evidence: %#v", pkg)
			}
			if pkg.Name == "Newtonsoft.Json" && pkg.Context != "installed-target-framework=net48" || pkg.Name == "Microsoft.Net.Compilers" && pkg.Context != "developmentDependency=true" {
				t.Fatalf("NuGet packages.config context: %#v", pkg)
			}
		}
		for _, edge := range doc.Edges {
			if edge.From != "root" || edge.Kind != "listed" {
				t.Fatalf("flat list claimed dependency graph: %#v", edge)
			}
		}
	}
	empty := filepath.Join("..", "testdata", "fixtures", "nuget-packages-config-empty", "packages.config")
	out, err := exec.Command(executable, "scan", empty, "--format", "ravel-json").Output()
	if err != nil {
		t.Fatal(err)
	}
	var doc model.Document
	if err := json.Unmarshal(out, &doc); err != nil || doc.Coverage.Packages != 0 {
		t.Fatalf("empty packages.config: %v %#v", err, doc.Coverage)
	}
}

func TestNuGetPackagesConfigDiscoveryAndExports(t *testing.T) {
	fixture := filepath.Join("..", "testdata", "fixtures", "nuget-packages-config-basic", "packages.config")
	root := t.TempDir()
	nested := filepath.Join(root, "legacy")
	if err := os.Mkdir(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nested, "packages.config"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"scan", nested, "--manager", "nuget", "--format", "ravel-json"},
		{"scan", root, "--all", "--recursive", "--format", "ravel-json"},
	} {
		out, err := exec.Command(executable, args...).Output()
		if err != nil {
			t.Fatalf("packages.config discovery %v: %v", args, err)
		}
		var doc model.Document
		if err := json.Unmarshal(out, &doc); err != nil || doc.Coverage.Packages != 3 {
			t.Fatalf("packages.config discovery %v: %v %#v", args, err, doc.Coverage)
		}
	}
	for _, format := range []string{"cyclonedx-json", "spdx-json"} {
		out, err := exec.Command(executable, "scan", fixture, "--format", format).Output()
		if err != nil || !json.Valid(out) || strings.Contains(string(out), "pkg:nuget/") {
			t.Fatalf("NuGet packages.config %s export failed or claimed source: %v", format, err)
		}
	}
}
