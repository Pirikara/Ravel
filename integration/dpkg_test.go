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

func TestDpkgInstalledDatabaseEvidenceAndDependencies(t *testing.T) {
	status := filepath.Join("..", "testdata", "fixtures", "dpkg-basic", "var", "lib", "dpkg", "status")
	result := filepath.Join(t.TempDir(), "dpkg.json")
	cmd := exec.Command(executable, "scan", status, "--manager", "dpkg", "--format", "ravel-json", "--output", result)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("direct dpkg status scan failed: %v: %s", err, output)
	}
	data, err := os.ReadFile(result)
	if err != nil {
		t.Fatal(err)
	}
	var doc model.Document
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Coverage.Manager != "dpkg" || doc.Coverage.Packages != 4 || doc.Coverage.Edges != 8 || doc.Coverage.GraphState != "complete_for_scope" || doc.Coverage.OriginState != "partial" {
		t.Fatalf("dpkg coverage incorrect: %#v", doc.Coverage)
	}
	ids := map[string]string{}
	for _, component := range doc.Components {
		ids[component.Name] = component.ID
		if component.PURL != "" || component.Evidence[0].Collector != "dpkg-status" || component.Evidence[0].InputDigest == "" || component.Evidence[0].Line == 0 {
			t.Fatalf("dpkg identity or evidence overstated: %#v", component)
		}
	}
	if ids["retired"] != "" || ids["application"] == "" || ids["libalpha"] == "" || ids["mailer"] == "" {
		t.Fatalf("installed selection incorrect: %#v", doc.Components)
	}
	for _, want := range [][2]string{{ids["application"], ids["libalpha"]}, {ids["application"], ids["mailer"]}, {ids["libalpha"], ids["base-files"]}, {ids["mailer"], ids["base-files"]}} {
		found := false
		for _, edge := range doc.Edges {
			found = found || edge.From == want[0] && edge.To == want[1] && edge.Condition == ""
		}
		if !found {
			t.Fatalf("missing installed dependency %v in %#v", want, doc.Edges)
		}
	}
	if output, err := exec.Command(executable, "scan", status, "--output", status).CombinedOutput(); err == nil || !strings.Contains(string(output), "cannot overwrite") {
		t.Fatalf("status database overwrite was accepted: %v: %s", err, output)
	}
}

func TestDpkgAlternativesStayConditional(t *testing.T) {
	fixture := filepath.Join("..", "testdata", "fixtures", "dpkg-alternatives")
	result := filepath.Join(t.TempDir(), "dpkg.json")
	if output, err := exec.Command(executable, "scan", fixture, "--format", "ravel-json", "--output", result).CombinedOutput(); err != nil {
		t.Fatalf("dpkg alternatives scan failed: %v: %s", err, output)
	}
	data, err := os.ReadFile(result)
	if err != nil {
		t.Fatal(err)
	}
	var doc model.Document
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	conditional := 0
	for _, edge := range doc.Edges {
		if edge.Condition != "" {
			conditional++
			if !strings.Contains(edge.Condition, "alternative=") {
				t.Fatalf("alternative condition lost: %#v", edge)
			}
		}
	}
	if conditional != 2 || doc.Coverage.GraphState != "partial" {
		t.Fatalf("alternative graph was asserted as definite: %#v", doc)
	}
}

func TestDpkgFilesystemIncludedInAllScan(t *testing.T) {
	fixture := filepath.Join("..", "testdata", "fixtures", "dpkg-basic")
	result := filepath.Join(t.TempDir(), "all.json")
	if output, err := exec.Command(executable, "scan", fixture, "--all", "--format", "ravel-json", "--output", result).CombinedOutput(); err != nil {
		t.Fatalf("dpkg --all scan failed: %v: %s", err, output)
	}
	data, err := os.ReadFile(result)
	if err != nil {
		t.Fatal(err)
	}
	var doc model.Document
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Components) != 4 || len(doc.Edges) != 8 {
		t.Fatalf("dpkg database omitted from --all: %#v", doc.Coverage)
	}
}

func TestDpkgNestedFilesystemIncludedInRecursiveScan(t *testing.T) {
	source := filepath.Join("..", "testdata", "fixtures", "dpkg-basic", "var", "lib", "dpkg", "status")
	data, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	base := t.TempDir()
	status := filepath.Join(base, "images", "rootfs", "var", "lib", "dpkg", "status")
	if err := os.MkdirAll(filepath.Dir(status), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(status, data, 0o644); err != nil {
		t.Fatal(err)
	}
	result := filepath.Join(t.TempDir(), "recursive.json")
	if output, err := exec.Command(executable, "scan", base, "--all", "--recursive", "--format", "ravel-json", "--output", result).CombinedOutput(); err != nil {
		t.Fatalf("recursive dpkg scan failed: %v: %s", err, output)
	}
	output, err := os.ReadFile(result)
	if err != nil {
		t.Fatal(err)
	}
	var doc model.Document
	if err := json.Unmarshal(output, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Components) != 4 || len(doc.Edges) != 8 {
		t.Fatalf("nested dpkg rootfs omitted from --all --recursive: %#v", doc.Coverage)
	}
}
