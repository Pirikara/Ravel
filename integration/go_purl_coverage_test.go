package integration_test

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/Pirikara/Ravel/internal/model"
)

func assertGoPURLCaseCoverage(t *testing.T, coverage model.Coverage) {
	t.Helper()
	missing := map[string]bool{"example.com/SourceApp": true, "example.com/Acme/Lib": true}
	for _, issue := range coverage.Issues {
		if issue.Code != "go_module_purl_unavailable" {
			continue
		}
		if !missing[issue.Name] || issue.Scope == "" {
			t.Fatalf("unexpected, duplicate, or unlocated PURL warning: %#v", issue)
		}
		delete(missing, issue.Name)
	}
	if len(missing) != 0 {
		t.Fatalf("unreported missing Go PURLs: %v", missing)
	}
}

func TestGoPURLCaseCoverage(t *testing.T) {
	root := filepath.Join("..", "testdata", "fixtures", "go-purl-case-coverage")
	for _, input := range []string{filepath.Join(root, "go.mod"), filepath.Join(root, "vendor", "modules.txt")} {
		t.Run(filepath.Base(input), func(t *testing.T) {
			doc := scanDevelopmentSample(t, input)
			if len(doc.Components) != 5 || len(doc.Edges) != 5 {
				t.Fatal(doc.Components, doc.Edges)
			}
			assertGoPURLCaseCoverage(t, doc.Coverage)
			for _, component := range doc.Components {
				want := ""
				if component.Name == "example.net/library" {
					want = "pkg:golang/example.net/library@v1.0.0"
				}
				if component.PURL != want {
					t.Fatalf("module case or replacement identity changed: %#v", component)
				}
			}
			for _, format := range []string{"ravel-json", "cyclonedx-json", "spdx-json"} {
				dir := t.TempDir()
				report := filepath.Join(dir, "coverage.json")
				cmd := exec.Command(executable, "scan", input, "--format", format, "--output", filepath.Join(dir, "sbom.json"), "--report", report)
				if output, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("%s scan: %v: %s", format, err, output)
				}
				data, err := os.ReadFile(report)
				if err != nil {
					t.Fatal(err)
				}
				var coverage model.Coverage
				if err := json.Unmarshal(data, &coverage); err != nil {
					t.Fatal(err)
				}
				assertGoPURLCaseCoverage(t, coverage)
			}
			assertDevelopmentExports(t, doc)
		})
	}
}

func TestOCIGoBinaryPreservesExistingMixedCasePURL(t *testing.T) {
	binary, _, version := ociGoBinaryFixture(t)
	// Change only the spelling of the generated fixture's module metadata;
	// this binary is scanned as data and is never executed.
	binary = bytes.ReplaceAll(binary, []byte("golang.org/x/mod"), []byte("golang.org/X/mod"))
	layout := ociTestLayout(t)
	image := ociTestImage(t, layout, "linux", "amd64", []ociTestLayer{{entries: []ociTestEntry{
		{name: "usr/bin/case-tool", data: binary, mode: 0o755},
	}}})
	ociTestIndex(t, layout, image)
	doc, output, code := ociTestScan(t, layout)
	if code != 0 {
		t.Fatal(code, output)
	}
	found := false
	for _, component := range doc.Components {
		if component.Name == "golang.org/X/mod" && component.Version == version && component.PURL == "pkg:golang/golang.org/X/mod@"+version {
			found = true
		}
	}
	if !found {
		t.Fatal("mixed-case binary module not retained", doc.Components)
	}
	for _, issue := range doc.Coverage.Issues {
		if issue.Code == "go_module_purl_unavailable" {
			t.Fatal("existing binary PURL incorrectly reported as unavailable", issue)
		}
	}
}
