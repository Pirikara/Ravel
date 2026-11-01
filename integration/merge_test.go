package integration_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/Pirikara/Ravel/internal/model"
)

func TestMergePolyglotScans(t *testing.T) {
	inputPaths := []string{}
	for _, name := range []string{"npm-v3", "bun-basic"} {
		input := filepath.Join(t.TempDir(), name+".json")
		fixture := filepath.Join("..", "testdata", "fixtures", name)
		if output, err := exec.Command(executable, "scan", fixture, "--format", "ravel-json", "--output", input).CombinedOutput(); err != nil {
			t.Fatalf("%s scan failed: %v: %s", name, err, output)
		}
		inputPaths = append(inputPaths, input)
	}
	mergedPath := filepath.Join(t.TempDir(), "merged.json")
	reportPath := filepath.Join(t.TempDir(), "coverage.json")
	args := []string{"merge", "--name", "polyglot", "--format", "ravel-json", "--output", mergedPath, "--report", reportPath}
	args = append(args, inputPaths...)
	if output, err := exec.Command(executable, args...).CombinedOutput(); err != nil {
		t.Fatalf("merge failed: %v: %s", err, output)
	}
	data, err := os.ReadFile(mergedPath)
	if err != nil {
		t.Fatal(err)
	}
	reordered := filepath.Join(t.TempDir(), "reordered.json")
	if output, err := exec.Command(executable, "merge", "--name", "polyglot", "--format", "ravel-json", "--output", reordered, inputPaths[1], inputPaths[0]).CombinedOutput(); err != nil {
		t.Fatalf("reordered merge failed: %v: %s", err, output)
	}
	reorderedData, err := os.ReadFile(reordered)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != string(reorderedData) {
		t.Fatal("merge output depended on input argument order")
	}
	var doc model.Document
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Project != "polyglot" || doc.Coverage.Manager != "multi" || len(doc.Sources) != 2 || len(doc.Coverage.Inputs) != 2 || doc.Coverage.Packages != 6 || doc.Coverage.Edges != 6 || doc.Coverage.GraphState != "complete_for_scope" || doc.Coverage.OriginState != "partial" {
		t.Fatalf("unexpected merge coverage: %#v", doc)
	}
	ids := map[string]bool{"root": true}
	alpha := 0
	for _, component := range doc.Components {
		if ids[component.ID] {
			t.Fatal("merged component ID collision")
		}
		ids[component.ID] = true
		if component.Name == "alpha" && component.Version == "1.0.0" {
			alpha++
		}
	}
	if alpha != 2 {
		t.Fatalf("same-named packages were merged: %d", alpha)
	}
	for _, edge := range doc.Edges {
		if !ids[edge.From] || !ids[edge.To] {
			t.Fatalf("dangling merged edge: %#v", edge)
		}
	}
	coverageBytes, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatal(err)
	}
	var coverage model.Coverage
	if err := json.Unmarshal(coverageBytes, &coverage); err != nil {
		t.Fatal(err)
	}
	if len(coverage.Inputs) != 2 {
		t.Fatal("per-input coverage missing from report")
	}
	for _, format := range []string{"cyclonedx-json", "spdx-json"} {
		out := filepath.Join(t.TempDir(), format+".json")
		args := []string{"merge", "--format", format, "--output", out}
		args = append(args, inputPaths...)
		cmd := exec.Command(executable, args...)
		cmd.Env = append(os.Environ(), "SOURCE_DATE_EPOCH=1700000000")
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%s merge failed: %v: %s", format, err, output)
		}
		content, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		var raw map[string]any
		if err := json.Unmarshal(content, &raw); err != nil {
			t.Fatal(err)
		}
		validateMergedSBOMSchema(t, format, raw)
		if format == "cyclonedx-json" && len(raw["components"].([]any)) != 6 {
			t.Fatal("CycloneDX merged package count wrong")
		}
		if format == "spdx-json" && len(raw["packages"].([]any)) != 7 {
			t.Fatal("SPDX merged package count wrong")
		}
	}
	duplicateArgs := []string{"merge", "--output", filepath.Join(t.TempDir(), "duplicate.json"), inputPaths[0], inputPaths[0]}
	if output, err := exec.Command(executable, duplicateArgs...).CombinedOutput(); err == nil || !strings.Contains(string(output), "duplicate") {
		t.Fatalf("duplicate input accepted: %v: %s", err, output)
	}
	if err := exec.Command(executable, "merge", "--output", inputPaths[0], inputPaths[0], inputPaths[1]).Run(); err == nil {
		t.Fatal("merge overwrote an input")
	}
	strictOutput := filepath.Join(t.TempDir(), "strict.json")
	if output, err := exec.Command(executable, "merge", "--strict", "--output", strictOutput, inputPaths[0], inputPaths[1]).CombinedOutput(); err == nil || !strings.Contains(string(output), "merged") {
		t.Fatalf("strict merge did not report partial coverage: %v: %s", err, output)
	}
	if _, err := os.Stat(strictOutput); err != nil {
		t.Fatal("strict merge did not write the SBOM")
	}
	swift := filepath.Join(t.TempDir(), "swift.ravel.json")
	if output, err := exec.Command(executable, "scan", filepath.Join("..", "testdata", "fixtures", "swift-v1"), "--format", "ravel-json", "--output", swift).CombinedOutput(); err != nil {
		t.Fatalf("Swift scan failed: %v: %s", err, output)
	}
	nested := filepath.Join(t.TempDir(), "nested.json")
	if output, err := exec.Command(executable, "merge", "--format", "ravel-json", "--output", nested, mergedPath, swift).CombinedOutput(); err != nil {
		t.Fatalf("nested merge failed: %v: %s", err, output)
	}
	nestedBytes, err := os.ReadFile(nested)
	if err != nil {
		t.Fatal(err)
	}
	var nestedDoc model.Document
	if err := json.Unmarshal(nestedBytes, &nestedDoc); err != nil {
		t.Fatal(err)
	}
	if len(nestedDoc.Coverage.Inputs) != 3 || len(nestedDoc.Sources) != 3 || nestedDoc.Coverage.Packages != 7 || nestedDoc.Coverage.GraphState != "partial" {
		t.Fatalf("nested merge lost original scopes: %#v", nestedDoc.Coverage)
	}
	if output, err := exec.Command(executable, "merge", "--output", filepath.Join(t.TempDir(), "duplicate-scope.json"), mergedPath, inputPaths[0]).CombinedOutput(); err == nil || !strings.Contains(string(output), "duplicate input scope") {
		t.Fatalf("duplicate nested scope accepted: %v: %s", err, output)
	}
}

func validateMergedSBOMSchema(t *testing.T, format string, raw any) {
	t.Helper()
	compiler := jsonschema.NewCompiler()
	var schemaID string
	names := []string{"spdx-2.3.schema.json"}
	if format == "cyclonedx-json" {
		schemaID = "http://cyclonedx.org/schema/bom-1.7.schema.json"
		names = []string{"bom-1.7.schema.json", "jsf-0.82.schema.json", "cryptography-defs.schema.json", "spdx.schema.json"}
	} else {
		schemaID = "http://spdx.org/rdf/terms/2.3"
	}
	for _, name := range names {
		data, err := os.ReadFile(filepath.Join("..", "testdata", "schema", name))
		if err != nil {
			t.Fatal(err)
		}
		var document any
		if err := json.Unmarshal(data, &document); err != nil {
			t.Fatal(err)
		}
		resource := schemaID
		if format == "cyclonedx-json" {
			resource = "http://cyclonedx.org/schema/" + name
		}
		if err := compiler.AddResource(resource, document); err != nil {
			t.Fatal(err)
		}
	}
	schema, err := compiler.Compile(schemaID)
	if err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(raw); err != nil {
		t.Fatalf("merged %s schema failed: %v", format, err)
	}
}

func TestMergeRejectsUnsafeRavelURL(t *testing.T) {
	first := filepath.Join(t.TempDir(), "first.json")
	second := filepath.Join(t.TempDir(), "second.json")
	for path, fixture := range map[string]string{first: "composer-basic", second: "cargo-basic"} {
		if output, err := exec.Command(executable, "scan", filepath.Join("..", "testdata", "fixtures", fixture), "--format", "ravel-json", "--output", path).CombinedOutput(); err != nil {
			t.Fatalf("scan failed: %v: %s", err, output)
		}
	}
	data, err := os.ReadFile(first)
	if err != nil {
		t.Fatal(err)
	}
	var doc model.Document
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	doc.Origins[0].SafeURL = "https://user:secret@example.test/repo?token=secret"
	modified, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(first, modified, 0o600); err != nil {
		t.Fatal(err)
	}
	output, err := exec.Command(executable, "merge", "--output", filepath.Join(t.TempDir(), "out.json"), first, second).CombinedOutput()
	if err == nil || !strings.Contains(string(output), "unsafe origin URL") {
		t.Fatalf("unsafe URL accepted: %v: %s", err, output)
	}
}

func TestMergeProtectsScannedSource(t *testing.T) {
	project := t.TempDir()
	lock := filepath.Join(project, "package-lock.json")
	original, err := os.ReadFile(filepath.Join("..", "testdata", "fixtures", "npm-v2", "package-lock.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lock, original, 0o600); err != nil {
		t.Fatal(err)
	}
	first := filepath.Join(t.TempDir(), "npm.ravel.json")
	second := filepath.Join(t.TempDir(), "bun.ravel.json")
	if output, err := exec.Command(executable, "scan", project, "--format", "ravel-json", "--output", first).CombinedOutput(); err != nil {
		t.Fatalf("npm scan failed: %v: %s", err, output)
	}
	if output, err := exec.Command(executable, "scan", filepath.Join("..", "testdata", "fixtures", "bun-basic"), "--format", "ravel-json", "--output", second).CombinedOutput(); err != nil {
		t.Fatalf("Bun scan failed: %v: %s", err, output)
	}
	if output, err := exec.Command(executable, "merge", "--output", lock, first, second).CombinedOutput(); err == nil || !strings.Contains(string(output), "scanned source") {
		t.Fatalf("merge overwrote scanned lockfile: %v: %s", err, output)
	}
	current, err := os.ReadFile(lock)
	if err != nil {
		t.Fatal(err)
	}
	if string(current) != string(original) {
		t.Fatal("scanned lockfile changed")
	}
}
