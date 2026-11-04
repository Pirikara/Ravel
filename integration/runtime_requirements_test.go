package integration_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Pirikara/Ravel/internal/model"
	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
)

func runtimeTestWrite(t *testing.T, root, name, content string) {
	t.Helper()
	file := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func runtimeTestScan(t *testing.T, root string, flags ...string) (model.Document, string, int) {
	t.Helper()
	output := filepath.Join(t.TempDir(), "result.json")
	args := append([]string{"scan", root, "--format", "ravel-json", "--output", output}, flags...)
	message, err := exec.Command(executable, args...).CombinedOutput()
	if err != nil {
		if exit, ok := err.(*exec.ExitError); ok {
			return model.Document{}, string(message), exit.ExitCode()
		}
		t.Fatal(err)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var doc model.Document
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	return doc, string(message), 0
}

func TestRepositoryRuntimeRequirementsAcrossProjects(t *testing.T) {
	root := t.TempDir()
	lock, err := os.ReadFile(filepath.Join("..", "testdata", "fixtures", "npm-v2", "package-lock.json"))
	if err != nil {
		t.Fatal(err)
	}
	runtimeTestWrite(t, root, "package-lock.json", string(lock))
	runtimeTestWrite(t, root, "package.json", `{"name":"npm-v2-sample","engines":{"node":">=20 <23"}}`)
	runtimeTestWrite(t, root, ".nvmrc", "v22.4.1\n")
	runtimeTestWrite(t, root, ".tool-versions", "nodejs 22.4.1\nruby 3.3.0\n")
	runtimeTestWrite(t, root, "services/go/go.mod", "module example.com/service\n\ngo 1.24.0\ntoolchain go1.24.3\n")
	runtimeTestWrite(t, root, "services/workspace/go.work", "go 1.25.0\ntoolchain go1.25.1\n")
	runtimeTestWrite(t, root, "services/python/.python-version", "3.12.4\n")
	runtimeTestWrite(t, root, "services/python/pyproject.toml", "[project]\nname = 'service'\nversion = '0.1.0'\nrequires-python = '>=3.12'\n")
	runtimeTestWrite(t, root, "services/rust/Cargo.toml", "[package]\nname = 'service'\nversion = '0.1.0'\nrust-version = '1.82'\n")
	runtimeTestWrite(t, root, "services/rust/rust-toolchain.toml", "[toolchain]\nchannel = '1.84.0'\n")
	runtimeTestWrite(t, root, "services/dotnet/global.json", `{"sdk":{"version":"9.0.100","rollForward":"latestFeature"}}`)
	runtimeTestWrite(t, root, "services/swift/Package.swift", "// swift-tools-version: 6.0\nimport PackageDescription\n")
	runtimeTestWrite(t, root, "services/dart/pubspec.yaml", "name: demo\nenvironment:\n  sdk: ^3.5.0\n")

	single, message, code := runtimeTestScan(t, root)
	if code != 0 || single.Coverage.Packages == 0 || len(single.Runtimes) != 4 {
		t.Fatalf("single-project runtime scan failed: code=%d message=%s runtimes=%#v", code, message, single.Runtimes)
	}
	doc, message, code := runtimeTestScan(t, root, "--all", "--recursive")
	if code != 0 {
		t.Fatalf("recursive runtime scan failed: code=%d message=%s", code, message)
	}
	want := map[string]bool{
		"node|compatibility|>=20 <23":  false,
		"node|selection|v22.4.1":       false,
		"python|selection|3.12.4":      false,
		"python|compatibility|>=3.12":  false,
		"go|minimum|1.24.0":            false,
		"go|suggested|1.24.3":          false,
		"go|minimum|1.25.0":            false,
		"go|suggested|1.25.1":          false,
		"rust|minimum|1.82":            false,
		"rust|selection|1.84.0":        false,
		"dotnet-sdk|selection|9.0.100": false,
		"swift-tools|minimum|6.0":      false,
		"dart|compatibility|^3.5.0":    false,
	}
	for _, requirement := range doc.Runtimes {
		key := requirement.Name + "|" + requirement.Relation + "|" + requirement.Requirement
		if _, ok := want[key]; ok {
			want[key] = true
		}
		if requirement.Scope == "" || requirement.Evidence.InputPath == "" || !strings.HasPrefix(requirement.Evidence.InputDigest, "sha256:") || requirement.Evidence.Method != "repository-declaration" {
			t.Fatalf("runtime evidence is incomplete: %#v", requirement)
		}
		if requirement.Name == "dotnet-sdk" && requirement.Policy != "latestFeature" {
			t.Fatalf(".NET SDK roll-forward policy was lost: %#v", requirement)
		}
	}
	for requirement, found := range want {
		if !found {
			t.Errorf("missing runtime declaration %s", requirement)
		}
	}
	if len(doc.Runtimes) < len(want) {
		t.Fatalf("runtime declarations were lost: %#v", doc.Runtimes)
	}
}

func TestRuntimeOnlyRepositoryAndStandardExports(t *testing.T) {
	root := t.TempDir()
	runtimeTestWrite(t, root, ".nvmrc", "lts/*\n")
	runtimeTestWrite(t, root, ".python-version", "3.12.4\n")
	doc, message, code := runtimeTestScan(t, root)
	if code != 0 || doc.Coverage.Manager != "runtime" || doc.Coverage.Packages != 0 || doc.Coverage.GraphState != "unknown" || len(doc.Runtimes) != 2 {
		t.Fatalf("runtime-only repository failed: code=%d message=%s doc=%#v", code, message, doc)
	}
	for _, format := range []string{"cyclonedx-json", "spdx-json"} {
		output := filepath.Join(t.TempDir(), "sbom.json")
		message, err := exec.Command(executable, "scan", root, "--format", format, "--output", output).CombinedOutput()
		if err != nil {
			t.Fatalf("%s export failed: %v %s", format, err, message)
		}
		data, err := os.ReadFile(output)
		if err != nil {
			t.Fatal(err)
		}
		if format == "cyclonedx-json" {
			validateRuntimeCycloneDX(t, data)
		} else {
			var output struct {
				Packages []struct {
					Comment string `json:"comment"`
				} `json:"packages"`
			}
			if err := json.Unmarshal(data, &output); err != nil || len(output.Packages) == 0 || !strings.Contains(output.Packages[0].Comment, "node selection lts/*") {
				t.Fatalf("SPDX runtime declaration missing: %v %s", err, data)
			}
		}
	}
	if _, message, code := runtimeTestScan(t, root, "--output", filepath.Join(root, ".nvmrc")); code != 2 || !strings.Contains(message, "cannot overwrite") {
		t.Fatalf("runtime declaration could be overwritten: code=%d message=%s", code, message)
	}
}

func TestGoManifestWithoutVendorReportsRuntimeAndMissingGraph(t *testing.T) {
	root := t.TempDir()
	runtimeTestWrite(t, root, "go.mod", "module example.com/demo\n\ngo 1.25.0\n")
	doc, message, code := runtimeTestScan(t, root)
	if code != 0 || doc.Coverage.Packages != 0 || doc.Coverage.GraphState != "partial" || len(doc.Runtimes) != 1 || doc.Runtimes[0].Requirement != "1.25.0" {
		t.Fatalf("Go runtime-only scan failed: code=%d message=%s doc=%#v", code, message, doc)
	}
	foundSkip := false
	for _, issue := range doc.Coverage.Issues {
		if issue.Code == "collector_skipped_requires_resolve" && issue.Name == "go" {
			foundSkip = true
		}
	}
	if !foundSkip {
		t.Fatalf("missing package graph was not reported: %#v", doc.Coverage.Issues)
	}
	if _, message, code := runtimeTestScan(t, root, "--manager", "go"); code != 2 || !strings.Contains(message, "--resolve") {
		t.Fatalf("explicit Go scan did not require resolver opt-in: code=%d message=%s", code, message)
	}
}

func validateRuntimeCycloneDX(t *testing.T, data []byte) {
	t.Helper()
	compiler := jsonschema.NewCompiler()
	for _, name := range []string{"bom-1.7.schema.json", "jsf-0.82.schema.json", "cryptography-defs.schema.json", "spdx.schema.json"} {
		schemaData, err := os.ReadFile(filepath.Join("..", "testdata", "schema", name))
		if err != nil {
			t.Fatal(err)
		}
		var schemaDoc any
		if err := json.Unmarshal(schemaData, &schemaDoc); err != nil {
			t.Fatal(err)
		}
		if err := compiler.AddResource("http://cyclonedx.org/schema/"+name, schemaDoc); err != nil {
			t.Fatal(err)
		}
	}
	schema, err := compiler.Compile("http://cyclonedx.org/schema/bom-1.7.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var output any
	if err := json.Unmarshal(data, &output); err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(output); err != nil {
		t.Fatal(err)
	}
	var bom struct {
		Metadata struct {
			Component struct {
				Properties []struct {
					Name  string `json:"name"`
					Value string `json:"value"`
				} `json:"properties"`
			} `json:"component"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(data, &bom); err != nil {
		t.Fatal(err)
	}
	if len(bom.Metadata.Component.Properties) != 2 || bom.Metadata.Component.Properties[0].Name != "ravel:runtimeRequirement" || !strings.Contains(bom.Metadata.Component.Properties[0].Value, `"name":"node"`) {
		t.Fatalf("CycloneDX runtime properties missing: %s", data)
	}
}
