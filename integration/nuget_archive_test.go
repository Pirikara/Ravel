package integration_test

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"ravel/internal/model"
)

func TestNuGetArchiveGeneratedByDotnet(t *testing.T) {
	archive := filepath.Join("..", "testdata", "artifacts", "nuget", "Ravel.Beta.1.2.3.nupkg")
	input, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	sha := sha256.Sum256(input)
	cmd := exec.Command(executable, "scan", archive, "--format", "ravel-json")
	data, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "secret") || strings.Contains(string(data), "token=hidden") {
		t.Fatal("NuGet archive credentials leaked")
	}
	var doc model.Document
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Coverage.Manager != "nuget-archive" || doc.Coverage.OriginState != "partial" || len(doc.Components) != 1 || doc.Components[0].Name != "Ravel.Beta" || doc.Components[0].Version != "1.2.3" || doc.Components[0].PURL != "" || len(doc.Components[0].Hashes) != 1 || doc.Components[0].Hashes[0].Content != hex.EncodeToString(sha[:]) || len(doc.Edges) != 0 || len(doc.Development) != 1 || doc.Development[0].SafeURL != "https://github.com/team/beta.git" {
		t.Fatalf("NuGet artifact identity, hash, or repository wrong: %#v", doc)
	}
	if !hasArchiveIssue(doc, "distribution_source_unavailable") {
		t.Fatal("NUPKG archive incorrectly claimed a known distribution source")
	}
	for _, format := range []string{"cyclonedx-json", "spdx-json"} {
		cmd = exec.Command(executable, "scan", archive, "--format", format)
		cmd.Env = append(os.Environ(), "SOURCE_DATE_EPOCH=1700000000")
		data, err = cmd.Output()
		if err != nil {
			t.Fatal(err)
		}
		var raw map[string]any
		if err := json.Unmarshal(data, &raw); err != nil {
			t.Fatal(err)
		}
		validateMergedSBOMSchema(t, format, raw)
	}
}

func TestNuGetArchiveAmbiguousDescriptor(t *testing.T) {
	file := filepath.Join(t.TempDir(), "ambiguous.nupkg")
	output, err := os.Create(file)
	if err != nil {
		t.Fatal(err)
	}
	writer := zip.NewWriter(output)
	for _, name := range []string{"first.nuspec", "second.nuspec"} {
		entry, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write([]byte(`<package><metadata><id>wrong</id><version>1.0</version></metadata></package>`)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := output.Close(); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(executable, "scan", file, "--format", "ravel-json")
	data, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	var doc model.Document
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Components) != 1 || doc.Components[0].Kind != "file" || doc.Components[0].Version != "" {
		t.Fatal("ambiguous nuspec supplied package identity")
	}
	found := false
	for _, issue := range doc.Coverage.Issues {
		found = found || issue.Code == "ambiguous_archive_metadata"
	}
	if !found {
		t.Fatal("ambiguous nuspec was not reported")
	}
	for _, format := range []string{"cyclonedx-json", "spdx-json"} {
		cmd = exec.Command(executable, "scan", file, "--format", format)
		cmd.Env = append(os.Environ(), "SOURCE_DATE_EPOCH=1700000000")
		encoded, err := cmd.Output()
		if err != nil {
			t.Fatal(err)
		}
		var raw map[string]any
		if err := json.Unmarshal(encoded, &raw); err != nil {
			t.Fatal(err)
		}
		validateMergedSBOMSchema(t, format, raw)
		if format == "cyclonedx-json" {
			components := raw["components"].([]any)
			if components[0].(map[string]any)["type"] != "file" {
				t.Fatal("unidentified archive exported as a library")
			}
		} else {
			packages := raw["packages"].([]any)
			if packages[1].(map[string]any)["primaryPackagePurpose"] != "FILE" {
				t.Fatal("unidentified archive exported as an SPDX library")
			}
		}
	}
}

func TestNuGetArchiveRejectsFakeNuspecRoot(t *testing.T) {
	file := filepath.Join(t.TempDir(), "fake.nupkg")
	output, err := os.Create(file)
	if err != nil {
		t.Fatal(err)
	}
	writer := zip.NewWriter(output)
	entry, err := writer.Create("fake.nuspec")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entry.Write([]byte(`<not-a-package><metadata><id>wrong</id><version>9.9</version></metadata></not-a-package>`)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := output.Close(); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command(executable, "scan", file, "--format", "ravel-json").CombinedOutput(); err == nil || !strings.Contains(string(output), "invalid NuGet nuspec") {
		t.Fatalf("fake nuspec accepted: %v, %s", err, output)
	}
}
