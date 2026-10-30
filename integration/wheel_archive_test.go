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

func TestWheelBuiltByUV(t *testing.T) {
	wheel := filepath.Join("..", "testdata", "artifacts", "python", "ravel_wheel_sample-1.2.3-py3-none-any.whl")
	input, err := os.ReadFile(wheel)
	if err != nil {
		t.Fatal(err)
	}
	sha := sha256.Sum256(input)
	cmd := exec.Command(executable, "scan", wheel, "--format", "ravel-json")
	data, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "user:secret") || strings.Contains(string(data), "token=hidden") || strings.Contains(string(data), "docs.example.test") {
		t.Fatal("wheel source credentials or documentation URL leaked into development source")
	}
	var doc model.Document
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Coverage.Manager != "python-wheel" || doc.Coverage.GraphState != "partial" || doc.Coverage.OriginState != "partial" || len(doc.Components) != 1 || doc.Components[0].Kind != "package" || doc.Components[0].Name != "ravel-wheel-sample" || doc.Components[0].Version != "1.2.3" || doc.Components[0].PURL != "" || len(doc.Components[0].Hashes) != 1 || doc.Components[0].Hashes[0].Content != hex.EncodeToString(sha[:]) || len(doc.Edges) != 0 || len(doc.Development) != 1 || doc.Development[0].SafeURL != "https://github.com/ravel/sample.git" {
		t.Fatalf("unexpected wheel SBOM: %#v", doc)
	}
	if !hasArchiveIssue(doc, "declared_dependencies_unresolved") || !hasArchiveIssue(doc, "distribution_source_unavailable") {
		t.Fatal("wheel Requires-Dist was not reported as unresolved")
	}
	for _, format := range []string{"cyclonedx-json", "spdx-json"} {
		cmd = exec.Command(executable, "scan", wheel, "--format", format)
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
	cmd = exec.Command(executable, "scan", wheel, "--output", wheel)
	if output, err := cmd.CombinedOutput(); err == nil || !strings.Contains(string(output), "cannot overwrite") {
		t.Fatalf("wheel was overwritten: %v, %s", err, output)
	}
}

func TestWheelAmbiguousAndInvalidMetadata(t *testing.T) {
	cases := []struct {
		name, issue string
		entries     map[string]string
	}{
		{name: "ambiguous", issue: "ambiguous_archive_metadata", entries: map[string]string{
			"sample-1.0.dist-info/METADATA": "Name: sample\nVersion: 1.0\n\n",
			"other-1.0.dist-info/METADATA":  "Name: other\nVersion: 1.0\n\n",
		}},
		{name: "duplicate", issue: "ambiguous_archive_metadata", entries: map[string]string{
			"sample-1.0.dist-info/METADATA": "Name: sample\nVersion: 1.0\n\n",
			"sample-1.0.dist-info/WHEEL":    "Wheel-Version: 1.0\n\n",
			"sample-1.0.dist-info/RECORD":   "",
		}},
		{name: "mismatch", issue: "invalid_archive_metadata", entries: map[string]string{
			"sample-1.0.dist-info/METADATA": "Name: wrong\nVersion: 1.0\n\n",
			"sample-1.0.dist-info/WHEEL":    "Wheel-Version: 1.0\n\n",
			"sample-1.0.dist-info/RECORD":   "",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wheel := filepath.Join(t.TempDir(), "sample-1.0-py3-none-any.whl")
			output, err := os.Create(wheel)
			if err != nil {
				t.Fatal(err)
			}
			writer := zip.NewWriter(output)
			for name, content := range tc.entries {
				entry, err := writer.Create(name)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := entry.Write([]byte(content)); err != nil {
					t.Fatal(err)
				}
			}
			if tc.name == "duplicate" {
				entry, err := writer.Create("sample-1.0.dist-info/METADATA")
				if err != nil {
					t.Fatal(err)
				}
				if _, err := entry.Write([]byte("Name: hostile\nVersion: 9\n\n")); err != nil {
					t.Fatal(err)
				}
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			if err := output.Close(); err != nil {
				t.Fatal(err)
			}
			data, err := exec.Command(executable, "scan", wheel, "--format", "ravel-json").Output()
			if err != nil {
				t.Fatal(err)
			}
			var doc model.Document
			if err := json.Unmarshal(data, &doc); err != nil {
				t.Fatal(err)
			}
			if len(doc.Components) != 1 || doc.Components[0].Kind != "file" || doc.Components[0].PURL != "" || len(doc.Development) != 0 || !hasArchiveIssue(doc, tc.issue) {
				t.Fatalf("invalid wheel supplied package identity: %#v", doc)
			}
			for _, format := range []string{"cyclonedx-json", "spdx-json"} {
				cmd := exec.Command(executable, "scan", wheel, "--format", format)
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
						t.Fatal("unidentified wheel exported as a library")
					}
				} else {
					packages := raw["packages"].([]any)
					if packages[1].(map[string]any)["primaryPackagePurpose"] != "FILE" {
						t.Fatal("unidentified wheel exported as an SPDX library")
					}
				}
			}
		})
	}
}

func hasArchiveIssue(doc model.Document, code string) bool {
	for _, issue := range doc.Coverage.Issues {
		if issue.Code == code {
			return true
		}
	}
	return false
}
