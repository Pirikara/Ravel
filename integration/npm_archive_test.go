package integration_test

import (
	"archive/tar"
	"compress/gzip"
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

func TestNpmTarballBuiltByNpm(t *testing.T) {
	archive := filepath.Join("..", "testdata", "artifacts", "npm", "ravel-packed-sample-2.3.4.tgz")
	input, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	sha := sha256.Sum256(input)
	data, err := exec.Command(executable, "scan", archive, "--format", "ravel-json").Output()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "user:secret") || strings.Contains(string(data), "token=hidden") {
		t.Fatal("npm tarball repository credentials leaked")
	}
	var doc model.Document
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Coverage.Manager != "npm-archive" || doc.Coverage.GraphState != "partial" || doc.Coverage.OriginState != "partial" || len(doc.Components) != 1 || doc.Components[0].Name != "@ravel/packed-sample" || doc.Components[0].Version != "2.3.4" || doc.Components[0].PURL != "" || len(doc.Components[0].Hashes) != 1 || doc.Components[0].Hashes[0].Content != hex.EncodeToString(sha[:]) || len(doc.Edges) != 0 || len(doc.Development) != 1 || doc.Development[0].SafeURL != "https://github.com/ravel/packed-sample.git" {
		t.Fatalf("unexpected npm archive: %#v", doc)
	}
	if !hasArchiveIssue(doc, "declared_dependencies_unresolved") || !hasArchiveIssue(doc, "distribution_source_unavailable") {
		t.Fatal("npm dependency ranges were not reported as unresolved")
	}
	for _, format := range []string{"cyclonedx-json", "spdx-json"} {
		cmd := exec.Command(executable, "scan", archive, "--format", format)
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
	}
	if output, err := exec.Command(executable, "scan", archive, "--output", archive).CombinedOutput(); err == nil || !strings.Contains(string(output), "cannot overwrite") {
		t.Fatalf("npm archive was overwritten: %v, %s", err, output)
	}
}

func TestNpmTarballAmbiguousAndBundled(t *testing.T) {
	archive := filepath.Join(t.TempDir(), "ambiguous.tgz")
	output, err := os.Create(archive)
	if err != nil {
		t.Fatal(err)
	}
	compressed := gzip.NewWriter(output)
	writer := tar.NewWriter(compressed)
	for _, item := range []struct{ name, content string }{
		{"package/package.json", `{"name":"first","version":"1.0"}`},
		{"package/node_modules/bundled/index.js", "module.exports = true;"},
		{"package/package.json", `{"name":"second","version":"9.0"}`},
	} {
		content := []byte(item.content)
		if err := writer.WriteHeader(&tar.Header{Name: item.name, Mode: 0o644, Size: int64(len(content))}); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := compressed.Close(); err != nil {
		t.Fatal(err)
	}
	if err := output.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := exec.Command(executable, "scan", archive, "--format", "ravel-json").Output()
	if err != nil {
		t.Fatal(err)
	}
	var doc model.Document
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Components) != 1 || doc.Components[0].Kind != "file" || doc.Components[0].Version != "" || len(doc.Development) != 0 || !hasArchiveIssue(doc, "ambiguous_archive_metadata") || !hasArchiveIssue(doc, "bundled_dependencies_unscanned") {
		t.Fatalf("ambiguous or bundled package was treated as resolved: %#v", doc)
	}
	for _, format := range []string{"cyclonedx-json", "spdx-json"} {
		cmd := exec.Command(executable, "scan", archive, "--format", format)
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
	}
}
