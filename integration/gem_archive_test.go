package integration_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Pirikara/Ravel/internal/model"
)

func TestGemBuiltByRubyGems(t *testing.T) {
	gem := filepath.Join("..", "testdata", "artifacts", "ruby", "ravel-archive-sample-1.2.3.gem")
	input, err := os.ReadFile(gem)
	if err != nil {
		t.Fatal(err)
	}
	sha := sha256.Sum256(input)
	data, err := exec.Command(executable, "scan", gem, "--format", "ravel-json").Output()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "example-secret") || strings.Contains(string(data), "token=private") {
		t.Fatal("gem metadata credentials leaked into SBOM")
	}
	var doc model.Document
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Coverage.Manager != "ruby-gem" || doc.Coverage.GraphState != "partial" || doc.Coverage.OriginState != "partial" || len(doc.Components) != 1 || doc.Components[0].Kind != "package" || doc.Components[0].Name != "ravel-archive-sample" || doc.Components[0].Version != "1.2.3" || doc.Components[0].PURL != "" || len(doc.Components[0].Hashes) != 1 || doc.Components[0].Hashes[0].Content != hex.EncodeToString(sha[:]) || len(doc.Edges) != 0 || len(doc.Development) != 1 || doc.Development[0].SafeURL != "https://github.com/ravel/ruby-archive.git" {
		t.Fatalf("unexpected RubyGems archive SBOM: %#v", doc)
	}
	if !hasArchiveIssue(doc, "declared_dependencies_unresolved") || !hasArchiveIssue(doc, "distribution_source_unavailable") {
		t.Fatal("gem dependency requirement was treated as a resolved graph")
	}
	strictOutput := filepath.Join(t.TempDir(), "strict.json")
	strict := exec.Command(executable, "scan", gem, "--format", "ravel-json", "--strict", "--output", strictOutput)
	if output, err := strict.CombinedOutput(); err == nil || strict.ProcessState.ExitCode() != 3 {
		t.Fatalf("strict mode accepted unresolved gem coverage: %v, %s", err, output)
	}
	if _, err := os.Stat(strictOutput); err != nil {
		t.Fatalf("strict mode did not write its SBOM: %v", err)
	}
	for _, format := range []string{"cyclonedx-json", "spdx-json"} {
		cmd := exec.Command(executable, "scan", gem, "--format", format)
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
	if output, err := exec.Command(executable, "scan", gem, "--output", gem).CombinedOutput(); err == nil || !strings.Contains(string(output), "cannot overwrite") {
		t.Fatalf("gem archive was overwritten: %v, %s", err, output)
	}
}

func TestGemAmbiguousAndInvalidMetadata(t *testing.T) {
	valid := []byte("--- !ruby/object:Gem::Specification\nname: sample\nversion: !ruby/object:Gem::Version\n  version: 1.0.0\nmetadata: {}\n")
	contents := gemTestContents(t)
	tests := []struct {
		name, issue, kind string
		entries           []gemTestEntry
	}{
		{name: "plain-metadata", kind: "package", entries: []gemTestEntry{{"metadata", valid}, {"data.tar.gz", contents}}},
		{name: "missing-metadata", issue: "missing_archive_metadata", kind: "file", entries: []gemTestEntry{{"data.tar.gz", contents}}},
		{name: "duplicate-metadata", issue: "ambiguous_archive_metadata", kind: "file", entries: []gemTestEntry{{"metadata", valid}, {"metadata", valid}, {"data.tar.gz", contents}}},
		{name: "missing-data", issue: "invalid_archive_metadata", kind: "file", entries: []gemTestEntry{{"metadata", valid}}},
		{name: "invalid-name", issue: "invalid_archive_metadata", kind: "file", entries: []gemTestEntry{{"metadata", []byte(strings.Replace(string(valid), "name: sample", "name: ../wrong", 1))}, {"data.tar.gz", contents}}},
		{name: "multiple-yaml-documents", issue: "invalid_archive_metadata", kind: "file", entries: []gemTestEntry{{"metadata", append(append([]byte{}, valid...), []byte("---\nname: hostile\n")...)}, {"data.tar.gz", contents}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gem := writeGemTestArchive(t, tc.entries)
			encoded, err := exec.Command(executable, "scan", gem, "--format", "ravel-json").Output()
			if err != nil {
				t.Fatal(err)
			}
			var doc model.Document
			if err := json.Unmarshal(encoded, &doc); err != nil {
				t.Fatal(err)
			}
			if len(doc.Components) != 1 || doc.Components[0].Kind != tc.kind || doc.Components[0].PURL != "" || (tc.issue != "" && !hasArchiveIssue(doc, tc.issue)) {
				t.Fatalf("unexpected gem archive identity: %#v", doc)
			}
			if tc.kind == "file" && len(doc.Development) != 0 {
				t.Fatal("invalid gem archive supplied development repository")
			}
			for _, format := range []string{"cyclonedx-json", "spdx-json"} {
				cmd := exec.Command(executable, "scan", gem, "--format", format)
				cmd.Env = append(os.Environ(), "SOURCE_DATE_EPOCH=1700000000")
				output, err := cmd.Output()
				if err != nil {
					t.Fatal(err)
				}
				var raw map[string]any
				if err := json.Unmarshal(output, &raw); err != nil {
					t.Fatal(err)
				}
				validateMergedSBOMSchema(t, format, raw)
			}
		})
	}
}

func TestGemRejectsMalformedContents(t *testing.T) {
	valid := []byte("--- !ruby/object:Gem::Specification\nname: sample\nversion: !ruby/object:Gem::Version\n  version: 1.0.0\n")
	gem := writeGemTestArchive(t, []gemTestEntry{{"metadata", valid}, {"data.tar.gz", []byte("not gzip")}})
	output, err := exec.Command(executable, "scan", gem).CombinedOutput()
	if err == nil || !strings.Contains(string(output), "invalid gem contents") {
		t.Fatalf("malformed gem content was accepted: %v, %s", err, output)
	}
}

func TestGemArchiveAndBundlerLockRemainDistinct(t *testing.T) {
	gem := filepath.Join("..", "testdata", "artifacts", "ruby", "ravel-archive-sample-1.2.3.gem")
	lock := filepath.Join(t.TempDir(), "Gemfile.lock")
	content := "GEM\n  remote: https://rubygems.org/\n  specs:\n    ravel-archive-sample (1.2.3)\n\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n  ravel-archive-sample (= 1.2.3)\n\nBUNDLED WITH\n   4.0.20\n"
	if err := os.WriteFile(lock, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	archiveJSON := filepath.Join(t.TempDir(), "archive.json")
	lockJSON := filepath.Join(t.TempDir(), "lock.json")
	for _, item := range [][2]string{{gem, archiveJSON}, {lock, lockJSON}} {
		if output, err := exec.Command(executable, "scan", item[0], "--format", "ravel-json", "--output", item[1]).CombinedOutput(); err != nil {
			t.Fatalf("scan failed: %v, %s", err, output)
		}
	}
	merged := filepath.Join(t.TempDir(), "merged.json")
	if output, err := exec.Command(executable, "merge", "--format", "ravel-json", "--output", merged, archiveJSON, lockJSON).CombinedOutput(); err != nil {
		t.Fatalf("merge failed: %v, %s", err, output)
	}
	data, err := os.ReadFile(merged)
	if err != nil {
		t.Fatal(err)
	}
	var doc model.Document
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Components) != 2 || doc.Components[0].ID == doc.Components[1].ID || len(doc.Origins) != 2 || len(doc.Development) != 1 {
		t.Fatalf("archive and lock occurrences were conflated: %#v", doc)
	}
	var registry, archive bool
	for _, component := range doc.Components {
		if component.Name != "ravel-archive-sample" || component.Version != "1.2.3" {
			t.Fatalf("unexpected merged component: %#v", component)
		}
		if component.PURL == "pkg:gem/ravel-archive-sample@1.2.3" {
			registry = true
		} else if component.PURL == "" && len(component.Hashes) == 1 {
			archive = true
		}
	}
	if !registry || !archive || doc.Development[0].SafeURL != "https://github.com/ravel/ruby-archive.git" {
		t.Fatalf("registry and archive evidence was not kept separate: %#v", doc)
	}
}

func gemTestContents(t *testing.T) []byte {
	t.Helper()
	var output bytes.Buffer
	compressed := gzip.NewWriter(&output)
	archive := tar.NewWriter(compressed)
	data := []byte("module Sample; end\n")
	if err := archive.WriteHeader(&tar.Header{Name: "lib/sample.rb", Mode: 0o644, Size: int64(len(data))}); err != nil {
		t.Fatal(err)
	}
	if _, err := archive.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := compressed.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

type gemTestEntry struct {
	name string
	data []byte
}

func writeGemTestArchive(t *testing.T, entries []gemTestEntry) string {
	t.Helper()
	file := filepath.Join(t.TempDir(), "sample-1.0.0.gem")
	output, err := os.Create(file)
	if err != nil {
		t.Fatal(err)
	}
	archive := tar.NewWriter(output)
	for _, entry := range entries {
		if err := archive.WriteHeader(&tar.Header{Name: entry.name, Mode: 0o644, Size: int64(len(entry.data))}); err != nil {
			t.Fatal(err)
		}
		if _, err := archive.Write(entry.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := output.Close(); err != nil {
		t.Fatal(err)
	}
	return file
}
