package integration_test

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func dockerTestEntries(t *testing.T, layers []ociTestLayer) []ociTestEntry {
	t.Helper()
	entries := make([]ociTestEntry, 0, len(layers)+2)
	paths := make([]string, 0, len(layers))
	diffIDs := make([]string, 0, len(layers))
	for i, layer := range layers {
		data := ociTestTar(t, layer.entries)
		hash := sha256.Sum256(data)
		diffID := "sha256:" + hex.EncodeToString(hash[:])
		if layer.diffID != "" {
			diffID = layer.diffID
		}
		name := "legacy/layer-" + strconv.Itoa(i) + ".tar"
		entries = append(entries, ociTestEntry{name: name, data: data})
		paths = append(paths, name)
		diffIDs = append(diffIDs, diffID)
	}
	configData, err := json.Marshal(map[string]any{"os": "linux", "architecture": "amd64", "rootfs": map[string]any{"type": "layers", "diff_ids": diffIDs}})
	if err != nil {
		t.Fatal(err)
	}
	configHash := sha256.Sum256(configData)
	configName := hex.EncodeToString(configHash[:]) + ".json"
	entries = append(entries, ociTestEntry{name: configName, data: configData})
	manifestData, err := json.Marshal([]map[string]any{{"Config": configName, "RepoTags": []string{"ravel-test:latest"}, "Layers": paths}})
	if err != nil {
		t.Fatal(err)
	}
	entries = append(entries, ociTestEntry{name: "manifest.json", data: manifestData})
	return entries
}

func dockerTestArchive(t *testing.T, name string, entries []ociTestEntry) string {
	t.Helper()
	archive := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(archive, ociTestTar(t, entries), 0o600); err != nil {
		t.Fatal(err)
	}
	return archive
}

func gzipDockerTestArchive(t *testing.T, source, name string) string {
	t.Helper()
	plain, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(archive, compressed.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return archive
}

func TestLegacyDockerSaveArchive(t *testing.T) {
	const node = "app/node_modules/"
	entries := dockerTestEntries(t, []ociTestLayer{
		{entries: []ociTestEntry{
			{name: "var/lib/dpkg/status", data: ociTestStatus(t, "dpkg-basic")},
			{name: node + "old/package.json", data: []byte(`{"name":"old","version":"1.0.0"}`)},
		}},
		{entries: []ociTestEntry{
			{name: node + ".wh.old"},
			{name: node + "new/package.json", data: []byte(`{"name":"new","version":"2.0.0"}`)},
			{name: "usr/local/lib/python3.13/site-packages/idna-3.10.dist-info/METADATA", data: []byte("Metadata-Version: 2.3\nName: idna\nVersion: 3.10\n")},
		}},
	})
	archive := dockerTestArchive(t, "image.docker.tar", entries)
	doc, output, code := ociTestScan(t, archive)
	if code != 0 || doc.Coverage.Packages != 6 || doc.Source != archive || len(doc.Sources) != 1 || doc.Sources[0] != archive || len(doc.Coverage.Platforms) != 1 || doc.Coverage.Platforms[0] != "linux/amd64" {
		t.Fatalf("legacy Docker save scan failed: code=%d output=%s coverage=%#v", code, output, doc.Coverage)
	}
	names := map[string]bool{}
	for _, component := range doc.Components {
		names[component.Name] = true
	}
	if !names["new"] || !names["idna"] || names["old"] {
		t.Fatalf("legacy Docker save overlay was incorrect: %#v", names)
	}
	plain := dockerTestArchive(t, "image.tar", entries)
	if _, output, code := ociTestScan(t, plain, "--manager", "oci"); code != 0 {
		t.Fatalf("explicit manager did not scan Docker save tar: code=%d output=%s", code, output)
	}
	compressed := gzipDockerTestArchive(t, archive, "image.docker.tar.gz")
	compressedDoc, output, code := ociTestScan(t, compressed)
	if code != 0 || compressedDoc.Coverage.Packages != 6 || compressedDoc.Source != compressed || len(compressedDoc.Sources) != 1 || compressedDoc.Sources[0] != compressed {
		t.Fatalf("gzip Docker save scan failed: code=%d output=%s coverage=%#v", code, output, compressedDoc.Coverage)
	}
	if _, output, code := ociTestScan(t, gzipDockerTestArchive(t, archive, "image.tar.gz"), "--manager", "oci"); code != 0 {
		t.Fatalf("explicit manager did not scan gzip Docker save tar: code=%d output=%s", code, output)
	}
	if _, output, code := ociTestScan(t, archive, "--platform", "linux/arm64"); code == 0 || !strings.Contains(output, "no manifest for platform") {
		t.Fatalf("Docker save platform mismatch was accepted: code=%d output=%s", code, output)
	}
}

func TestGzipOCIArchive(t *testing.T) {
	layout := ociTestLayout(t)
	image := ociTestImage(t, layout, "linux", "amd64", []ociTestLayer{{entries: []ociTestEntry{{name: "var/lib/dpkg/status", data: ociTestStatus(t, "dpkg-basic")}}}})
	ociTestIndex(t, layout, image)
	plain := ociTestArchive(t, layout, "image.oci.tar")
	compressed := gzipDockerTestArchive(t, plain, "image.oci.tar.gz")
	doc, output, code := ociTestScan(t, compressed)
	if code != 0 || doc.Coverage.Packages != 4 || doc.Source != compressed {
		t.Fatalf("gzip OCI archive scan failed: code=%d output=%s coverage=%#v", code, output, doc.Coverage)
	}
	data, err := os.ReadFile(compressed)
	if err != nil {
		t.Fatal(err)
	}
	truncated := filepath.Join(t.TempDir(), "truncated.oci.tar.gz")
	if err := os.WriteFile(truncated, data[:len(data)-4], 0o600); err != nil {
		t.Fatal(err)
	}
	if _, output, code := ociTestScan(t, truncated); code == 0 || !strings.Contains(output, "unexpected EOF") {
		t.Fatalf("truncated gzip OCI archive was accepted: code=%d output=%s", code, output)
	}
}

func TestLegacyDockerSaveArchiveRejectsInvalidInput(t *testing.T) {
	base := func() []ociTestEntry {
		return dockerTestEntries(t, []ociTestLayer{{entries: []ociTestEntry{{name: "app/node_modules/foo/package.json", data: []byte(`{"name":"foo","version":"1.0.0"}`)}}}})
	}
	for _, tc := range []struct {
		name, want string
		change     func([]ociTestEntry) []ociTestEntry
	}{
		{"diff-id", "diff ID mismatch", func(entries []ociTestEntry) []ociTestEntry {
			var config map[string]any
			if err := json.Unmarshal(entries[1].data, &config); err != nil {
				t.Fatal(err)
			}
			config["rootfs"].(map[string]any)["diff_ids"] = []string{"sha256:" + strings.Repeat("0", 64)}
			entries[1].data, _ = json.Marshal(config)
			hash := sha256.Sum256(entries[1].data)
			entries[1].name = hex.EncodeToString(hash[:]) + ".json"
			var manifest []map[string]any
			_ = json.Unmarshal(entries[2].data, &manifest)
			manifest[0]["Config"] = entries[1].name
			entries[2].data, _ = json.Marshal(manifest)
			return entries
		}},
		{"config-hash", "config filename digest mismatch", func(entries []ociTestEntry) []ociTestEntry {
			entries[1].name = strings.Repeat("0", 64) + ".json"
			var manifest []map[string]any
			_ = json.Unmarshal(entries[2].data, &manifest)
			manifest[0]["Config"] = entries[1].name
			entries[2].data, _ = json.Marshal(manifest)
			return entries
		}},
		{"missing-layer", "lacks referenced entry", func(entries []ociTestEntry) []ociTestEntry {
			return entries[1:]
		}},
		{"multiple-images", "exactly one image", func(entries []ociTestEntry) []ociTestEntry {
			var manifest []map[string]any
			_ = json.Unmarshal(entries[2].data, &manifest)
			manifest = append(manifest, manifest[0])
			entries[2].data, _ = json.Marshal(manifest)
			return entries
		}},
		{"unsafe-reference", "unsafe reference", func(entries []ociTestEntry) []ociTestEntry {
			var manifest []map[string]any
			_ = json.Unmarshal(entries[2].data, &manifest)
			manifest[0]["Layers"] = []string{"../outside.tar"}
			entries[2].data, _ = json.Marshal(manifest)
			return entries
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			archive := dockerTestArchive(t, "invalid.docker.tar", tc.change(base()))
			_, output, code := ociTestScan(t, archive)
			if code == 0 || !strings.Contains(output, tc.want) {
				t.Fatalf("invalid Docker save archive was accepted: code=%d output=%s", code, output)
			}
		})
	}
}
