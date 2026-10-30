package integration_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOCIDockerSchema2MediaTypesInLayoutAndArchive(t *testing.T) {
	for _, test := range []struct {
		name      string
		gzip      bool
		layerType string
	}{
		{name: "gzip", gzip: true, layerType: "application/vnd.docker.image.rootfs.diff.tar.gzip"},
		{name: "plain", layerType: "application/vnd.docker.image.rootfs.diff.tar"},
	} {
		t.Run(test.name, func(t *testing.T) {
			layout := ociTestLayout(t)
			original := ociTestImage(t, layout, "linux", "amd64", []ociTestLayer{{gzip: test.gzip, entries: []ociTestEntry{{name: "var/lib/dpkg/status", data: ociTestStatus(t, "dpkg-basic")}}}})
			blob := filepath.Join(layout, "blobs", "sha256", strings.TrimPrefix(original.Digest, "sha256:"))
			data, err := os.ReadFile(blob)
			if err != nil {
				t.Fatal(err)
			}
			var manifest struct {
				SchemaVersion int                 `json:"schemaVersion"`
				MediaType     string              `json:"mediaType"`
				Config        ociTestDescriptor   `json:"config"`
				Layers        []ociTestDescriptor `json:"layers"`
			}
			if err := json.Unmarshal(data, &manifest); err != nil || len(manifest.Layers) != 1 {
				t.Fatalf("test manifest invalid: %v", err)
			}
			manifest.MediaType = "application/vnd.docker.distribution.manifest.v2+json"
			manifest.Config.MediaType = "application/vnd.docker.container.image.v1+json"
			manifest.Layers[0].MediaType = test.layerType
			data, err = json.Marshal(manifest)
			if err != nil {
				t.Fatal(err)
			}
			dockerManifest := ociTestBlob(t, layout, manifest.MediaType, data)
			nested, err := json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": "application/vnd.docker.distribution.manifest.list.v2+json", "manifests": []ociTestDescriptor{dockerManifest}})
			if err != nil {
				t.Fatal(err)
			}
			dockerIndex := ociTestBlob(t, layout, "application/vnd.docker.distribution.manifest.list.v2+json", nested)
			ociTestIndex(t, layout, dockerIndex)
			for _, target := range []string{layout, ociTestArchive(t, layout, "image.docker.tar")} {
				doc, output, code := ociTestScan(t, target)
				if code != 0 || doc.Coverage.Manager != "oci" || doc.Coverage.Packages != 4 || len(doc.Coverage.Platforms) != 1 || doc.Coverage.Platforms[0] != "linux/amd64" {
					t.Fatalf("Docker media type scan failed for %s: code=%d output=%s coverage=%#v", target, code, output, doc.Coverage)
				}
			}
		})
	}
}

func TestOCIDockerSaveHybridSparseIndexUsesSavedManifest(t *testing.T) {
	layout := ociTestLayout(t)
	original := ociTestImage(t, layout, "linux", "amd64", []ociTestLayer{{gzip: true, entries: []ociTestEntry{{name: "var/lib/dpkg/status", data: ociTestStatus(t, "dpkg-basic")}}}})
	data, err := os.ReadFile(filepath.Join(layout, "blobs", "sha256", strings.TrimPrefix(original.Digest, "sha256:")))
	if err != nil {
		t.Fatal(err)
	}
	var image struct {
		Config ociTestDescriptor   `json:"config"`
		Layers []ociTestDescriptor `json:"layers"`
	}
	if err := json.Unmarshal(data, &image); err != nil || len(image.Layers) != 1 {
		t.Fatalf("test image manifest invalid: %v", err)
	}
	configPath := "blobs/sha256/" + strings.TrimPrefix(image.Config.Digest, "sha256:")
	layerPath := "blobs/sha256/" + strings.TrimPrefix(image.Layers[0].Digest, "sha256:")
	saveManifest, err := json.Marshal([]map[string]any{{"Config": configPath, "Layers": []string{layerPath}, "RepoTags": []string{"test:latest"}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(layout, "manifest.json"), saveManifest, 0o644); err != nil {
		t.Fatal(err)
	}
	// A modern docker save may retain a multi-platform index whose other
	// manifests were not included in the local archive.
	ociTestIndex(t, layout, ociTestDescriptor{MediaType: "application/vnd.oci.image.index.v1+json", Digest: "sha256:" + strings.Repeat("a", 64), Size: 123})
	archive := ociTestArchive(t, layout, "hybrid.docker.tar")
	doc, output, code := ociTestScan(t, archive)
	if code != 0 || doc.Coverage.Packages != 4 || doc.Coverage.Manager != "oci" || doc.Source != archive {
		t.Fatalf("hybrid Docker save failed: code=%d output=%s coverage=%#v", code, output, doc.Coverage)
	}
	blob := filepath.Join(layout, filepath.FromSlash(layerPath))
	data, err = os.ReadFile(blob)
	if err != nil {
		t.Fatal(err)
	}
	data[0] ^= 1
	if err := os.WriteFile(blob, data, 0o644); err != nil {
		t.Fatal(err)
	}
	corrupt := ociTestArchive(t, layout, "corrupt.docker.tar")
	if _, output, code := ociTestScan(t, corrupt); code != 1 || !strings.Contains(output, "digest mismatch") {
		t.Fatalf("content-addressed layer digest mismatch accepted: code=%d output=%s", code, output)
	}
}
