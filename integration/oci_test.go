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

	"ravel/internal/model"
)

type ociTestDescriptor struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
}

type ociTestEntry struct {
	name     string
	data     []byte
	typeflag byte
	linkname string
}

type ociTestLayer struct {
	entries []ociTestEntry
	gzip    bool
	diffID  string
}

func ociTestLayout(t *testing.T) string {
	t.Helper()
	layout := t.TempDir()
	if err := os.WriteFile(filepath.Join(layout, "oci-layout"), []byte(`{"imageLayoutVersion":"1.0.0"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	return layout
}

func ociTestBlob(t *testing.T, layout, mediaType string, data []byte) ociTestDescriptor {
	t.Helper()
	hash := sha256.Sum256(data)
	digest := hex.EncodeToString(hash[:])
	dir := filepath.Join(layout, "blobs", "sha256")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, digest), data, 0o644); err != nil {
		t.Fatal(err)
	}
	return ociTestDescriptor{MediaType: mediaType, Digest: "sha256:" + digest, Size: int64(len(data))}
}

func ociTestTar(t *testing.T, entries []ociTestEntry) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	for _, entry := range entries {
		typ := entry.typeflag
		if typ == 0 {
			typ = tar.TypeReg
		}
		data := entry.data
		if typ != tar.TypeReg {
			data = nil
		}
		header := &tar.Header{Name: entry.name, Typeflag: typ, Mode: 0o644, Size: int64(len(data)), Linkname: entry.linkname}
		if err := writer.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if len(data) > 0 {
			if _, err := writer.Write(data); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func ociTestImage(t *testing.T, layout, osName, arch string, layers []ociTestLayer) ociTestDescriptor {
	t.Helper()
	var layerDescriptors []ociTestDescriptor
	var diffIDs []string
	for _, layer := range layers {
		plain := ociTestTar(t, layer.entries)
		hash := sha256.Sum256(plain)
		diffID := "sha256:" + hex.EncodeToString(hash[:])
		if layer.diffID != "" {
			diffID = layer.diffID
		}
		data := plain
		media := "application/vnd.oci.image.layer.v1.tar"
		if layer.gzip {
			var compressed bytes.Buffer
			writer := gzip.NewWriter(&compressed)
			if _, err := writer.Write(plain); err != nil {
				t.Fatal(err)
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			data = compressed.Bytes()
			media += "+gzip"
		}
		layerDescriptors = append(layerDescriptors, ociTestBlob(t, layout, media, data))
		diffIDs = append(diffIDs, diffID)
	}
	configData, err := json.Marshal(map[string]any{"os": osName, "architecture": arch, "rootfs": map[string]any{"type": "layers", "diff_ids": diffIDs}})
	if err != nil {
		t.Fatal(err)
	}
	config := ociTestBlob(t, layout, "application/vnd.oci.image.config.v1+json", configData)
	manifestData, err := json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json", "config": config, "layers": layerDescriptors})
	if err != nil {
		t.Fatal(err)
	}
	return ociTestBlob(t, layout, "application/vnd.oci.image.manifest.v1+json", manifestData)
}

func ociTestIndex(t *testing.T, layout string, manifests ...ociTestDescriptor) {
	t.Helper()
	data, err := json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": manifests})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(layout, "index.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func ociTestStatus(t *testing.T, fixture string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "testdata", "fixtures", fixture, "var", "lib", "dpkg", "status"))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func ociTestAPKInstalled(t *testing.T, fixture string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "testdata", "fixtures", fixture, "lib", "apk", "db", "installed"))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func ociTestScan(t *testing.T, layout string, args ...string) (model.Document, string, int) {
	t.Helper()
	result := filepath.Join(t.TempDir(), "image.json")
	command := append([]string{"scan", layout, "--format", "ravel-json", "--output", result}, args...)
	output, err := exec.Command(executable, command...).CombinedOutput()
	if err != nil {
		if exit, ok := err.(*exec.ExitError); ok {
			return model.Document{}, string(output), exit.ExitCode()
		}
		t.Fatal(err)
	}
	data, err := os.ReadFile(result)
	if err != nil {
		t.Fatal(err)
	}
	var doc model.Document
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	return doc, string(output), 0
}

func TestOCILayoutLayerOverlayAndEvidence(t *testing.T) {
	layout := ociTestLayout(t)
	base := ociTestStatus(t, "dpkg-basic")
	updated := ociTestStatus(t, "dpkg-versioned-provide")
	layer1 := ociTestLayer{gzip: true, entries: []ociTestEntry{{name: "var/lib/dpkg/status", data: base}}}
	// A whiteout affects a lower layer even when it appears after a new file.
	layer2 := ociTestLayer{entries: []ociTestEntry{{name: "var/lib/dpkg/status", data: updated}, {name: "var/lib/dpkg/.wh.status"}}}
	manifest := ociTestImage(t, layout, "linux", "amd64", []ociTestLayer{layer1, layer2})
	ociTestIndex(t, layout, manifest)
	doc, output, code := ociTestScan(t, layout)
	if code != 0 {
		t.Fatalf("OCI scan failed, code=%d output=%s", code, output)
	}
	if doc.Coverage.Manager != "oci" || doc.Coverage.Packages != 2 || doc.Coverage.Edges != 3 || doc.Coverage.GraphState != "partial" || len(doc.Sources) != 6 || len(doc.Coverage.Platforms) != 1 || doc.Coverage.Platforms[0] != "linux/amd64" {
		t.Fatalf("OCI coverage incorrect: %#v", doc)
	}
	for _, component := range doc.Components {
		if component.Name == "base-files" || component.PURL != "" || !strings.Contains(component.Context, "image=linux/amd64") || !strings.HasPrefix(component.Evidence[0].InputPath, "oci:sha256:") {
			t.Fatalf("OCI layer evidence or identity incorrect: %#v", component)
		}
	}
	if output, err := exec.Command(executable, "scan", layout, "--output", filepath.Join(layout, "index.json")).CombinedOutput(); err == nil || !strings.Contains(string(output), "cannot overwrite") {
		t.Fatalf("OCI index overwrite accepted: %v: %s", err, output)
	}
}

func TestOCILayoutWhiteoutsRemovePackageDatabase(t *testing.T) {
	for _, marker := range []string{"var/lib/dpkg/.wh.status", "var/lib/dpkg/.wh..wh..opq", "var/lib/.wh.dpkg"} {
		t.Run(strings.ReplaceAll(marker, "/", "_"), func(t *testing.T) {
			layout := ociTestLayout(t)
			manifest := ociTestImage(t, layout, "linux", "amd64", []ociTestLayer{
				{entries: []ociTestEntry{{name: "var/lib/dpkg/status", data: ociTestStatus(t, "dpkg-basic")}}},
				{entries: []ociTestEntry{{name: marker}}},
			})
			ociTestIndex(t, layout, manifest)
			doc, output, code := ociTestScan(t, layout)
			if code != 0 || len(doc.Components) != 0 || doc.Coverage.GraphState != "unknown" {
				t.Fatalf("whiteout did not remove lower status: code=%d output=%s doc=%#v", code, output, doc)
			}
		})
	}
}

func TestOCILayoutPlatformSelection(t *testing.T) {
	layout := ociTestLayout(t)
	amd := ociTestImage(t, layout, "linux", "amd64", []ociTestLayer{{entries: []ociTestEntry{{name: "var/lib/dpkg/status", data: ociTestStatus(t, "dpkg-basic")}}}})
	armStatus := []byte("Package: arm64-only\nStatus: install ok installed\nArchitecture: arm64\nVersion: 1.0\n")
	arm := ociTestImage(t, layout, "linux", "arm64", []ociTestLayer{{entries: []ociTestEntry{{name: "var/lib/dpkg/status", data: armStatus}}}})
	ociTestIndex(t, layout, amd, arm)
	if _, output, code := ociTestScan(t, layout); code != 1 || !strings.Contains(output, "select --platform") {
		t.Fatalf("ambiguous multi-platform image was accepted: code=%d output=%s", code, output)
	}
	doc, output, code := ociTestScan(t, layout, "--platform", "linux/arm64")
	if code != 0 || len(doc.Components) != 1 || doc.Components[0].Name != "arm64-only" {
		t.Fatalf("OCI platform selection failed: code=%d output=%s doc=%#v", code, output, doc)
	}
	if _, output, code := ociTestScan(t, layout, "--platform", "linux/s390x"); code != 1 || !strings.Contains(output, "no manifest for platform") {
		t.Fatalf("missing OCI platform was accepted: code=%d output=%s", code, output)
	}
}

func TestOCILayoutRejectsCorruptLayers(t *testing.T) {
	t.Run("diff-id", func(t *testing.T) {
		layout := ociTestLayout(t)
		manifest := ociTestImage(t, layout, "linux", "amd64", []ociTestLayer{{diffID: "sha256:" + strings.Repeat("0", 64), entries: []ociTestEntry{{name: "var/lib/dpkg/status", data: ociTestStatus(t, "dpkg-basic")}}}})
		ociTestIndex(t, layout, manifest)
		if _, output, code := ociTestScan(t, layout); code != 1 || !strings.Contains(output, "diff ID mismatch") {
			t.Fatalf("wrong OCI diff ID accepted: code=%d output=%s", code, output)
		}
	})
	t.Run("manifest-digest", func(t *testing.T) {
		layout := ociTestLayout(t)
		manifest := ociTestImage(t, layout, "linux", "amd64", []ociTestLayer{{entries: []ociTestEntry{{name: "var/lib/dpkg/status", data: ociTestStatus(t, "dpkg-basic")}}}})
		ociTestIndex(t, layout, manifest)
		blob := filepath.Join(layout, "blobs", "sha256", strings.TrimPrefix(manifest.Digest, "sha256:"))
		data, err := os.ReadFile(blob)
		if err != nil {
			t.Fatal(err)
		}
		data[len(data)-1] ^= 1
		if err := os.WriteFile(blob, data, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, output, code := ociTestScan(t, layout); code != 1 || !strings.Contains(output, "digest mismatch") {
			t.Fatalf("corrupt OCI manifest accepted: code=%d output=%s", code, output)
		}
	})
	t.Run("whiteout-payload", func(t *testing.T) {
		layout := ociTestLayout(t)
		manifest := ociTestImage(t, layout, "linux", "amd64", []ociTestLayer{{entries: []ociTestEntry{{name: "var/lib/dpkg/.wh.status", data: []byte("unexpected")}}}})
		ociTestIndex(t, layout, manifest)
		if _, output, code := ociTestScan(t, layout); code != 1 || !strings.Contains(output, "whiteout") {
			t.Fatalf("invalid OCI whiteout accepted: code=%d output=%s", code, output)
		}
	})
	for name, entry := range map[string]ociTestEntry{
		"traversal": {name: "../var/lib/dpkg/status", data: ociTestStatus(t, "dpkg-basic")},
		"symlink":   {name: "var/lib/dpkg", typeflag: tar.TypeSymlink, linkname: "/outside"},
	} {
		t.Run(name, func(t *testing.T) {
			layout := ociTestLayout(t)
			manifest := ociTestImage(t, layout, "linux", "amd64", []ociTestLayer{{entries: []ociTestEntry{entry}}})
			ociTestIndex(t, layout, manifest)
			if _, output, code := ociTestScan(t, layout); code != 1 || !strings.Contains(output, "OCI layer") {
				t.Fatalf("unsafe OCI layer accepted: code=%d output=%s", code, output)
			}
		})
	}
}

func TestOCINestedIndexAndRecursiveScan(t *testing.T) {
	root := t.TempDir()
	layout := filepath.Join(root, "image")
	if err := os.Mkdir(layout, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(layout, "oci-layout"), []byte(`{"imageLayoutVersion":"1.0.0"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	manifest := ociTestImage(t, layout, "linux", "amd64", []ociTestLayer{{entries: []ociTestEntry{{name: "var/lib/dpkg/status", data: ociTestStatus(t, "dpkg-basic")}}}})
	nestedData, err := json.Marshal(map[string]any{"schemaVersion": 2, "manifests": []ociTestDescriptor{manifest}})
	if err != nil {
		t.Fatal(err)
	}
	nested := ociTestBlob(t, layout, "application/vnd.oci.image.index.v1+json", nestedData)
	ociTestIndex(t, layout, nested)
	doc, output, code := ociTestScan(t, layout)
	if code != 0 || doc.Coverage.Packages == 0 {
		t.Fatalf("nested OCI index scan failed: code=%d output=%s", code, output)
	}
	nestedPath := filepath.Join(layout, "blobs", "sha256", strings.TrimPrefix(nested.Digest, "sha256:"))
	found := false
	for _, source := range doc.Sources {
		found = found || source == nestedPath
	}
	if !found {
		t.Fatalf("nested index missing from source protection: %v", doc.Sources)
	}
	if output, err := exec.Command(executable, "scan", layout, "--output", nestedPath).CombinedOutput(); err == nil || !strings.Contains(string(output), "cannot overwrite") {
		t.Fatalf("nested OCI index overwrite accepted: %v: %s", err, output)
	}
	result := filepath.Join(t.TempDir(), "all.json")
	outputBytes, err := exec.Command(executable, "scan", root, "--all", "--recursive", "--format", "ravel-json", "--output", result).CombinedOutput()
	if err != nil {
		t.Fatalf("recursive OCI scan failed: %v: %s", err, outputBytes)
	}
	data, err := os.ReadFile(result)
	if err != nil {
		t.Fatal(err)
	}
	var recursive model.Document
	if err := json.Unmarshal(data, &recursive); err != nil {
		t.Fatal(err)
	}
	if recursive.Coverage.Packages != doc.Coverage.Packages || recursive.Coverage.Manager != "oci" {
		t.Fatalf("recursive OCI scan changed package inventory: %#v", recursive.Coverage)
	}
}

func ociTestArchive(t *testing.T, layout, name string) string {
	t.Helper()
	archive := filepath.Join(t.TempDir(), name)
	file, err := os.Create(archive)
	if err != nil {
		t.Fatal(err)
	}
	writer := tar.NewWriter(file)
	err = filepath.WalkDir(layout, func(filePath string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil || entry.IsDir() {
			return walkErr
		}
		relative, err := filepath.Rel(layout, filePath)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(filePath)
		if err != nil {
			return err
		}
		if err := writer.WriteHeader(&tar.Header{Name: filepath.ToSlash(relative), Mode: 0o644, Size: int64(len(data))}); err != nil {
			return err
		}
		_, err = writer.Write(data)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return archive
}

func TestOCIArchiveScanAndSourceProtection(t *testing.T) {
	layout := ociTestLayout(t)
	manifest := ociTestImage(t, layout, "linux", "amd64", []ociTestLayer{{gzip: true, entries: []ociTestEntry{{name: "var/lib/dpkg/status", data: ociTestStatus(t, "dpkg-basic")}}}})
	ociTestIndex(t, layout, manifest)
	archive := ociTestArchive(t, layout, "image.oci.tar")
	doc, output, code := ociTestScan(t, archive)
	if code != 0 || doc.Coverage.Packages != 4 || doc.Source != archive || len(doc.Sources) != 1 || doc.Sources[0] != archive {
		t.Fatalf("OCI archive scan failed: code=%d output=%s doc=%#v", code, output, doc)
	}
	if output, err := exec.Command(executable, "scan", archive, "--output", archive).CombinedOutput(); err == nil || !strings.Contains(string(output), "cannot overwrite") {
		t.Fatalf("OCI archive overwrite accepted: %v: %s", err, output)
	}
	plainName := filepath.Join(t.TempDir(), "image.tar")
	data, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(plainName, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, output, code := ociTestScan(t, plainName, "--manager", "oci"); code != 0 {
		t.Fatalf("explicit OCI archive manager failed: code=%d output=%s", code, output)
	}
}

func TestOCIArchiveRejectsUnsafePath(t *testing.T) {
	archive := filepath.Join(t.TempDir(), "bad.oci.tar")
	file, err := os.Create(archive)
	if err != nil {
		t.Fatal(err)
	}
	writer := tar.NewWriter(file)
	if err := writer.WriteHeader(&tar.Header{Name: "../index.json", Mode: 0o644, Size: 0}); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, output, code := ociTestScan(t, archive); code != 1 || !strings.Contains(output, "unsafe OCI layer path") {
		t.Fatalf("unsafe OCI archive path accepted: code=%d output=%s", code, output)
	}
}

func TestOCIApkDatabaseOverlayAndWhiteout(t *testing.T) {
	layout := ociTestLayout(t)
	manifest := ociTestImage(t, layout, "linux", "amd64", []ociTestLayer{
		{gzip: true, entries: []ociTestEntry{{name: "lib/apk/db/installed", data: ociTestAPKInstalled(t, "apk-basic")}}},
		{entries: []ociTestEntry{{name: "lib/apk/db/installed", data: ociTestAPKInstalled(t, "apk-versioned")}, {name: "lib/apk/db/.wh.installed"}}},
	})
	ociTestIndex(t, layout, manifest)
	doc, output, code := ociTestScan(t, layout)
	if code != 0 || doc.Coverage.Packages != 2 || doc.Coverage.Edges != 3 || doc.Coverage.GraphState != "partial" {
		t.Fatalf("OCI APK overlay failed: code=%d output=%s coverage=%#v", code, output, doc.Coverage)
	}
	for _, component := range doc.Components {
		if !strings.Contains(component.Evidence[0].InputPath, "!/lib/apk/db/installed") || component.Evidence[0].Collector != "apk-installed" {
			t.Fatalf("OCI APK evidence incorrect: %#v", component)
		}
	}
	removed := ociTestLayout(t)
	removedManifest := ociTestImage(t, removed, "linux", "amd64", []ociTestLayer{
		{entries: []ociTestEntry{{name: "lib/apk/db/installed", data: ociTestAPKInstalled(t, "apk-basic")}}},
		{entries: []ociTestEntry{{name: "lib/apk/db/.wh.installed"}}},
	})
	ociTestIndex(t, removed, removedManifest)
	removedDoc, output, code := ociTestScan(t, removed)
	if code != 0 || removedDoc.Coverage.Packages != 0 || removedDoc.Coverage.GraphState != "unknown" {
		t.Fatalf("OCI APK whiteout failed: code=%d output=%s coverage=%#v", code, output, removedDoc.Coverage)
	}
}

func TestOCIMixedOSDatabases(t *testing.T) {
	layout := ociTestLayout(t)
	manifest := ociTestImage(t, layout, "linux", "amd64", []ociTestLayer{{entries: []ociTestEntry{
		{name: "var/lib/dpkg/status", data: ociTestStatus(t, "dpkg-basic")},
		{name: "lib/apk/db/installed", data: ociTestAPKInstalled(t, "apk-basic")},
	}}})
	ociTestIndex(t, layout, manifest)
	doc, output, code := ociTestScan(t, layout)
	if code != 0 || doc.Coverage.Packages != 7 || doc.Coverage.Edges != 13 || doc.Coverage.Manager != "oci" {
		t.Fatalf("mixed OCI OS databases failed: code=%d output=%s coverage=%#v", code, output, doc.Coverage)
	}
}

func TestOCIPythonInstalledMetadataOverlay(t *testing.T) {
	const site = "usr/local/lib/python3.13/site-packages/"
	metadata := func(name, version, requires string) []byte {
		return []byte("Metadata-Version: 2.3\nName: " + name + "\nVersion: " + version + "\n" + requires + "\n")
	}
	layout := ociTestLayout(t)
	manifest := ociTestImage(t, layout, "linux", "amd64", []ociTestLayer{
		{entries: []ociTestEntry{
			{name: site + "demo_pkg-1.2.0.dist-info/METADATA", data: metadata("demo-pkg", "1.2.0", "Requires-Dist: idna >=3")},
			{name: site + "idna-3.10.dist-info/METADATA", data: metadata("idna", "3.10", "")},
		}},
		{entries: []ociTestEntry{
			{name: site + "demo_pkg-2.0.0.dist-info/METADATA", data: metadata("demo-pkg", "2.0.0", "Requires-Dist: idna >=3")},
			{name: site + ".wh.demo_pkg-1.2.0.dist-info"},
		}},
	})
	ociTestIndex(t, layout, manifest)
	doc, output, code := ociTestScan(t, layout)
	if code != 0 || doc.Coverage.Packages != 2 || doc.Coverage.Edges != 2 || doc.Coverage.GraphState != "partial" {
		t.Fatalf("OCI Python metadata overlay failed: code=%d output=%s coverage=%#v", code, output, doc.Coverage)
	}
	versions := map[string]string{}
	for _, component := range doc.Components {
		versions[component.Name] = component.Version
		if component.Evidence[0].Collector != "python-dist-info" || !strings.Contains(component.Evidence[0].InputPath, "!/"+site) {
			t.Fatalf("OCI Python evidence incorrect: %#v", component)
		}
	}
	if versions["demo-pkg"] != "2.0.0" || versions["idna"] != "3.10" {
		t.Fatalf("OCI Python whiteout kept a stale distribution: %#v", versions)
	}
	issues := map[string]bool{}
	for _, issue := range doc.Coverage.Issues {
		issues[issue.Code] = true
	}
	if !issues["declared_dependencies_unresolved"] || !issues["os_package_database_not_found"] {
		t.Fatalf("OCI Python coverage did not declare its limits: %#v", doc.Coverage.Issues)
	}
	archive := ociTestArchive(t, layout, "python.oci.tar")
	archiveDoc, output, code := ociTestScan(t, archive)
	if code != 0 || archiveDoc.Coverage.Packages != 2 {
		t.Fatalf("OCI Python archive scan failed: code=%d output=%s coverage=%#v", code, output, archiveDoc.Coverage)
	}
}

func TestOCIPythonOpaqueDirectoryAndInvalidMetadata(t *testing.T) {
	const site = "usr/local/lib/python3.13/site-packages/"
	layout := ociTestLayout(t)
	manifest := ociTestImage(t, layout, "linux", "amd64", []ociTestLayer{
		{entries: []ociTestEntry{{name: site + "old-1.0.dist-info/METADATA", data: []byte("Metadata-Version: 2.3\nName: old\nVersion: 1.0\n")}}},
		{entries: []ociTestEntry{
			{name: site + ".wh..wh..opq"},
			{name: site + "new-2.0.dist-info/METADATA", data: []byte("Metadata-Version: 2.3\nName: new\nVersion: 2.0\n")},
			{name: site + "wrong-1.0.dist-info/METADATA", data: []byte("Metadata-Version: 2.3\nName: other\nVersion: 1.0\n")},
		}},
	})
	ociTestIndex(t, layout, manifest)
	doc, output, code := ociTestScan(t, layout)
	if code != 0 || doc.Coverage.Packages != 1 || doc.Components[0].Name != "new" {
		t.Fatalf("OCI Python opaque directory failed: code=%d output=%s coverage=%#v", code, output, doc.Coverage)
	}
	foundInvalid := false
	for _, issue := range doc.Coverage.Issues {
		foundInvalid = foundInvalid || issue.Code == "python_installed_metadata_invalid"
	}
	if !foundInvalid || doc.Coverage.OriginState != "partial" {
		t.Fatalf("invalid OCI Python metadata was not reported: %#v", doc.Coverage)
	}
}
