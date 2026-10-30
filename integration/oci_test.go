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
	"strconv"
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
	if code != 0 || doc.Coverage.Packages != 2 || doc.Coverage.Edges != 3 || doc.Coverage.GraphState != "partial" {
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
	if !issues["dependency_constraint_unverified"] || !issues["os_package_database_not_found"] || issues["declared_dependencies_unresolved"] {
		t.Fatalf("OCI Python coverage did not declare its limits: %#v", doc.Coverage.Issues)
	}
	linked := false
	for _, edge := range doc.Edges {
		linked = linked || edge.Kind == "depends_on" && edge.Condition == "constraint=(>=3)" && edge.Evidence.Pointer == "Requires-Dist/0"
	}
	if !linked {
		t.Fatalf("OCI Python version range was not retained as a conditional edge: %#v", doc.Edges)
	}
	archive := ociTestArchive(t, layout, "python.oci.tar")
	archiveDoc, output, code := ociTestScan(t, archive)
	if code != 0 || archiveDoc.Coverage.Packages != 2 || archiveDoc.Coverage.Edges != 3 {
		t.Fatalf("OCI Python archive scan failed: code=%d output=%s coverage=%#v", code, output, archiveDoc.Coverage)
	}
}

func TestOCIPythonInstalledRequirements(t *testing.T) {
	const site = "usr/local/lib/python3.13/site-packages/"
	metadata := func(name, version, requirements string) []byte {
		return []byte("Metadata-Version: 2.3\nName: " + name + "\nVersion: " + version + "\n" + requirements + "\n")
	}
	layout := ociTestLayout(t)
	manifest := ociTestImage(t, layout, "linux", "amd64", []ociTestLayer{{entries: []ociTestEntry{
		{name: site + "application-1.0.dist-info/METADATA", data: metadata("application", "1.0", strings.Join([]string{
			"Requires-Dist: idna ==3.10",
			"Requires-Dist: typing_extensions",
			"Requires-Dist: charset-normalizer >=3; python_version >= \"3.11\"",
			"Requires-Dist: idna ===3.10",
			"Requires-Dist: requests[socks]",
			"Requires-Dist: extra-only; extra == \"feature\"",
			"Requires-Dist: mismatch ==2.0",
			"Requires-Dist: venv-only",
			"Requires-Dist: unsafe @ https://user:secret@example.invalid/pkg.whl",
		}, "\n"))},
		{name: site + "idna-3.10.dist-info/METADATA", data: metadata("idna", "3.10", "")},
		{name: site + "typing_extensions-4.14.dist-info/METADATA", data: metadata("typing-extensions", "4.14", "")},
		{name: site + "charset_normalizer-3.4.dist-info/METADATA", data: metadata("charset-normalizer", "3.4", "")},
		{name: site + "requests-2.32.dist-info/METADATA", data: metadata("requests", "2.32", "")},
		{name: site + "mismatch-1.0.dist-info/METADATA", data: metadata("mismatch", "1.0", "")},
		{name: "opt/venv/lib/python3.13/site-packages/venv_only-1.0.dist-info/METADATA", data: metadata("venv-only", "1.0", "")},
	}}})
	ociTestIndex(t, layout, manifest)
	doc, output, code := ociTestScan(t, layout)
	if code != 0 || doc.Coverage.Packages != 7 || doc.Coverage.Edges != 12 {
		t.Fatalf("OCI Python requirements scan failed: code=%d output=%s coverage=%#v", code, output, doc.Coverage)
	}
	ids := map[string]string{}
	for _, component := range doc.Components {
		ids[component.Name] = component.ID
	}
	conditions := map[string]bool{}
	for _, edge := range doc.Edges {
		if edge.From == ids["application"] {
			for name, id := range ids {
				if edge.To == id {
					conditions[name+"\x00"+edge.Condition] = true
				}
			}
		}
	}
	for _, key := range []string{
		"idna\x00", "typing-extensions\x00", "requests\x00",
		"idna\x00constraint=(===3.10)",
		"charset-normalizer\x00marker=(python_version >= \"3.11\") && constraint=(>=3)",
	} {
		if !conditions[key] {
			t.Fatalf("OCI Python requirement edge missing %q: %#v", key, doc.Edges)
		}
	}
	if conditions["venv-only\x00"] || conditions["mismatch\x00"] {
		t.Fatalf("cross-environment or wrong-version Python edge was created: %#v", doc.Edges)
	}
	issues := map[string]bool{}
	for _, issue := range doc.Coverage.Issues {
		issues[issue.Code] = true
	}
	for _, code := range []string{"python_requirement_unparsed", "requested_extra_graph_unavailable", "conditional_dependency_unresolved", "unresolved_dependency", "dependency_constraint_unverified", "conditional_graph"} {
		if !issues[code] {
			t.Fatalf("OCI Python issue %s missing: %#v", code, doc.Coverage.Issues)
		}
	}
	if issues["declared_dependencies_unresolved"] {
		t.Fatalf("obsolete unresolved issue remained after linking: %#v", doc.Coverage.Issues)
	}
	serialized, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(serialized, []byte("secret")) || bytes.Contains(serialized, []byte("example.invalid")) {
		t.Fatalf("direct URL requirement leaked into SBOM: %s", serialized)
	}
	for _, format := range []string{"cyclonedx-json", "spdx-json"} {
		out, err := exec.Command(executable, "scan", layout, "--format", format).Output()
		if err != nil {
			t.Fatalf("OCI Python %s export failed: %v", format, err)
		}
		if bytes.Contains(out, []byte("secret")) || bytes.Contains(out, []byte("example.invalid")) {
			t.Fatalf("direct URL requirement leaked into %s export", format)
		}
		if format == "cyclonedx-json" {
			var bom struct {
				Dependencies []struct {
					Ref       string   `json:"ref"`
					DependsOn []string `json:"dependsOn"`
				} `json:"dependencies"`
			}
			if err := json.Unmarshal(out, &bom); err != nil {
				t.Fatal(err)
			}
			found := false
			for _, dependency := range bom.Dependencies {
				if dependency.Ref == ids["application"] {
					found = true
					if len(dependency.DependsOn) != 3 {
						t.Fatalf("conditional Python edges entered CycloneDX: %#v", dependency)
					}
				}
			}
			if !found {
				t.Fatal("CycloneDX omitted definite Python dependencies")
			}
		} else {
			var spdx struct {
				Relationships []json.RawMessage `json:"relationships"`
			}
			if err := json.Unmarshal(out, &spdx); err != nil {
				t.Fatal(err)
			}
			if len(spdx.Relationships) != 10 {
				t.Fatalf("conditional Python edges entered SPDX: got %d relationships, want 10", len(spdx.Relationships))
			}
		}
	}
}

func TestOCIPythonAmbiguousAndWhiteoutedRequirements(t *testing.T) {
	const site = "usr/local/lib/python3.13/site-packages/"
	metadata := func(name, version, requirements string) []byte {
		return []byte("Metadata-Version: 2.3\nName: " + name + "\nVersion: " + version + "\n" + requirements + "\n")
	}
	for _, whiteout := range []bool{false, true} {
		name := "ambiguous"
		if whiteout {
			name = "whiteout"
		}
		t.Run(name, func(t *testing.T) {
			layout := ociTestLayout(t)
			layers := []ociTestLayer{{entries: []ociTestEntry{
				{name: site + "consumer-1.0.dist-info/METADATA", data: metadata("consumer", "1.0", "Requires-Dist: target")},
				{name: site + "target-1.0.dist-info/METADATA", data: metadata("target", "1.0", "")},
				{name: site + "target-2.0.dist-info/METADATA", data: metadata("target", "2.0", "")},
			}}}
			if whiteout {
				layers = append(layers, ociTestLayer{entries: []ociTestEntry{
					{name: site + ".wh.target-1.0.dist-info"},
					{name: site + ".wh.target-2.0.dist-info"},
				}})
			}
			manifest := ociTestImage(t, layout, "linux", "amd64", layers)
			ociTestIndex(t, layout, manifest)
			doc, output, code := ociTestScan(t, layout)
			if code != 0 {
				t.Fatalf("OCI Python candidate scan failed: %s", output)
			}
			linked := 0
			for _, edge := range doc.Edges {
				if edge.Kind == "depends_on" {
					linked++
					if !whiteout && edge.Condition != "candidate=target" {
						t.Fatalf("ambiguous Python dependency became definite: %#v", edge)
					}
				}
			}
			issueCode := "ambiguous_dependency"
			wantPackages, wantEdges, wantLinked := 3, 5, 2
			if whiteout {
				issueCode = "unresolved_dependency"
				wantPackages, wantEdges, wantLinked = 1, 1, 0
			}
			found := false
			for _, issue := range doc.Coverage.Issues {
				found = found || issue.Code == issueCode && issue.Name == "target"
			}
			if doc.Coverage.Packages != wantPackages || doc.Coverage.Edges != wantEdges || linked != wantLinked || !found {
				t.Fatalf("OCI Python candidate resolution incorrect: coverage=%#v edges=%#v", doc.Coverage, doc.Edges)
			}
		})
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

func TestOCINodeInstalledPackageOverlay(t *testing.T) {
	const base = "app/node_modules/"
	manifestJSON := func(name, version, dependencies string) []byte {
		return []byte(`{"name":` + strconv.Quote(name) + `,"version":` + strconv.Quote(version) + `,"dependencies":` + dependencies + `}`)
	}
	layout := ociTestLayout(t)
	manifest := ociTestImage(t, layout, "linux", "amd64", []ociTestLayer{
		{entries: []ociTestEntry{
			{name: base + "alpha/package.json", data: manifestJSON("alpha", "1.0.0", `{"beta":"^2"}`)},
			{name: base + "beta/package.json", data: manifestJSON("beta", "2.0.0", `{}`)},
			{name: base + "@scope/util/package.json", data: manifestJSON("@scope/util", "3.0.0", `{}`)},
			{name: base + "alpha/node_modules/nested/package.json", data: manifestJSON("nested", "0.1.0", `{}`)},
			{name: base + ".pnpm/store/node_modules/stored/package.json", data: manifestJSON("stored", "9.0.0", `{}`)},
			{name: "app/package.json", data: manifestJSON("project", "1.0.0", `{}`)},
		}},
		{entries: []ociTestEntry{
			{name: base + ".wh.alpha"},
			{name: base + ".wh.beta"},
			{name: base + "alpha/package.json", data: manifestJSON("alpha", "1.1.0", `{"missing":"^4"}`)},
			{name: base + "invalid/package.json", data: []byte(`{"name":42,"version":"1.0.0"}`)},
			{name: base + "duplicate/package.json", data: []byte(`{"name":"first","name":"second","version":"1.0.0"}`)},
		}},
	})
	ociTestIndex(t, layout, manifest)
	doc, output, code := ociTestScan(t, layout)
	if code != 0 || doc.Coverage.Packages != 2 || doc.Coverage.Edges != 2 || doc.Coverage.OriginState != "partial" || doc.Coverage.GraphState != "partial" {
		t.Fatalf("OCI Node package overlay failed: code=%d output=%s coverage=%#v", code, output, doc.Coverage)
	}
	versions := map[string]string{}
	for _, component := range doc.Components {
		versions[component.Name] = component.Version
		if component.PURL != "" || component.Evidence[0].Collector != "node-package-json" || !strings.Contains(component.Evidence[0].InputPath, "!/"+base) || !strings.Contains(component.Context, "image=linux/amd64") {
			t.Fatalf("OCI Node identity or evidence incorrect: %#v", component)
		}
	}
	if versions["alpha"] != "1.1.0" || versions["@scope/util"] != "3.0.0" || versions["beta"] != "" || versions["nested"] != "" || versions["stored"] != "" || versions["project"] != "" {
		t.Fatalf("OCI Node overlay kept stale or unrelated package: %#v", versions)
	}
	issues := map[string]bool{}
	for _, issue := range doc.Coverage.Issues {
		issues[issue.Code] = true
	}
	for _, issue := range []string{"unresolved_dependency", "node_installed_metadata_invalid", "os_package_database_not_found", "distribution_source_unavailable"} {
		if !issues[issue] {
			t.Fatalf("OCI Node coverage issue %s missing: %#v", issue, doc.Coverage.Issues)
		}
	}
	if issues["declared_dependencies_unresolved"] {
		t.Fatalf("obsolete Node dependency issue remained after linking: %#v", doc.Coverage.Issues)
	}
	archive := ociTestArchive(t, layout, "node.oci.tar")
	archiveDoc, output, code := ociTestScan(t, archive)
	if code != 0 || archiveDoc.Coverage.Packages != 2 || archiveDoc.Coverage.Edges != 2 {
		t.Fatalf("OCI Node archive scan failed: code=%d output=%s coverage=%#v", code, output, archiveDoc.Coverage)
	}
	for _, format := range []string{"cyclonedx-json", "spdx-json"} {
		data, err := exec.Command(executable, "scan", layout, "--format", format).Output()
		if err != nil || !json.Valid(data) {
			t.Fatalf("OCI Node %s export failed: %v", format, err)
		}
	}
}

func TestOCINodeDuplicateDependencyKeys(t *testing.T) {
	const base = "app/node_modules/"
	layout := ociTestLayout(t)
	manifest := ociTestImage(t, layout, "linux", "amd64", []ociTestLayer{{entries: []ociTestEntry{
		{name: base + "consumer/package.json", data: []byte(`{"name":"consumer","version":"1.0.0","dependencies":{"target":"1.0.0","target":"2.0.0"}}`)},
		{name: base + "consumer/node_modules/target/package.json", data: []byte(`{"name":"target","version":"2.0.0"}`)},
	}}})
	ociTestIndex(t, layout, manifest)
	doc, output, code := ociTestScan(t, layout)
	if code != 0 || doc.Coverage.Packages != 2 || doc.Coverage.Edges != 2 {
		t.Fatalf("OCI Node duplicate dependency scan failed: code=%d output=%s coverage=%#v", code, output, doc.Coverage)
	}
	found := false
	for _, issue := range doc.Coverage.Issues {
		found = found || issue.Code == "node_dependency_manifest_invalid" && issue.Name == "consumer"
	}
	if !found {
		t.Fatalf("duplicate Node dependency keys were not reported: %#v", doc.Coverage.Issues)
	}
}

func TestOCINodeOptionalDependencyOverridesRequired(t *testing.T) {
	const base = "app/node_modules/"
	layout := ociTestLayout(t)
	manifest := ociTestImage(t, layout, "linux", "amd64", []ociTestLayer{{entries: []ociTestEntry{
		{name: base + "consumer/package.json", data: []byte(`{"name":"consumer","version":"1.0.0","dependencies":{"target":"1.0.0"},"optionalDependencies":{"target":"1.0.0"}}`)},
		{name: base + "consumer/node_modules/target/package.json", data: []byte(`{"name":"target","version":"1.0.0"}`)},
	}}})
	ociTestIndex(t, layout, manifest)
	doc, output, code := ociTestScan(t, layout)
	if code != 0 || doc.Coverage.Packages != 2 || doc.Coverage.Edges != 3 {
		t.Fatalf("OCI Node optional override scan failed: code=%d output=%s coverage=%#v", code, output, doc.Coverage)
	}
	linked := 0
	for _, edge := range doc.Edges {
		if edge.Kind == "depends_on" {
			linked++
			if edge.Condition != "optional" || edge.Evidence.Pointer != "/optionalDependencies/target" {
				t.Fatalf("optional Node dependency was exported as required: %#v", edge)
			}
		}
	}
	if linked != 1 {
		t.Fatalf("optional Node dependency generated %d edges", linked)
	}
}

func TestOCINodeInstalledDependencies(t *testing.T) {
	const base = "app/node_modules/"
	manifestJSON := func(name, version, rest string) []byte {
		return []byte(`{"name":` + strconv.Quote(name) + `,"version":` + strconv.Quote(version) + rest + `}`)
	}
	layout := ociTestLayout(t)
	manifest := ociTestImage(t, layout, "linux", "amd64", []ociTestLayer{{entries: []ociTestEntry{
		{name: base + "consumer/package.json", data: manifestJSON("consumer", "1.0.0", `,"dependencies":{"direct":"1.2.3","@scope/util":"1.0.0","hoisted":"^2","alias":"npm:actual@3.0.0","unsafe":"git+https://user:secret@example.invalid/repo.git","wrong":"1.0.0"},"optionalDependencies":{"missing-optional":"^1"},"peerDependencies":{"peer":"1.0.0"}`)},
		{name: base + "consumer/node_modules/direct/package.json", data: manifestJSON("direct", "1.2.3", "")},
		{name: base + "consumer/node_modules/@scope/util/package.json", data: manifestJSON("@scope/util", "1.0.0", "")},
		{name: base + "consumer/node_modules/alias/package.json", data: manifestJSON("actual", "3.0.0", "")},
		{name: base + "consumer/node_modules/unsafe/package.json", data: manifestJSON("unsafe", "1.0.0", "")},
		{name: base + "consumer/node_modules/wrong/package.json", data: manifestJSON("wrong", "2.0.0", "")},
		{name: base + "hoisted/package.json", data: manifestJSON("hoisted", "2.5.0", "")},
		{name: base + "peer/package.json", data: manifestJSON("peer", "1.0.0", "")},
	}}})
	ociTestIndex(t, layout, manifest)
	doc, output, code := ociTestScan(t, layout)
	if code != 0 || doc.Coverage.Packages != 8 || doc.Coverage.Edges != 14 {
		t.Fatalf("OCI Node dependency scan failed: code=%d output=%s coverage=%#v", code, output, doc.Coverage)
	}
	ids := map[string]string{}
	for _, component := range doc.Components {
		ids[component.Name] = component.ID
	}
	conditions := map[string]bool{}
	for _, edge := range doc.Edges {
		if edge.From != ids["consumer"] {
			continue
		}
		for name, id := range ids {
			if edge.To == id {
				conditions[name+"\x00"+edge.Condition] = true
			}
		}
	}
	for _, key := range []string{
		"direct\x00", "@scope/util\x00",
		"hoisted\x00resolution=ancestor_lookup && constraint=(^2)",
		"actual\x00alias=unverified && specifier=unverified",
		"unsafe\x00specifier=unverified",
		"peer\x00peer && resolution=ancestor_lookup",
	} {
		if !conditions[key] {
			t.Fatalf("OCI Node dependency edge %q missing: %#v", key, doc.Edges)
		}
	}
	for _, edge := range doc.Edges {
		if edge.From == ids["consumer"] && edge.To == ids["wrong"] {
			t.Fatalf("wrong-version Node dependency was linked: %#v", edge)
		}
	}
	issues := map[string]bool{}
	for _, issue := range doc.Coverage.Issues {
		issues[issue.Code] = true
	}
	for _, issue := range []string{"node_resolution_unverified", "node_package_alias_unverified", "node_dependency_specifier_unverified", "dependency_constraint_unverified", "conditional_dependency_unresolved", "unresolved_dependency"} {
		if !issues[issue] {
			t.Fatalf("OCI Node coverage issue %s missing: %#v", issue, doc.Coverage.Issues)
		}
	}
	if issues["declared_dependencies_unresolved"] {
		t.Fatalf("obsolete Node dependency issue remained after linking: %#v", doc.Coverage.Issues)
	}
	serialized, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(serialized, []byte("secret")) || bytes.Contains(serialized, []byte("example.invalid")) {
		t.Fatalf("Node dependency URL leaked into SBOM: %s", serialized)
	}
	for _, format := range []string{"cyclonedx-json", "spdx-json"} {
		data, err := exec.Command(executable, "scan", layout, "--format", format).Output()
		if err != nil {
			t.Fatalf("OCI Node %s export failed: %v", format, err)
		}
		if bytes.Contains(data, []byte("secret")) || bytes.Contains(data, []byte("example.invalid")) {
			t.Fatalf("Node dependency URL leaked into %s export", format)
		}
		if format == "cyclonedx-json" {
			var bom struct {
				Dependencies []struct {
					Ref       string   `json:"ref"`
					DependsOn []string `json:"dependsOn"`
				} `json:"dependencies"`
			}
			if err := json.Unmarshal(data, &bom); err != nil {
				t.Fatal(err)
			}
			found := false
			for _, dependency := range bom.Dependencies {
				if dependency.Ref == ids["consumer"] {
					found = true
					if len(dependency.DependsOn) != 2 {
						t.Fatalf("conditional Node edges entered CycloneDX: %#v", dependency)
					}
				}
			}
			if !found {
				t.Fatal("CycloneDX omitted definite Node dependencies")
			}
		} else {
			var spdx struct {
				Relationships []json.RawMessage `json:"relationships"`
			}
			if err := json.Unmarshal(data, &spdx); err != nil {
				t.Fatal(err)
			}
			if len(spdx.Relationships) != 10 {
				t.Fatalf("conditional Node edges entered SPDX: got %d relationships, want 10", len(spdx.Relationships))
			}
		}
	}
}

func TestOCINodeMetadataParentReplacement(t *testing.T) {
	const base = "app/node_modules/"
	layout := ociTestLayout(t)
	manifest := ociTestImage(t, layout, "linux", "amd64", []ociTestLayer{
		{entries: []ociTestEntry{{name: base + "linked/package.json", data: []byte(`{"name":"linked","version":"1.0.0"}`)}}},
		{entries: []ociTestEntry{{name: base + "linked", typeflag: tar.TypeSymlink, linkname: "../store/linked"}}},
	})
	ociTestIndex(t, layout, manifest)
	doc, output, code := ociTestScan(t, layout)
	if code != 0 || doc.Coverage.Packages != 0 || doc.Coverage.GraphState != "unknown" {
		t.Fatalf("OCI Node symlink replacement retained stale metadata: code=%d output=%s coverage=%#v", code, output, doc.Coverage)
	}
}

func TestOCILanguageMetadataUnderSameLayerSymlinkRejected(t *testing.T) {
	for _, tc := range []struct {
		name, parent, metadataPath string
		metadata                   []byte
	}{
		{"node", "app/node_modules/linked", "app/node_modules/linked/package.json", []byte(`{"name":"linked","version":"1.0.0"}`)},
		{"python", "usr/local/lib/python3.13/site-packages/linked-1.0.dist-info", "usr/local/lib/python3.13/site-packages/linked-1.0.dist-info/METADATA", []byte("Metadata-Version: 2.3\nName: linked\nVersion: 1.0\n")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			layout := ociTestLayout(t)
			manifest := ociTestImage(t, layout, "linux", "amd64", []ociTestLayer{{entries: []ociTestEntry{
				{name: tc.parent, typeflag: tar.TypeSymlink, linkname: "../elsewhere"},
				{name: tc.metadataPath, data: tc.metadata},
			}}})
			ociTestIndex(t, layout, manifest)
			_, output, code := ociTestScan(t, layout)
			if code == 0 || !strings.Contains(output, "metadata beneath a non-directory entry") {
				t.Fatalf("OCI same-layer link allowed false package inventory: code=%d output=%s", code, output)
			}
		})
	}
}
