package integration_test

import (
	"archive/tar"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func ociGoBinaryFixture(t *testing.T) ([]byte, string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/semver-tool\n\ngo 1.27\n\nrequire golang.org/x/mod v0.42.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\nimport (\"fmt\"; \"golang.org/x/mod/semver\")\nfunc main() { fmt.Println(semver.IsValid(\"v1.2.3\")) }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(dir, "semver-tool")
	cmd := exec.Command("go", "build", "-mod=mod", "-buildvcs=false", "-o", binary, ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0", "GOPROXY=off", "GOSUMDB=off", "GOWORK=off")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build Linux Go fixture: %v: %s", err, output)
	}
	info, err := buildinfo.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	if len(info.Deps) != 1 || info.Deps[0].Path != "golang.org/x/mod" {
		t.Fatalf("fixture build info unexpected: %#v", info)
	}
	data, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	return data, info.GoVersion
}

func TestOCIGoBinaryEmbeddedModulesAndEvidence(t *testing.T) {
	binary, goVersion := ociGoBinaryFixture(t)
	layout := ociTestLayout(t)
	image := ociTestImage(t, layout, "linux", "amd64", []ociTestLayer{{entries: []ociTestEntry{
		{name: "usr/local/bin/semver-tool", data: binary, mode: 0o755},
	}}})
	ociTestIndex(t, layout, image)
	doc, output, code := ociTestScan(t, layout)
	if code != 0 || doc.Coverage.Manager != "oci" || doc.Coverage.Packages != 3 || doc.Coverage.Edges != 3 || doc.Coverage.GraphState != "partial" || doc.Coverage.OriginState != "partial" {
		t.Fatalf("OCI Go inventory incorrect: code=%d output=%s coverage=%#v", code, output, doc.Coverage)
	}
	hash := sha256.Sum256(binary)
	digest := hex.EncodeToString(hash[:])
	components := map[string]bool{}
	ids := map[string]bool{}
	for _, component := range doc.Components {
		components[component.Name+"@"+component.Version] = true
		if ids[component.ID] || !strings.Contains(component.Context, "binary=/usr/local/bin/semver-tool") && component.Kind != "application" || !strings.Contains(component.Context, "image=linux/amd64") {
			t.Fatalf("Go component identity or context incorrect: %#v", component)
		}
		ids[component.ID] = true
		if len(component.Evidence) != 1 || !strings.HasPrefix(component.Evidence[0].InputPath, "oci:sha256:") || !strings.HasSuffix(component.Evidence[0].InputPath, "!/usr/local/bin/semver-tool") || component.Evidence[0].InputDigest != "sha256:"+digest {
			t.Fatalf("Go binary evidence incorrect: %#v", component)
		}
		if component.Name == "semver-tool" && (component.Kind != "application" || len(component.Hashes) != 1 || component.Hashes[0].Content != digest || !strings.Contains(component.Context, "main_module=example.com/semver-tool")) {
			t.Fatalf("Go executable metadata incorrect: %#v", component)
		}
		if component.Name == "golang.org/x/mod" && component.PURL != "pkg:golang/golang.org/x/mod@v0.42.0" {
			t.Fatalf("Go module PURL incorrect: %#v", component)
		}
	}
	for _, name := range []string{"semver-tool@", "stdlib@" + goVersion, "golang.org/x/mod@v0.42.0"} {
		if !components[name] {
			t.Fatalf("missing %s: %#v", name, doc.Components)
		}
	}
	issues := map[string]bool{}
	for _, issue := range doc.Coverage.Issues {
		issues[issue.Code] = true
	}
	if !issues["go_binary_graph_unavailable"] || !issues["go_binary_origin_unavailable"] {
		t.Fatalf("Go build info limits not reported: %#v", doc.Coverage.Issues)
	}
}

func TestOCIGoBinaryLargerThanMemoryLimit(t *testing.T) {
	binary, goVersion := ociGoBinaryFixture(t)
	const paddedSize = int64(64<<20) + 1
	layout := ociTestLayout(t)
	layerPath := filepath.Join(layout, "large-layer.tar")
	file, err := os.Create(layerPath)
	if err != nil {
		t.Fatal(err)
	}
	layerHash := sha256.New()
	writer := tar.NewWriter(io.MultiWriter(file, layerHash))
	if err := writer.WriteHeader(&tar.Header{Name: "usr/bin/large-go", Typeflag: tar.TypeReg, Mode: 0o755, Size: paddedSize}); err != nil {
		t.Fatal(err)
	}
	binaryHash := sha256.New()
	payload := io.MultiWriter(writer, binaryHash)
	if _, err := payload.Write(binary); err != nil {
		t.Fatal(err)
	}
	zeros := make([]byte, 32<<10)
	for remaining := paddedSize - int64(len(binary)); remaining > 0; {
		chunk := int64(len(zeros))
		if remaining < chunk {
			chunk = remaining
		}
		if _, err := payload.Write(zeros[:int(chunk)]); err != nil {
			t.Fatal(err)
		}
		remaining -= chunk
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	layerDigest := hex.EncodeToString(layerHash.Sum(nil))
	blobDir := filepath.Join(layout, "blobs", "sha256")
	if err := os.MkdirAll(blobDir, 0o755); err != nil {
		t.Fatal(err)
	}
	blobPath := filepath.Join(blobDir, layerDigest)
	if err := os.Rename(layerPath, blobPath); err != nil {
		t.Fatal(err)
	}
	stat, err := os.Stat(blobPath)
	if err != nil {
		t.Fatal(err)
	}
	configData, err := json.Marshal(map[string]any{"os": "linux", "architecture": "amd64", "rootfs": map[string]any{"type": "layers", "diff_ids": []string{"sha256:" + layerDigest}}})
	if err != nil {
		t.Fatal(err)
	}
	config := ociTestBlob(t, layout, "application/vnd.oci.image.config.v1+json", configData)
	manifestData, err := json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json", "config": config, "layers": []ociTestDescriptor{{MediaType: "application/vnd.oci.image.layer.v1.tar", Digest: "sha256:" + layerDigest, Size: stat.Size()}}})
	if err != nil {
		t.Fatal(err)
	}
	image := ociTestBlob(t, layout, "application/vnd.oci.image.manifest.v1+json", manifestData)
	ociTestIndex(t, layout, image)
	doc, output, code := ociTestScan(t, layout)
	if code != 0 || len(doc.Components) != 3 || doc.Coverage.Packages != 3 {
		t.Fatalf("large Go binary was not inventoried: code=%d output=%s coverage=%#v", code, output, doc.Coverage)
	}
	wantDigest := "sha256:" + hex.EncodeToString(binaryHash.Sum(nil))
	found := map[string]bool{}
	for _, component := range doc.Components {
		found[component.Name+"@"+component.Version] = true
		if len(component.Evidence) != 1 || component.Evidence[0].InputDigest != wantDigest || !strings.HasSuffix(component.Evidence[0].InputPath, "!/usr/bin/large-go") {
			t.Fatalf("large Go binary evidence incorrect: %#v", component)
		}
	}
	for _, key := range []string{"large-go@", "stdlib@" + goVersion, "golang.org/x/mod@v0.42.0"} {
		if !found[key] {
			t.Fatalf("missing large Go component %s", key)
		}
	}
	for _, issue := range doc.Coverage.Issues {
		if issue.Code == "go_binary_oversized" || issue.Code == "go_binary_invalid" {
			t.Fatalf("large Go binary was rejected: %#v", issue)
		}
	}
}

func TestOCIGoBinaryFinalLayerOverlay(t *testing.T) {
	binary, _ := ociGoBinaryFixture(t)
	for _, test := range []struct {
		name    string
		entries []ociTestEntry
		want    int
	}{
		{name: "whiteout", entries: []ociTestEntry{{name: "usr/local/bin/.wh.semver-tool"}}, want: 0},
		{name: "script_replacement", entries: []ociTestEntry{{name: "usr/local/bin/semver-tool", data: []byte("#!/bin/sh\nexit 0\n"), mode: 0o755}}, want: 0},
		{name: "binary_replacement", entries: []ociTestEntry{{name: "usr/local/bin/semver-tool", data: binary, mode: 0o644}}, want: 3},
	} {
		t.Run(test.name, func(t *testing.T) {
			layout := ociTestLayout(t)
			upperHash := sha256.Sum256(ociTestTar(t, test.entries))
			upperSource := "oci:sha256:" + hex.EncodeToString(upperHash[:]) + "!/usr/local/bin/semver-tool"
			image := ociTestImage(t, layout, "linux", "amd64", []ociTestLayer{
				{entries: []ociTestEntry{{name: "usr/local/bin/semver-tool", data: binary, mode: 0o755}}},
				{entries: test.entries},
			})
			ociTestIndex(t, layout, image)
			doc, output, code := ociTestScan(t, layout)
			if code != 0 || len(doc.Components) != test.want {
				t.Fatalf("Go binary overlay incorrect: code=%d output=%s coverage=%#v components=%#v", code, output, doc.Coverage, doc.Components)
			}
			if test.want > 0 {
				for _, component := range doc.Components {
					if component.Evidence[0].InputPath != upperSource {
						t.Fatalf("Go binary evidence did not follow upper layer: %#v", component.Evidence[0])
					}
				}
			}
		})
	}
}

func TestOCIGoBinaryUnderSameLayerSymlinkRejected(t *testing.T) {
	binary, _ := ociGoBinaryFixture(t)
	layout := ociTestLayout(t)
	image := ociTestImage(t, layout, "linux", "amd64", []ociTestLayer{{entries: []ociTestEntry{
		{name: "app", typeflag: tar.TypeSymlink, linkname: "/outside"},
		{name: "app/semver-tool", data: binary, mode: 0o755},
	}}})
	ociTestIndex(t, layout, image)
	_, output, code := ociTestScan(t, layout)
	if code != 1 || !strings.Contains(output, "non-directory entry") {
		t.Fatalf("Go binary beneath same-layer symlink was accepted: code=%d output=%s", code, output)
	}
}

func TestOCIGoBinaryIdenticalBytesAtDistinctPaths(t *testing.T) {
	binaryBytes, _ := ociGoBinaryFixture(t)
	layout := ociTestLayout(t)
	image := ociTestImage(t, layout, "linux", "amd64", []ociTestLayer{{entries: []ociTestEntry{
		{name: "usr/bin/first", data: binaryBytes, mode: 0o755},
		{name: "usr/bin/second", data: binaryBytes, mode: 0o755},
	}}})
	ociTestIndex(t, layout, image)
	doc, output, code := ociTestScan(t, layout)
	if code != 0 || doc.Coverage.Packages != 6 || doc.Coverage.Edges != 6 {
		t.Fatalf("identical Go binaries conflated: code=%d output=%s coverage=%#v", code, output, doc.Coverage)
	}
	ids := map[string]bool{}
	for _, component := range doc.Components {
		if ids[component.ID] {
			t.Fatalf("duplicate Go component ID: %s", component.ID)
		}
		ids[component.ID] = true
	}
}

func TestOCIGoBinaryMalformedSectionNamesReported(t *testing.T) {
	binaryBytes, _ := ociGoBinaryFixture(t)
	mutated := append([]byte(nil), binaryBytes...)
	if len(mutated) < 64 || string(mutated[:4]) != "\x7fELF" || mutated[4] != 2 || mutated[5] != 1 {
		t.Fatal("fixture must be ELF64 little-endian")
	}
	shoff := binary.LittleEndian.Uint64(mutated[40:48])
	shentsize := uint64(binary.LittleEndian.Uint16(mutated[58:60]))
	shstrndx := uint64(binary.LittleEndian.Uint16(mutated[62:64]))
	if shstrndx == 0 || shoff+shstrndx*shentsize+16 > uint64(len(mutated)) {
		t.Fatal("fixture section-name header missing")
	}
	flags := shoff + shstrndx*shentsize + 8
	binary.LittleEndian.PutUint64(mutated[flags:flags+8], binary.LittleEndian.Uint64(mutated[flags:flags+8])|0x800)
	layout := ociTestLayout(t)
	image := ociTestImage(t, layout, "linux", "amd64", []ociTestLayer{{entries: []ociTestEntry{{name: "usr/bin/broken", data: mutated, mode: 0o755}}}})
	ociTestIndex(t, layout, image)
	doc, output, code := ociTestScan(t, layout)
	if code != 0 || len(doc.Components) != 0 || doc.Coverage.GraphState != "partial" || doc.Coverage.OriginState != "partial" {
		t.Fatalf("malformed ELF handling incorrect: code=%d output=%s coverage=%#v", code, output, doc.Coverage)
	}
	for _, issue := range doc.Coverage.Issues {
		if issue.Code == "go_binary_invalid" && issue.Name == "usr/bin/broken" {
			return
		}
	}
	t.Fatalf("malformed Go ELF was not reported: %#v", doc.Coverage.Issues)
}
