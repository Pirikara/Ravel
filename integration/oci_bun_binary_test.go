package integration_test

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func bunELFFixture(bannerVersion, agentVersion, architecture string) []byte {
	rodata := []byte("\x00Bun v" + bannerVersion + " (Linux " + architecture + ")\x00\x00Bun/" + agentVersion + "\x00")
	return runtimeELFFixture(rodata)
}

func TestOCIBunBinaryVerifiedVersion(t *testing.T) {
	for _, test := range []struct {
		name, bannerVersion, agentVersion, architecture, want string
	}{
		{name: "bun_1_3", bannerVersion: "1.3.14", agentVersion: "1.3.14", architecture: "arm64", want: "1.3.14"},
		{name: "bun_1_4", bannerVersion: "1.4.4", agentVersion: "1.4.4", architecture: "arm64", want: "1.4.4"},
		{name: "mismatch", bannerVersion: "1.4.4", agentVersion: "1.4.3", architecture: "arm64"},
		{name: "bad_version", bannerVersion: "1.04.4", agentVersion: "1.04.4", architecture: "arm64"},
		{name: "wrong_architecture", bannerVersion: "1.4.4", agentVersion: "1.4.4", architecture: "x64"},
	} {
		t.Run(test.name, func(t *testing.T) {
			binaryBytes := bunELFFixture(test.bannerVersion, test.agentVersion, test.architecture)
			layout := ociTestLayout(t)
			image := ociTestImage(t, layout, "linux", "arm64", []ociTestLayer{{entries: []ociTestEntry{{name: "usr/local/bin/bun", data: binaryBytes, mode: 0o755}}}})
			ociTestIndex(t, layout, image)
			doc, output, code := ociTestScan(t, layout)
			if code != 0 {
				t.Fatalf("OCI scan failed: %s", output)
			}
			if test.want == "" {
				if len(doc.Components) != 0 || !hasOCICoverageIssue(doc, "bun_runtime_invalid") {
					t.Fatalf("unsupported Bun identity was reported: %#v", doc)
				}
				return
			}
			if len(doc.Components) != 1 || doc.Coverage.Packages != 1 || doc.Coverage.Edges != 1 {
				t.Fatalf("Bun executable missing: %#v", doc)
			}
			component := doc.Components[0]
			digest := sha256.Sum256(binaryBytes)
			wantDigest := hex.EncodeToString(digest[:])
			if component.Kind != "application" || component.Name != "bun" || component.Version != test.want || component.PURL != "" || len(component.Hashes) != 1 || component.Hashes[0].Content != wantDigest || len(component.Evidence) != 1 || component.Evidence[0].InputDigest != "sha256:"+wantDigest || !strings.HasSuffix(component.Evidence[0].InputPath, "!/usr/local/bin/bun") || !strings.HasPrefix(component.Evidence[0].Pointer, "elf/offset/") || !hasOCICoverageIssue(doc, "bun_runtime_origin_unavailable") {
				t.Fatalf("Bun executable evidence incorrect: %#v", doc)
			}
		})
	}
}

func TestOCIBunBinaryFinalLayerAndPath(t *testing.T) {
	binaryBytes := bunELFFixture("1.4.4", "1.4.4", "arm64")
	for _, test := range []struct {
		name, binaryPath string
		upper            []ociTestEntry
		want             bool
	}{
		{name: "whiteout", binaryPath: "usr/local/bin/bun", upper: []ociTestEntry{{name: "usr/local/bin/.wh.bun"}}},
		{name: "parent_whiteout", binaryPath: "usr/local/bin/bun", upper: []ociTestEntry{{name: "usr/local/.wh.bin"}}},
		{name: "script_replacement", binaryPath: "usr/local/bin/bun", upper: []ociTestEntry{{name: "usr/local/bin/bun", data: []byte("#!/bin/sh\nexit 0\n"), mode: 0o755}}},
		{name: "symlink_replacement", binaryPath: "usr/local/bin/bun", upper: []ociTestEntry{{name: "usr/local/bin/bun", typeflag: tar.TypeSymlink, linkname: "/bin/false"}}},
		{name: "other_path", binaryPath: "usr/bin/bun"},
		{name: "retained", binaryPath: "usr/local/bin/bun", want: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			layout := ociTestLayout(t)
			layers := []ociTestLayer{{entries: []ociTestEntry{{name: test.binaryPath, data: binaryBytes, mode: 0o755}}}}
			if len(test.upper) > 0 {
				layers = append(layers, ociTestLayer{entries: test.upper})
			}
			image := ociTestImage(t, layout, "linux", "arm64", layers)
			ociTestIndex(t, layout, image)
			doc, output, code := ociTestScan(t, layout)
			if code != 0 || (len(doc.Components) == 1) != test.want {
				t.Fatalf("Bun final path handling incorrect: code=%d output=%s doc=%#v", code, output, doc)
			}
		})
	}
}
