package integration_test

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func memcachedELFFixture(flagVersion, usageVersion, wireVersion string) []byte {
	rodata := []byte("\x00memcached " + flagVersion + "\x00\x00memcached " + usageVersion + "\n\x00\x00VERSION " + wireVersion + "\x00")
	return runtimeELFFixture(rodata)
}

func TestOCIMemcachedBinaryVerifiedVersion(t *testing.T) {
	for _, test := range []struct {
		name, flagVersion, usageVersion, wireVersion, platform, want string
	}{
		{name: "memcached_1_6_44", flagVersion: "1.6.44", usageVersion: "1.6.44", wireVersion: "1.6.44", platform: "arm64", want: "1.6.44"},
		{name: "memcached_1_6_45", flagVersion: "1.6.45", usageVersion: "1.6.45", wireVersion: "1.6.45", platform: "arm64", want: "1.6.45"},
		{name: "usage_mismatch", flagVersion: "1.6.45", usageVersion: "1.6.44", wireVersion: "1.6.45", platform: "arm64"},
		{name: "wire_mismatch", flagVersion: "1.6.45", usageVersion: "1.6.45", wireVersion: "1.6.44", platform: "arm64"},
		{name: "bad_version", flagVersion: "1.06.45", usageVersion: "1.06.45", wireVersion: "1.06.45", platform: "arm64"},
		{name: "missing_wire", flagVersion: "1.6.45", usageVersion: "1.6.45", wireVersion: "", platform: "arm64"},
		{name: "wrong_architecture", flagVersion: "1.6.45", usageVersion: "1.6.45", wireVersion: "1.6.45", platform: "amd64"},
	} {
		t.Run(test.name, func(t *testing.T) {
			binaryBytes := memcachedELFFixture(test.flagVersion, test.usageVersion, test.wireVersion)
			layout := ociTestLayout(t)
			image := ociTestImage(t, layout, "linux", test.platform, []ociTestLayer{{entries: []ociTestEntry{{name: "usr/local/bin/memcached", data: binaryBytes, mode: 0o755}}}})
			ociTestIndex(t, layout, image)
			doc, output, code := ociTestScan(t, layout)
			if code != 0 {
				t.Fatalf("OCI scan failed: %s", output)
			}
			if test.want == "" {
				if len(doc.Components) != 0 || !hasOCICoverageIssue(doc, "memcached_server_invalid") {
					t.Fatalf("unsupported Memcached identity was reported: %#v", doc)
				}
				return
			}
			if len(doc.Components) != 1 || doc.Coverage.Packages != 1 || doc.Coverage.Edges != 1 {
				t.Fatalf("Memcached executable missing: %#v", doc)
			}
			component := doc.Components[0]
			digest := sha256.Sum256(binaryBytes)
			wantDigest := hex.EncodeToString(digest[:])
			if component.Kind != "application" || component.Name != "memcached" || component.Version != test.want || component.PURL != "" || len(component.Hashes) != 1 || component.Hashes[0].Content != wantDigest || len(component.Evidence) != 1 || component.Evidence[0].InputDigest != "sha256:"+wantDigest || !strings.HasSuffix(component.Evidence[0].InputPath, "!/usr/local/bin/memcached") || !strings.HasPrefix(component.Evidence[0].Pointer, "elf/offset/") || !hasOCICoverageIssue(doc, "memcached_server_origin_unavailable") {
				t.Fatalf("Memcached executable evidence incorrect: %#v", doc)
			}
		})
	}
}

func TestOCIMemcachedBinaryFinalLayerAndPath(t *testing.T) {
	binaryBytes := memcachedELFFixture("1.6.45", "1.6.45", "1.6.45")
	for _, test := range []struct {
		name, binaryPath string
		upper            []ociTestEntry
		want             bool
	}{
		{name: "whiteout", binaryPath: "usr/local/bin/memcached", upper: []ociTestEntry{{name: "usr/local/bin/.wh.memcached"}}},
		{name: "parent_whiteout", binaryPath: "usr/local/bin/memcached", upper: []ociTestEntry{{name: "usr/local/.wh.bin"}}},
		{name: "script_replacement", binaryPath: "usr/local/bin/memcached", upper: []ociTestEntry{{name: "usr/local/bin/memcached", data: []byte("#!/bin/sh\nexit 0\n"), mode: 0o755}}},
		{name: "symlink_replacement", binaryPath: "usr/local/bin/memcached", upper: []ociTestEntry{{name: "usr/local/bin/memcached", typeflag: tar.TypeSymlink, linkname: "/bin/false"}}},
		{name: "package_managed_path", binaryPath: "usr/bin/memcached"},
		{name: "retained", binaryPath: "usr/local/bin/memcached", want: true},
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
				t.Fatalf("Memcached final path handling incorrect: code=%d output=%s doc=%#v", code, output, doc)
			}
		})
	}
}
