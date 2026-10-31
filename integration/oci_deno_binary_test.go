package integration_test

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func denoSignature(release, agent, revision string) string {
	return release + release + "+" + revision + "Deno/" + agent + "Deno/" + agent + "+" + revision
}

func TestOCIDenoBinaryVerifiedVersion(t *testing.T) {
	for _, test := range []struct {
		name, rodata, platform, want string
	}{
		{name: "deno_2_8", rodata: denoSignature("2.8.3", "2.8.3", "ba69908"), platform: "arm64", want: "2.8.3"},
		{name: "deno_2_9", rodata: denoSignature("2.9.8", "2.9.8", "fe7ed01"), platform: "arm64", want: "2.9.8"},
		{name: "release_agent_mismatch", rodata: denoSignature("2.9.8", "2.9.7", "fe7ed01"), platform: "arm64"},
		{name: "revision_mismatch", rodata: "2.9.82.9.8+fe7ed01Deno/2.9.8Deno/2.9.8+fe7ed02", platform: "arm64"},
		{name: "invalid_version", rodata: denoSignature("2.09.8", "2.09.8", "fe7ed01"), platform: "arm64"},
		{name: "unrelated_user_agent", rodata: "OTel-OTLP-Exporter-Deno/0.82.0", platform: "arm64"},
		{name: "ambiguous", rodata: denoSignature("2.8.3", "2.8.3", "ba69908") + "\x00" + denoSignature("2.9.8", "2.9.8", "fe7ed01"), platform: "arm64"},
		{name: "wrong_architecture", rodata: denoSignature("2.9.8", "2.9.8", "fe7ed01"), platform: "amd64"},
	} {
		t.Run(test.name, func(t *testing.T) {
			binaryBytes := runtimeELFFixture([]byte(test.rodata))
			layout := ociTestLayout(t)
			image := ociTestImage(t, layout, "linux", test.platform, []ociTestLayer{{entries: []ociTestEntry{{name: "bin/deno", data: binaryBytes, mode: 0o755}}}})
			ociTestIndex(t, layout, image)
			doc, output, code := ociTestScan(t, layout)
			if code != 0 {
				t.Fatalf("OCI scan failed: %s", output)
			}
			if test.want == "" {
				if len(doc.Components) != 0 || !hasOCICoverageIssue(doc, "deno_runtime_invalid") {
					t.Fatalf("unsupported Deno identity was reported: %#v", doc)
				}
				return
			}
			if len(doc.Components) != 1 || doc.Coverage.Packages != 1 || doc.Coverage.Edges != 1 {
				t.Fatalf("Deno executable missing: %#v", doc)
			}
			component := doc.Components[0]
			digest := sha256.Sum256(binaryBytes)
			wantDigest := hex.EncodeToString(digest[:])
			if component.Kind != "application" || component.Name != "deno" || component.Version != test.want || component.PURL != "" || len(component.Hashes) != 1 || component.Hashes[0].Content != wantDigest || len(component.Evidence) != 1 || component.Evidence[0].InputDigest != "sha256:"+wantDigest || !strings.HasSuffix(component.Evidence[0].InputPath, "!/bin/deno") || !strings.HasPrefix(component.Evidence[0].Pointer, "elf/offset/") || !hasOCICoverageIssue(doc, "deno_runtime_origin_unavailable") {
				t.Fatalf("Deno executable evidence incorrect: %#v", doc)
			}
		})
	}
}

func TestOCIDenoBinaryFinalLayerAndPath(t *testing.T) {
	binaryBytes := runtimeELFFixture([]byte(denoSignature("2.9.8", "2.9.8", "fe7ed01")))
	for _, test := range []struct {
		name, binaryPath string
		upper            []ociTestEntry
		want             bool
	}{
		{name: "whiteout", binaryPath: "bin/deno", upper: []ociTestEntry{{name: "bin/.wh.deno"}}},
		{name: "parent_whiteout", binaryPath: "bin/deno", upper: []ociTestEntry{{name: ".wh.bin"}}},
		{name: "script_replacement", binaryPath: "bin/deno", upper: []ociTestEntry{{name: "bin/deno", data: []byte("#!/bin/sh\nexit 0\n"), mode: 0o755}}},
		{name: "symlink_replacement", binaryPath: "bin/deno", upper: []ociTestEntry{{name: "bin/deno", typeflag: tar.TypeSymlink, linkname: "/bin/false"}}},
		{name: "different_path", binaryPath: "usr/bin/deno"},
		{name: "retained", binaryPath: "bin/deno", want: true},
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
				t.Fatalf("Deno final path handling incorrect: code=%d output=%s doc=%#v", code, output, doc)
			}
		})
	}
}
