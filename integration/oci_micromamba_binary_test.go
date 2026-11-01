package integration_test

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func micromambaELFFixture(agentVersion, buildVersion string, command bool) []byte {
	rodata := "\x00mamba/" + agentVersion + "\x00\x00" + buildVersion + "\x00\x00\x00" + buildVersion + "\x00"
	if command {
		rodata += "\x00Install specific micromamba version\x00"
	}
	return runtimeELFFixture([]byte(rodata))
}

func TestOCIMicromambaBinaryVersionEvidence(t *testing.T) {
	for _, test := range []struct {
		name, agentVersion, buildVersion, platform, want string
		command                                          bool
	}{
		{name: "micromamba_2_5_0", agentVersion: "2.5.0", buildVersion: "2.5.0", platform: "arm64", command: true, want: "2.5.0"},
		{name: "micromamba_2_6_1", agentVersion: "2.6.1", buildVersion: "2.6.1", platform: "arm64", command: true, want: "2.6.1"},
		{name: "mismatched_version", agentVersion: "2.5.0", buildVersion: "2.4.0", platform: "arm64", command: true},
		{name: "missing_identity", agentVersion: "2.5.0", buildVersion: "2.5.0", platform: "arm64"},
		{name: "wrong_architecture", agentVersion: "2.5.0", buildVersion: "2.5.0", platform: "amd64", command: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			binaryBytes := micromambaELFFixture(test.agentVersion, test.buildVersion, test.command)
			layout := ociTestLayout(t)
			image := ociTestImage(t, layout, "linux", test.platform, []ociTestLayer{{entries: []ociTestEntry{{name: "usr/bin/micromamba", data: binaryBytes, mode: 0o755}}}})
			ociTestIndex(t, layout, image)
			doc, output, code := ociTestScan(t, layout)
			if code != 0 {
				t.Fatalf("OCI scan failed: %s", output)
			}
			if test.want == "" {
				if len(doc.Components) != 0 || !hasOCICoverageIssue(doc, "micromamba_runtime_invalid") {
					t.Fatalf("unverified binary identified: %#v", doc)
				}
				return
			}
			if len(doc.Components) != 1 || doc.Coverage.Packages != 1 || doc.Coverage.Edges != 1 {
				t.Fatalf("micromamba executable missing: %#v", doc)
			}
			component := doc.Components[0]
			digest := sha256.Sum256(binaryBytes)
			wantDigest := hex.EncodeToString(digest[:])
			if component.Kind != "application" || component.Name != "micromamba" || component.Version != test.want || component.PURL != "" || len(component.Hashes) != 1 || component.Hashes[0].Content != wantDigest || len(component.Evidence) != 1 || component.Evidence[0].InputDigest != "sha256:"+wantDigest || !strings.HasSuffix(component.Evidence[0].InputPath, "!/usr/bin/micromamba") || !strings.HasPrefix(component.Evidence[0].Pointer, "elf/offset/") || !hasOCICoverageIssue(doc, "micromamba_runtime_origin_unavailable") {
				t.Fatalf("micromamba evidence incorrect: %#v", doc)
			}
		})
	}
}

func TestOCIMicromambaBinaryFinalLayer(t *testing.T) {
	binaryBytes := micromambaELFFixture("2.5.0", "2.5.0", true)
	for _, test := range []struct {
		name  string
		upper []ociTestEntry
		want  bool
	}{
		{name: "retained", want: true},
		{name: "whiteout", upper: []ociTestEntry{{name: "usr/bin/.wh.micromamba"}}},
		{name: "parent_whiteout", upper: []ociTestEntry{{name: "usr/.wh.bin"}}},
		{name: "script_replacement", upper: []ociTestEntry{{name: "usr/bin/micromamba", data: []byte("#!/bin/sh\nexit 0\n"), mode: 0o755}}},
		{name: "symlink_replacement", upper: []ociTestEntry{{name: "usr/bin/micromamba", typeflag: tar.TypeSymlink, linkname: "/bin/false"}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			layout := ociTestLayout(t)
			layers := []ociTestLayer{{entries: []ociTestEntry{{name: "usr/bin/micromamba", data: binaryBytes, mode: 0o755}}}}
			if len(test.upper) > 0 {
				layers = append(layers, ociTestLayer{entries: test.upper})
			}
			image := ociTestImage(t, layout, "linux", "arm64", layers)
			ociTestIndex(t, layout, image)
			doc, output, code := ociTestScan(t, layout)
			if code != 0 || (len(doc.Components) == 1) != test.want {
				t.Fatalf("micromamba final layer handling incorrect: code=%d output=%s doc=%#v", code, output, doc)
			}
		})
	}
}
