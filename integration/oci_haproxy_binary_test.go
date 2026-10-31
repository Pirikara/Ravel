package integration_test

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func haproxyELFFixture(buildVersion, buildRevision, bannerVersion, bannerRevision string, template bool) []byte {
	rodata := "\x00" + buildVersion + "-" + buildRevision + "\x00\x00\x00haproxy_server_\x00"
	if template {
		rodata += "\x00HAProxy version %s %s - https://haproxy.org/\n"
	}
	rodata += "\x00HAProxy's dummy HTTP server for benchmarks - version " + bannerVersion + "-" + bannerRevision + ".\n"
	return runtimeELFFixture([]byte(rodata))
}

func TestOCIHAProxyBinaryVerifiedVersion(t *testing.T) {
	for _, test := range []struct {
		name, buildVersion, buildRevision, bannerVersion, bannerRevision, platform, want string
		template                                                                         bool
	}{
		{name: "haproxy_3_4_6", buildVersion: "3.4.6", buildRevision: "56332c5", bannerVersion: "3.4.6", bannerRevision: "56332c5", platform: "arm64", template: true, want: "3.4.6"},
		{name: "haproxy_3_4_7", buildVersion: "3.4.7", buildRevision: "8872a26", bannerVersion: "3.4.7", bannerRevision: "8872a26", platform: "arm64", template: true, want: "3.4.7"},
		{name: "version_mismatch", buildVersion: "3.4.7", buildRevision: "8872a26", bannerVersion: "3.4.6", bannerRevision: "8872a26", platform: "arm64", template: true},
		{name: "revision_mismatch", buildVersion: "3.4.7", buildRevision: "8872a26", bannerVersion: "3.4.7", bannerRevision: "8872a27", platform: "arm64", template: true},
		{name: "bad_version", buildVersion: "3.04.7", buildRevision: "8872a26", bannerVersion: "3.04.7", bannerRevision: "8872a26", platform: "arm64", template: true},
		{name: "missing_banner", buildVersion: "3.4.7", buildRevision: "8872a26", bannerVersion: "", bannerRevision: "", platform: "arm64", template: true},
		{name: "missing_template", buildVersion: "3.4.7", buildRevision: "8872a26", bannerVersion: "3.4.7", bannerRevision: "8872a26", platform: "arm64"},
		{name: "wrong_architecture", buildVersion: "3.4.7", buildRevision: "8872a26", bannerVersion: "3.4.7", bannerRevision: "8872a26", platform: "amd64", template: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			binaryBytes := haproxyELFFixture(test.buildVersion, test.buildRevision, test.bannerVersion, test.bannerRevision, test.template)
			layout := ociTestLayout(t)
			image := ociTestImage(t, layout, "linux", test.platform, []ociTestLayer{{entries: []ociTestEntry{{name: "usr/local/sbin/haproxy", data: binaryBytes, mode: 0o755}}}})
			ociTestIndex(t, layout, image)
			doc, output, code := ociTestScan(t, layout)
			if code != 0 {
				t.Fatalf("OCI scan failed: %s", output)
			}
			if test.want == "" {
				if len(doc.Components) != 0 || !hasOCICoverageIssue(doc, "haproxy_server_invalid") {
					t.Fatalf("unsupported HAProxy identity was reported: %#v", doc)
				}
				return
			}
			if len(doc.Components) != 1 || doc.Coverage.Packages != 1 || doc.Coverage.Edges != 1 {
				t.Fatalf("HAProxy executable missing: %#v", doc)
			}
			component := doc.Components[0]
			digest := sha256.Sum256(binaryBytes)
			wantDigest := hex.EncodeToString(digest[:])
			if component.Kind != "application" || component.Name != "haproxy" || component.Version != test.want || component.PURL != "" || !strings.Contains(component.Context, "revision="+test.buildRevision) || len(component.Hashes) != 1 || component.Hashes[0].Content != wantDigest || len(component.Evidence) != 1 || component.Evidence[0].InputDigest != "sha256:"+wantDigest || !strings.HasSuffix(component.Evidence[0].InputPath, "!/usr/local/sbin/haproxy") || !strings.HasPrefix(component.Evidence[0].Pointer, "elf/offset/") || !hasOCICoverageIssue(doc, "haproxy_server_origin_unavailable") {
				t.Fatalf("HAProxy executable evidence incorrect: %#v", doc)
			}
		})
	}
}

func TestOCIHAProxyBinaryFinalLayerAndPath(t *testing.T) {
	binaryBytes := haproxyELFFixture("3.4.7", "8872a26", "3.4.7", "8872a26", true)
	for _, test := range []struct {
		name, binaryPath string
		upper            []ociTestEntry
		want             bool
	}{
		{name: "whiteout", binaryPath: "usr/local/sbin/haproxy", upper: []ociTestEntry{{name: "usr/local/sbin/.wh.haproxy"}}},
		{name: "parent_whiteout", binaryPath: "usr/local/sbin/haproxy", upper: []ociTestEntry{{name: "usr/local/.wh.sbin"}}},
		{name: "script_replacement", binaryPath: "usr/local/sbin/haproxy", upper: []ociTestEntry{{name: "usr/local/sbin/haproxy", data: []byte("#!/bin/sh\nexit 0\n"), mode: 0o755}}},
		{name: "symlink_replacement", binaryPath: "usr/local/sbin/haproxy", upper: []ociTestEntry{{name: "usr/local/sbin/haproxy", typeflag: tar.TypeSymlink, linkname: "/bin/false"}}},
		{name: "package_managed_path", binaryPath: "usr/sbin/haproxy"},
		{name: "retained", binaryPath: "usr/local/sbin/haproxy", want: true},
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
				t.Fatalf("HAProxy final path handling incorrect: code=%d output=%s doc=%#v", code, output, doc)
			}
		})
	}
}
