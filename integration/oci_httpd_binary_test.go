package integration_test

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func httpdVersionStrings(full, short string) string {
	return "\x00Apache/" + full + " (Unix)\x00\x00\x00\x00Apache/" + short + "\x00"
}

func TestOCIHTTPDBinaryVerifiedVersion(t *testing.T) {
	for _, test := range []struct {
		name, rodata, platform, want string
	}{
		{name: "httpd_2_4_68", rodata: "\x00Server version: %s\n\x00" + httpdVersionStrings("2.4.68", "2.4.68"), platform: "arm64", want: "2.4.68"},
		{name: "httpd_2_4_69", rodata: "\x00Server version: %s\n\x00" + httpdVersionStrings("2.4.69", "2.4.69"), platform: "arm64", want: "2.4.69"},
		{name: "debian_string_order", rodata: "\x00Server version: %s\n\x00\x00Apache/2.4.69\x00" + strings.Repeat("x", 128) + "\x00Apache/2.4.69 (Unix)\x00", platform: "arm64", want: "2.4.69"},
		{name: "mismatch", rodata: "\x00Server version: %s\n\x00" + httpdVersionStrings("2.4.69", "2.4.68"), platform: "arm64"},
		{name: "bad_version", rodata: "\x00Server version: %s\n\x00" + httpdVersionStrings("2.04.69", "2.04.69"), platform: "arm64"},
		{name: "missing_output_template", rodata: httpdVersionStrings("2.4.69", "2.4.69"), platform: "arm64"},
		{name: "standalone_header", rodata: "\x00Server version: %s\n\x00\x00Apache/2.4.69 (Unix)\x00", platform: "arm64"},
		{name: "ambiguous", rodata: "\x00Server version: %s\n\x00" + httpdVersionStrings("2.4.68", "2.4.68") + httpdVersionStrings("2.4.69", "2.4.69"), platform: "arm64"},
		{name: "wrong_architecture", rodata: "\x00Server version: %s\n\x00" + httpdVersionStrings("2.4.69", "2.4.69"), platform: "amd64"},
	} {
		t.Run(test.name, func(t *testing.T) {
			binaryBytes := runtimeELFFixture([]byte(test.rodata))
			layout := ociTestLayout(t)
			image := ociTestImage(t, layout, "linux", test.platform, []ociTestLayer{{entries: []ociTestEntry{{name: "usr/local/apache2/bin/httpd", data: binaryBytes, mode: 0o755}}}})
			ociTestIndex(t, layout, image)
			doc, output, code := ociTestScan(t, layout)
			if code != 0 {
				t.Fatalf("OCI scan failed: %s", output)
			}
			if test.want == "" {
				if len(doc.Components) != 0 || !hasOCICoverageIssue(doc, "httpd_server_invalid") {
					t.Fatalf("unsupported httpd identity was reported: %#v", doc)
				}
				return
			}
			if len(doc.Components) != 1 || doc.Coverage.Packages != 1 || doc.Coverage.Edges != 1 {
				t.Fatalf("httpd executable missing: %#v", doc)
			}
			component := doc.Components[0]
			digest := sha256.Sum256(binaryBytes)
			wantDigest := hex.EncodeToString(digest[:])
			if component.Kind != "application" || component.Name != "httpd" || component.Version != test.want || component.PURL != "" || len(component.Hashes) != 1 || component.Hashes[0].Content != wantDigest || len(component.Evidence) != 1 || component.Evidence[0].InputDigest != "sha256:"+wantDigest || !strings.HasSuffix(component.Evidence[0].InputPath, "!/usr/local/apache2/bin/httpd") || !strings.HasPrefix(component.Evidence[0].Pointer, "elf/offset/") || !hasOCICoverageIssue(doc, "httpd_server_origin_unavailable") {
				t.Fatalf("httpd executable evidence incorrect: %#v", doc)
			}
		})
	}
}

func TestOCIHTTPDBinaryFinalLayerAndPath(t *testing.T) {
	binaryBytes := runtimeELFFixture([]byte("\x00Server version: %s\n\x00" + httpdVersionStrings("2.4.69", "2.4.69")))
	for _, test := range []struct {
		name, binaryPath string
		upper            []ociTestEntry
		want             bool
	}{
		{name: "whiteout", binaryPath: "usr/local/apache2/bin/httpd", upper: []ociTestEntry{{name: "usr/local/apache2/bin/.wh.httpd"}}},
		{name: "parent_whiteout", binaryPath: "usr/local/apache2/bin/httpd", upper: []ociTestEntry{{name: "usr/local/apache2/.wh.bin"}}},
		{name: "script_replacement", binaryPath: "usr/local/apache2/bin/httpd", upper: []ociTestEntry{{name: "usr/local/apache2/bin/httpd", data: []byte("#!/bin/sh\nexit 0\n"), mode: 0o755}}},
		{name: "symlink_replacement", binaryPath: "usr/local/apache2/bin/httpd", upper: []ociTestEntry{{name: "usr/local/apache2/bin/httpd", typeflag: tar.TypeSymlink, linkname: "/bin/false"}}},
		{name: "package_managed_path", binaryPath: "usr/sbin/httpd"},
		{name: "retained", binaryPath: "usr/local/apache2/bin/httpd", want: true},
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
				t.Fatalf("httpd final path handling incorrect: code=%d output=%s doc=%#v", code, output, doc)
			}
		})
	}
}
