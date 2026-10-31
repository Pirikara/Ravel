package integration_test

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func phpCLIELFFixture(phpVersion, zendVersion, mysqlndVersion string, template bool) []byte {
	rodata := "\x00X-Powered-By: PHP/" + phpVersion + "\x00\x00Zend Engine v" + zendVersion + ", Copyright (c) Zend Technologies\n\x00"
	if mysqlndVersion != "" {
		rodata += "\x00mysqlnd " + mysqlndVersion + "\x00"
	}
	if template {
		rodata += "\x00PHP %s (%s) (built: %s %s) (%s)\nCopyright (c) The PHP Group\n"
	}
	return runtimeELFFixture([]byte(rodata))
}

func TestOCIPHPCLIBinaryVerifiedVersion(t *testing.T) {
	for _, test := range []struct {
		name, phpVersion, zendVersion, mysqlndVersion, platform, want string
		template                                                      bool
	}{
		{name: "php_8_3", phpVersion: "8.3.36", zendVersion: "4.3.36", mysqlndVersion: "8.3.36", platform: "arm64", template: true, want: "8.3.36"},
		{name: "php_8_4", phpVersion: "8.4.27", zendVersion: "4.4.27", mysqlndVersion: "8.4.27", platform: "arm64", template: true, want: "8.4.27"},
		{name: "without_mysqlnd", phpVersion: "8.4.27", zendVersion: "4.4.27", platform: "arm64", template: true, want: "8.4.27"},
		{name: "zend_mismatch", phpVersion: "8.4.27", zendVersion: "4.4.26", mysqlndVersion: "8.4.27", platform: "arm64", template: true},
		{name: "mysqlnd_mismatch", phpVersion: "8.4.27", zendVersion: "4.4.27", mysqlndVersion: "8.4.26", platform: "arm64", template: true},
		{name: "unsupported_major", phpVersion: "7.4.33", zendVersion: "3.4.33", platform: "arm64", template: true},
		{name: "bad_version", phpVersion: "8.04.27", zendVersion: "4.04.27", platform: "arm64", template: true},
		{name: "missing_template", phpVersion: "8.4.27", zendVersion: "4.4.27", platform: "arm64"},
		{name: "wrong_architecture", phpVersion: "8.4.27", zendVersion: "4.4.27", platform: "amd64", template: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			binaryBytes := phpCLIELFFixture(test.phpVersion, test.zendVersion, test.mysqlndVersion, test.template)
			layout := ociTestLayout(t)
			image := ociTestImage(t, layout, "linux", test.platform, []ociTestLayer{{entries: []ociTestEntry{{name: "usr/local/bin/php", data: binaryBytes, mode: 0o755}}}})
			ociTestIndex(t, layout, image)
			doc, output, code := ociTestScan(t, layout)
			if code != 0 {
				t.Fatalf("OCI scan failed: %s", output)
			}
			if test.want == "" {
				if len(doc.Components) != 0 || !hasOCICoverageIssue(doc, "php_cli_invalid") {
					t.Fatalf("unsupported PHP CLI identity was reported: %#v", doc)
				}
				return
			}
			if len(doc.Components) != 1 || doc.Coverage.Packages != 1 || doc.Coverage.Edges != 1 {
				t.Fatalf("PHP CLI executable missing: %#v", doc)
			}
			component := doc.Components[0]
			digest := sha256.Sum256(binaryBytes)
			wantDigest := hex.EncodeToString(digest[:])
			if component.Kind != "application" || component.Name != "php-cli" || component.Version != test.want || component.PURL != "" || len(component.Hashes) != 1 || component.Hashes[0].Content != wantDigest || len(component.Evidence) != 1 || component.Evidence[0].InputDigest != "sha256:"+wantDigest || !strings.HasSuffix(component.Evidence[0].InputPath, "!/usr/local/bin/php") || !strings.HasPrefix(component.Evidence[0].Pointer, "elf/offset/") || !hasOCICoverageIssue(doc, "php_cli_origin_unavailable") {
				t.Fatalf("PHP CLI executable evidence incorrect: %#v", doc)
			}
		})
	}
}

func TestOCIPHPCLIBinaryFinalLayerAndPath(t *testing.T) {
	binaryBytes := phpCLIELFFixture("8.4.27", "4.4.27", "8.4.27", true)
	for _, test := range []struct {
		name, binaryPath string
		upper            []ociTestEntry
		want             bool
	}{
		{name: "whiteout", binaryPath: "usr/local/bin/php", upper: []ociTestEntry{{name: "usr/local/bin/.wh.php"}}},
		{name: "parent_whiteout", binaryPath: "usr/local/bin/php", upper: []ociTestEntry{{name: "usr/local/.wh.bin"}}},
		{name: "script_replacement", binaryPath: "usr/local/bin/php", upper: []ociTestEntry{{name: "usr/local/bin/php", data: []byte("#!/bin/sh\nexit 0\n"), mode: 0o755}}},
		{name: "symlink_replacement", binaryPath: "usr/local/bin/php", upper: []ociTestEntry{{name: "usr/local/bin/php", typeflag: tar.TypeSymlink, linkname: "/bin/false"}}},
		{name: "package_managed_path", binaryPath: "usr/bin/php"},
		{name: "retained", binaryPath: "usr/local/bin/php", want: true},
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
				t.Fatalf("PHP CLI final path handling incorrect: code=%d output=%s doc=%#v", code, output, doc)
			}
		})
	}
}
