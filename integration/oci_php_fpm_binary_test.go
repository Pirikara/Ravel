package integration_test

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func phpFPMELFFixture(phpVersion, zendVersion, bannerSuffix string, fpmMarker, banner bool) []byte {
	rodata := "\x00X-Powered-By: PHP/" + phpVersion + "\x00\x00Zend Engine v" + zendVersion + ", Copyright (c) Zend Technologies\n\x00"
	if fpmMarker {
		rodata += "\x00fpm-fcgi\x00\x00FastCGI Process Manager\x00"
	}
	if banner {
		rodata += "\x00PHP %s (%s) (built: %s %s)" + bannerSuffix + "\nCopyright (c) The PHP Group\n"
	}
	return runtimeELFFixture([]byte(rodata))
}

func TestOCIPHPFPMBinaryVerifiedVersion(t *testing.T) {
	for _, test := range []struct {
		name, phpVersion, zendVersion, bannerSuffix, platform, want string
		fpmMarker, banner                                           bool
	}{
		{name: "php_8_3_fpm", phpVersion: "8.3.36", zendVersion: "4.3.36", platform: "arm64", fpmMarker: true, banner: true, want: "8.3.36"},
		{name: "php_8_4_fpm", phpVersion: "8.4.27", zendVersion: "4.4.27", bannerSuffix: " (%s)", platform: "arm64", fpmMarker: true, banner: true, want: "8.4.27"},
		{name: "zend_mismatch", phpVersion: "8.4.27", zendVersion: "4.4.26", bannerSuffix: " (%s)", platform: "arm64", fpmMarker: true, banner: true},
		{name: "missing_fpm_marker", phpVersion: "8.4.27", zendVersion: "4.4.27", bannerSuffix: " (%s)", platform: "arm64", banner: true},
		{name: "missing_banner", phpVersion: "8.4.27", zendVersion: "4.4.27", platform: "arm64", fpmMarker: true},
		{name: "wrong_architecture", phpVersion: "8.4.27", zendVersion: "4.4.27", bannerSuffix: " (%s)", platform: "amd64", fpmMarker: true, banner: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			binaryBytes := phpFPMELFFixture(test.phpVersion, test.zendVersion, test.bannerSuffix, test.fpmMarker, test.banner)
			layout := ociTestLayout(t)
			image := ociTestImage(t, layout, "linux", test.platform, []ociTestLayer{{entries: []ociTestEntry{{name: "usr/local/sbin/php-fpm", data: binaryBytes, mode: 0o755}}}})
			ociTestIndex(t, layout, image)
			doc, output, code := ociTestScan(t, layout)
			if code != 0 {
				t.Fatalf("OCI scan failed: %s", output)
			}
			if test.want == "" {
				if len(doc.Components) != 0 || !hasOCICoverageIssue(doc, "php_fpm_invalid") {
					t.Fatalf("unsupported PHP FPM identity was reported: %#v", doc)
				}
				return
			}
			if len(doc.Components) != 1 || doc.Coverage.Packages != 1 || doc.Coverage.Edges != 1 {
				t.Fatalf("PHP FPM executable missing: %#v", doc)
			}
			component := doc.Components[0]
			digest := sha256.Sum256(binaryBytes)
			wantDigest := hex.EncodeToString(digest[:])
			if component.Kind != "application" || component.Name != "php-fpm" || component.Version != test.want || component.PURL != "" || len(component.Hashes) != 1 || component.Hashes[0].Content != wantDigest || len(component.Evidence) != 1 || component.Evidence[0].InputDigest != "sha256:"+wantDigest || !strings.HasSuffix(component.Evidence[0].InputPath, "!/usr/local/sbin/php-fpm") || !strings.HasPrefix(component.Evidence[0].Pointer, "elf/offset/") || !hasOCICoverageIssue(doc, "php_fpm_origin_unavailable") {
				t.Fatalf("PHP FPM executable evidence incorrect: %#v", doc)
			}
		})
	}
}

func TestOCIPHPFPMAndCLIBothInstalled(t *testing.T) {
	layout := ociTestLayout(t)
	cli := phpCLIELFFixture("8.4.27", "4.4.27", "8.4.27", true)
	fpm := phpFPMELFFixture("8.4.27", "4.4.27", " (%s)", true, true)
	image := ociTestImage(t, layout, "linux", "arm64", []ociTestLayer{{entries: []ociTestEntry{
		{name: "usr/local/bin/php", data: cli, mode: 0o755},
		{name: "usr/local/sbin/php-fpm", data: fpm, mode: 0o755},
	}}})
	ociTestIndex(t, layout, image)
	doc, output, code := ociTestScan(t, layout)
	if code != 0 || len(doc.Components) != 2 || doc.Coverage.Packages != 2 {
		t.Fatalf("PHP CLI and FPM were not both reported: code=%d output=%s doc=%#v", code, output, doc)
	}
	names := map[string]bool{}
	for _, component := range doc.Components {
		names[component.Name] = component.Version == "8.4.27"
	}
	if !names["php-cli"] || !names["php-fpm"] {
		t.Fatalf("PHP executables were conflated: %#v", doc.Components)
	}
}

func TestOCIPHPFPMBinaryFinalLayerAndPath(t *testing.T) {
	binaryBytes := phpFPMELFFixture("8.4.27", "4.4.27", " (%s)", true, true)
	for _, test := range []struct {
		name, binaryPath string
		upper            []ociTestEntry
		want             bool
	}{
		{name: "whiteout", binaryPath: "usr/local/sbin/php-fpm", upper: []ociTestEntry{{name: "usr/local/sbin/.wh.php-fpm"}}},
		{name: "parent_whiteout", binaryPath: "usr/local/sbin/php-fpm", upper: []ociTestEntry{{name: "usr/local/.wh.sbin"}}},
		{name: "script_replacement", binaryPath: "usr/local/sbin/php-fpm", upper: []ociTestEntry{{name: "usr/local/sbin/php-fpm", data: []byte("#!/bin/sh\nexit 0\n"), mode: 0o755}}},
		{name: "symlink_replacement", binaryPath: "usr/local/sbin/php-fpm", upper: []ociTestEntry{{name: "usr/local/sbin/php-fpm", typeflag: tar.TypeSymlink, linkname: "/bin/false"}}},
		{name: "package_managed_path", binaryPath: "usr/sbin/php-fpm"},
		{name: "retained", binaryPath: "usr/local/sbin/php-fpm", want: true},
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
				t.Fatalf("PHP FPM final path handling incorrect: code=%d output=%s doc=%#v", code, output, doc)
			}
		})
	}
}
