package integration_test

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func redisELFFixture(infoVersion, buildVersion string, extraBuildVersions ...string) []byte {
	rodata := []byte("\x00Redis server %s\n\x00\x00" + infoVersion + "\x00\x00# Server\r\nredis_version:%s\r\nredis_git_sha1:%s\r\n\x00" + buildVersion + "buildkitsandbox-1793032788000000000\x00")
	for _, version := range extraBuildVersions {
		if version != "" {
			rodata = append(rodata, []byte("\x00"+version+"buildkitsandbox-1793032788000000000\x00")...)
		}
	}
	return runtimeELFFixture(rodata)
}

func TestOCIRedisBinaryVerifiedVersion(t *testing.T) {
	for _, test := range []struct {
		name, infoVersion, buildVersion, extraBuildVersion, want string
	}{
		{name: "redis_7", infoVersion: "7.4.12", buildVersion: "7.4.12", want: "7.4.12"},
		{name: "redis_8", infoVersion: "8.10.3", buildVersion: "8.10.3", want: "8.10.3"},
		{name: "mismatch", infoVersion: "7.4.12", buildVersion: "7.4.11"},
		{name: "ambiguous_build", infoVersion: "7.4.12", buildVersion: "7.4.12", extraBuildVersion: "7.4.11"},
		{name: "bad_version", infoVersion: "7.04.12", buildVersion: "7.04.12"},
	} {
		t.Run(test.name, func(t *testing.T) {
			binaryBytes := redisELFFixture(test.infoVersion, test.buildVersion, test.extraBuildVersion)
			layout := ociTestLayout(t)
			image := ociTestImage(t, layout, "linux", "arm64", []ociTestLayer{{entries: []ociTestEntry{{name: "usr/local/bin/redis-server", data: binaryBytes, mode: 0o755}}}})
			ociTestIndex(t, layout, image)
			doc, output, code := ociTestScan(t, layout)
			if code != 0 {
				t.Fatalf("OCI scan failed: %s", output)
			}
			if test.want == "" {
				if len(doc.Components) != 0 || !hasOCICoverageIssue(doc, "redis_runtime_invalid") {
					t.Fatalf("unsupported Redis identity was reported: %#v", doc)
				}
				return
			}
			if len(doc.Components) != 1 || doc.Coverage.Packages != 1 || doc.Coverage.Edges != 1 {
				t.Fatalf("Redis executable missing: %#v", doc)
			}
			component := doc.Components[0]
			digest := sha256.Sum256(binaryBytes)
			wantDigest := hex.EncodeToString(digest[:])
			if component.Kind != "application" || component.Name != "redis" || component.Version != test.want || component.PURL != "" || len(component.Hashes) != 1 || component.Hashes[0].Content != wantDigest || len(component.Evidence) != 1 || component.Evidence[0].InputDigest != "sha256:"+wantDigest || !strings.HasSuffix(component.Evidence[0].InputPath, "!/usr/local/bin/redis-server") || !strings.HasPrefix(component.Evidence[0].Pointer, "elf/offset/") || !hasOCICoverageIssue(doc, "redis_runtime_origin_unavailable") {
				t.Fatalf("Redis executable evidence incorrect: %#v", doc)
			}
		})
	}
}

func TestOCIRedisBinaryFinalLayerAndPath(t *testing.T) {
	binaryBytes := redisELFFixture("7.4.12", "7.4.12")
	for _, test := range []struct {
		name, binaryPath string
		upper            []ociTestEntry
		want             bool
	}{
		{name: "whiteout", binaryPath: "usr/local/bin/redis-server", upper: []ociTestEntry{{name: "usr/local/bin/.wh.redis-server"}}},
		{name: "parent_whiteout", binaryPath: "usr/local/bin/redis-server", upper: []ociTestEntry{{name: "usr/local/.wh.bin"}}},
		{name: "script_replacement", binaryPath: "usr/local/bin/redis-server", upper: []ociTestEntry{{name: "usr/local/bin/redis-server", data: []byte("#!/bin/sh\nexit 0\n"), mode: 0o755}}},
		{name: "symlink_replacement", binaryPath: "usr/local/bin/redis-server", upper: []ociTestEntry{{name: "usr/local/bin/redis-server", typeflag: tar.TypeSymlink, linkname: "/bin/false"}}},
		{name: "package_managed_path", binaryPath: "usr/bin/redis-server"},
		{name: "retained", binaryPath: "usr/local/bin/redis-server", want: true},
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
				t.Fatalf("Redis final path handling incorrect: code=%d output=%s doc=%#v", code, output, doc)
			}
		})
	}
}
