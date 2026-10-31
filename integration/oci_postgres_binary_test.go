package integration_test

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"

	"ravel/internal/model"
)

func hasPostgresCoverageIssue(doc model.Document, code string) bool {
	for _, issue := range doc.Coverage.Issues {
		if issue.Code == code {
			return true
		}
	}
	return false
}

// postgresELFFixture contains the two independent version strings in an
// allocated read-only ELF section. It is generated so no upstream executable
// needs to be checked into the repository.
func postgresELFFixture(versionLine, buildLine string) []byte {
	data := make([]byte, 0x500)
	copy(data[:4], "\x7fELF")
	data[4], data[5], data[6] = 2, 1, 1
	binary.LittleEndian.PutUint16(data[16:18], 2)
	binary.LittleEndian.PutUint16(data[18:20], 183)
	binary.LittleEndian.PutUint32(data[20:24], 1)
	binary.LittleEndian.PutUint64(data[32:40], 64)
	binary.LittleEndian.PutUint64(data[40:48], 0x400)
	binary.LittleEndian.PutUint16(data[52:54], 64)
	binary.LittleEndian.PutUint16(data[54:56], 56)
	binary.LittleEndian.PutUint16(data[56:58], 1)
	binary.LittleEndian.PutUint16(data[58:60], 64)
	binary.LittleEndian.PutUint16(data[60:62], 3)
	binary.LittleEndian.PutUint16(data[62:64], 1)
	rodata := []byte("\x00postgres (PostgreSQL) " + versionLine + "\n\x00\x00PostgreSQL " + buildLine + " on aarch64-linux, 64-bit\x00")
	copy(data[0x100:], rodata)
	shstr := []byte("\x00.shstrtab\x00.rodata\x00")
	copy(data[0x300:], shstr)
	binary.LittleEndian.PutUint32(data[64:68], 1)
	binary.LittleEndian.PutUint32(data[68:72], 4)
	binary.LittleEndian.PutUint64(data[72:80], 0x100)
	binary.LittleEndian.PutUint64(data[80:88], 0x400100)
	binary.LittleEndian.PutUint64(data[96:104], uint64(len(rodata)))
	binary.LittleEndian.PutUint64(data[104:112], uint64(len(rodata)))
	binary.LittleEndian.PutUint32(data[0x440:0x444], 1)
	binary.LittleEndian.PutUint32(data[0x444:0x448], 3)
	binary.LittleEndian.PutUint64(data[0x458:0x460], 0x300)
	binary.LittleEndian.PutUint64(data[0x460:0x468], uint64(len(shstr)))
	binary.LittleEndian.PutUint32(data[0x480:0x484], 11)
	binary.LittleEndian.PutUint32(data[0x484:0x488], 1)
	binary.LittleEndian.PutUint64(data[0x488:0x490], 2)
	binary.LittleEndian.PutUint64(data[0x498:0x4a0], 0x100)
	binary.LittleEndian.PutUint64(data[0x4a0:0x4a8], uint64(len(rodata)))
	return data
}

func TestOCIPostgresBinaryVerifiedVersion(t *testing.T) {
	for _, test := range []struct {
		name, versionLine, buildLine, want string
	}{
		{name: "alpine", versionLine: "16.15", buildLine: "16.15", want: "16.15"},
		{name: "debian_suffix", versionLine: "17.11 (Debian 17.11-1.pgdg12+2)", buildLine: "17.11 (Debian 17.11-1.pgdg12+2)", want: "17.11"},
		{name: "mismatch", versionLine: "16.15", buildLine: "16.14"},
		{name: "bad_version", versionLine: "16.15evil", buildLine: "16.15evil"},
	} {
		t.Run(test.name, func(t *testing.T) {
			binaryBytes := postgresELFFixture(test.versionLine, test.buildLine)
			layout := ociTestLayout(t)
			image := ociTestImage(t, layout, "linux", "arm64", []ociTestLayer{{entries: []ociTestEntry{{name: "usr/local/bin/postgres", data: binaryBytes, mode: 0o755}}}})
			ociTestIndex(t, layout, image)
			doc, output, code := ociTestScan(t, layout)
			if code != 0 {
				t.Fatalf("OCI scan failed: %s", output)
			}
			if test.want == "" {
				if len(doc.Components) != 0 || !hasPostgresCoverageIssue(doc, "postgres_runtime_invalid") {
					t.Fatalf("unsupported PostgreSQL identity was reported: %#v", doc)
				}
				return
			}
			if len(doc.Components) != 1 || doc.Coverage.Packages != 1 || doc.Coverage.Edges != 1 {
				t.Fatalf("PostgreSQL executable missing: %#v", doc)
			}
			component := doc.Components[0]
			digest := sha256.Sum256(binaryBytes)
			wantDigest := hex.EncodeToString(digest[:])
			if component.Kind != "application" || component.Name != "postgresql" || component.Version != test.want || component.PURL != "" || len(component.Hashes) != 1 || component.Hashes[0].Content != wantDigest || len(component.Evidence) != 1 || component.Evidence[0].InputDigest != "sha256:"+wantDigest || !strings.HasSuffix(component.Evidence[0].InputPath, "!/usr/local/bin/postgres") || !strings.HasPrefix(component.Evidence[0].Pointer, "elf/offset/") || !hasPostgresCoverageIssue(doc, "postgres_runtime_origin_unavailable") {
				t.Fatalf("PostgreSQL executable evidence incorrect: %#v", doc)
			}
		})
	}
}

func TestOCIPostgresBinaryFinalLayerAndPath(t *testing.T) {
	binaryBytes := postgresELFFixture("16.15", "16.15")
	for _, test := range []struct {
		name, binaryPath string
		upper            []ociTestEntry
		want             bool
	}{
		{name: "whiteout", binaryPath: "usr/local/bin/postgres", upper: []ociTestEntry{{name: "usr/local/bin/.wh.postgres"}}},
		{name: "parent_whiteout", binaryPath: "usr/local/bin/postgres", upper: []ociTestEntry{{name: "usr/local/.wh.bin"}}},
		{name: "script_replacement", binaryPath: "usr/local/bin/postgres", upper: []ociTestEntry{{name: "usr/local/bin/postgres", data: []byte("#!/bin/sh\nexit 0\n"), mode: 0o755}}},
		{name: "symlink_replacement", binaryPath: "usr/local/bin/postgres", upper: []ociTestEntry{{name: "usr/local/bin/postgres", typeflag: tar.TypeSymlink, linkname: "/bin/false"}}},
		{name: "package_managed_path", binaryPath: "usr/lib/postgresql/17/bin/postgres", want: false},
		{name: "retained", binaryPath: "usr/local/bin/postgres", want: true},
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
				t.Fatalf("PostgreSQL final path handling incorrect: code=%d output=%s doc=%#v", code, output, doc)
			}
		})
	}
}
