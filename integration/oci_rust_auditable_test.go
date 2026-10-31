package integration_test

import (
	"bytes"
	"compress/zlib"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
)

const rustAuditTestPath = "usr/bin/uv"

func rustAuditTestELF(t *testing.T, payload string) []byte {
	t.Helper()
	var compressed bytes.Buffer
	writer := zlib.NewWriter(&compressed)
	if _, err := writer.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	strtab := []byte("\x00.shstrtab\x00.dep-v0\x00")
	depOffset := 64 + len(strtab)
	sectionOffset := (depOffset + compressed.Len() + 7) &^ 7
	data := make([]byte, sectionOffset+3*64)
	copy(data[:4], "\x7fELF")
	data[4], data[5], data[6] = 2, 1, 1            // ELF64, little endian, version 1.
	binary.LittleEndian.PutUint16(data[16:18], 2)  // ET_EXEC.
	binary.LittleEndian.PutUint16(data[18:20], 62) // x86-64.
	binary.LittleEndian.PutUint32(data[20:24], 1)
	binary.LittleEndian.PutUint64(data[40:48], uint64(sectionOffset))
	binary.LittleEndian.PutUint16(data[52:54], 64)
	binary.LittleEndian.PutUint16(data[58:60], 64)
	binary.LittleEndian.PutUint16(data[60:62], 3)
	binary.LittleEndian.PutUint16(data[62:64], 1)
	copy(data[64:], strtab)
	copy(data[depOffset:], compressed.Bytes())
	shstr := data[sectionOffset+64 : sectionOffset+128]
	binary.LittleEndian.PutUint32(shstr[0:4], 1)
	binary.LittleEndian.PutUint32(shstr[4:8], 3) // SHT_STRTAB.
	binary.LittleEndian.PutUint64(shstr[24:32], 64)
	binary.LittleEndian.PutUint64(shstr[32:40], uint64(len(strtab)))
	dep := data[sectionOffset+128 : sectionOffset+192]
	binary.LittleEndian.PutUint32(dep[0:4], 11)
	binary.LittleEndian.PutUint32(dep[4:8], 1) // SHT_PROGBITS.
	binary.LittleEndian.PutUint64(dep[24:32], uint64(depOffset))
	binary.LittleEndian.PutUint64(dep[32:40], uint64(compressed.Len()))
	return data
}

func TestOCIRustAuditableRuntimeGraph(t *testing.T) {
	payload := `{"format":1,"packages":[{"name":"uv","version":"0.13.4","source":"local","root":true,"dependencies":[1,2,3]},{"name":"adler2","version":"2.0.1","source":"crates.io","dependencies":[3]},{"name":"build-helper","version":"1.0.0","source":"crates.io","kind":"build","dependencies":[4]},{"name":"libc","version":"0.2.177","source":"crates.io"},{"name":"build-sub","version":"1.0.0","source":"crates.io"}]}`
	binaryData := rustAuditTestELF(t, payload)
	layout := ociTestLayout(t)
	image := ociTestImage(t, layout, "linux", "amd64", []ociTestLayer{{entries: []ociTestEntry{{name: rustAuditTestPath, data: binaryData}}}})
	ociTestIndex(t, layout, image)
	doc, output, code := ociTestScan(t, layout)
	if code != 0 || doc.Coverage.Packages != 3 || doc.Coverage.Edges != 4 || doc.Coverage.GraphState != "partial" || doc.Coverage.OriginState != "partial" {
		t.Fatalf("Rust audit runtime graph incorrect: code=%d output=%s coverage=%#v", code, output, doc.Coverage)
	}
	hash := sha256.Sum256(binaryData)
	wantDigest := "sha256:" + hex.EncodeToString(hash[:])
	want := map[string]bool{"uv@0.13.4": false, "adler2@2.0.1": false, "libc@0.2.177": false}
	for _, component := range doc.Components {
		key := component.Name + "@" + component.Version
		if _, found := want[key]; !found || component.Evidence[0].InputDigest != wantDigest || !strings.HasSuffix(component.Evidence[0].InputPath, "!/"+rustAuditTestPath) {
			t.Fatalf("Rust audit identity or evidence incorrect: %#v", component)
		}
		if component.Name == "uv" && (component.Kind != "application" || len(component.Hashes) != 1 || component.Hashes[0].Content != hex.EncodeToString(hash[:])) {
			t.Fatalf("Rust executable identity incorrect: %#v", component)
		}
		if component.Name == "adler2" && component.PURL != "pkg:cargo/adler2@2.0.1" {
			t.Fatalf("Rust crate PURL incorrect: %#v", component)
		}
		want[key] = true
	}
	for key, found := range want {
		if !found {
			t.Fatalf("Rust package missing: %s", key)
		}
	}
}

func TestOCIRustAuditableOverlayAndRejectedGraphs(t *testing.T) {
	valid := `{"format":1,"packages":[{"name":"uv","version":"0.13.4","source":"local","root":true,"dependencies":[1]},{"name":"adler2","version":"2.0.1","source":"crates.io"}]}`
	for _, test := range []struct {
		name      string
		upper     ociTestEntry
		want      int
		wantIssue string
	}{
		{name: "whiteout", upper: ociTestEntry{name: "usr/bin/.wh.uv"}, want: 0},
		{name: "replacement", upper: ociTestEntry{name: rustAuditTestPath, data: rustAuditTestELF(t, strings.Replace(valid, "0.13.4", "0.13.5", 1))}, want: 2},
		{name: "legacy_format", upper: ociTestEntry{name: rustAuditTestPath, data: rustAuditTestELF(t, strings.Replace(valid, `"format":1,`, "", 1))}, want: 0, wantIssue: "rust_auditable_legacy_ambiguous"},
		{name: "cycle", upper: ociTestEntry{name: rustAuditTestPath, data: rustAuditTestELF(t, strings.Replace(valid, `"source":"crates.io"}`, `"source":"crates.io","dependencies":[0]}`, 1))}, want: 0, wantIssue: "rust_auditable_invalid"},
		{name: "bad_index", upper: ociTestEntry{name: rustAuditTestPath, data: rustAuditTestELF(t, strings.Replace(valid, `"dependencies":[1]`, `"dependencies":[9]`, 1))}, want: 0, wantIssue: "rust_auditable_invalid"},
	} {
		t.Run(test.name, func(t *testing.T) {
			layout := ociTestLayout(t)
			image := ociTestImage(t, layout, "linux", "amd64", []ociTestLayer{
				{entries: []ociTestEntry{{name: rustAuditTestPath, data: rustAuditTestELF(t, valid)}}},
				{entries: []ociTestEntry{test.upper}},
			})
			ociTestIndex(t, layout, image)
			doc, output, code := ociTestScan(t, layout)
			if code != 0 || len(doc.Components) != test.want {
				t.Fatalf("Rust audit overlay incorrect: code=%d output=%s components=%#v", code, output, doc.Components)
			}
			if test.name == "replacement" {
				if doc.Components[0].Name != "uv" && doc.Components[1].Name != "uv" {
					t.Fatalf("Rust replacement root missing: %#v", doc.Components)
				}
				for _, component := range doc.Components {
					if component.Name == "uv" && component.Version != "0.13.5" {
						t.Fatalf("stale Rust binary survived replacement: %#v", component)
					}
				}
			}
			if test.wantIssue != "" {
				found := false
				for _, issue := range doc.Coverage.Issues {
					found = found || issue.Code == test.wantIssue
				}
				if !found {
					t.Fatalf("Rust audit failure not reported: %#v", doc.Coverage.Issues)
				}
			}
		})
	}
}
