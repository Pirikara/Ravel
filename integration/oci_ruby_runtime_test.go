package integration_test

import (
	"archive/tar"
	"encoding/binary"
	"strings"
	"testing"
)

const ociRubyRuntimePath = "usr/local/lib/libruby.so.3.3.12"

func ociTestRubyRuntimeELF(version string) []byte {
	data := make([]byte, 1024)
	copy(data, "\x7fELF")
	data[4], data[5], data[6] = 2, 1, 1
	binary.LittleEndian.PutUint16(data[16:18], 3)  // ET_DYN
	binary.LittleEndian.PutUint16(data[18:20], 62) // x86-64
	binary.LittleEndian.PutUint32(data[20:24], 1)
	binary.LittleEndian.PutUint64(data[40:48], 640)
	binary.LittleEndian.PutUint16(data[52:54], 64)
	binary.LittleEndian.PutUint16(data[58:60], 64)
	binary.LittleEndian.PutUint16(data[60:62], 5)
	binary.LittleEndian.PutUint16(data[62:64], 4)
	copy(data[256:], "\x00ruby_version\x00")
	copy(data[400:], version+"\x00")
	copy(data[512:], "\x00.dynstr\x00.dynsym\x00.rodata\x00.shstrtab\x00")
	// ELF64 symbol table: the first entry is null, the second names
	// ruby_version and points into .rodata.
	symbol := data[312:336]
	binary.LittleEndian.PutUint32(symbol[0:4], 1)
	symbol[4] = 0x11 // STB_GLOBAL | STT_OBJECT
	binary.LittleEndian.PutUint16(symbol[6:8], 3)
	binary.LittleEndian.PutUint64(symbol[8:16], 1000)
	binary.LittleEndian.PutUint64(symbol[16:24], uint64(len(version)+1))
	section := func(index int, name, typ uint32, flags, addr, offset, size uint64, link uint32, align, entrySize uint64) {
		start := 640 + index*64
		binary.LittleEndian.PutUint32(data[start:start+4], name)
		binary.LittleEndian.PutUint32(data[start+4:start+8], typ)
		binary.LittleEndian.PutUint64(data[start+8:start+16], flags)
		binary.LittleEndian.PutUint64(data[start+16:start+24], addr)
		binary.LittleEndian.PutUint64(data[start+24:start+32], offset)
		binary.LittleEndian.PutUint64(data[start+32:start+40], size)
		binary.LittleEndian.PutUint32(data[start+40:start+44], link)
		binary.LittleEndian.PutUint64(data[start+48:start+56], align)
		binary.LittleEndian.PutUint64(data[start+56:start+64], entrySize)
	}
	section(1, 1, 3, 2, 256, 256, 14, 0, 1, 0)   // .dynstr
	section(2, 9, 11, 2, 288, 288, 48, 1, 8, 24) // .dynsym
	section(3, 17, 1, 2, 1000, 400, 64, 0, 1, 0) // .rodata
	section(4, 25, 3, 0, 0, 512, 35, 0, 1, 0)    // .shstrtab
	return data
}

func TestOCIRubyRuntimeLibraryEvidenceAndOverlay(t *testing.T) {
	wrongVersion := ociTestRubyRuntimeELF("3.3.11")
	missingSymbol := ociTestRubyRuntimeELF("3.3.12")
	copy(missingSymbol[257:269], "fake_version")
	duplicateSymbol := ociTestRubyRuntimeELF("3.3.12")
	copy(duplicateSymbol[336:360], duplicateSymbol[312:336])
	binary.LittleEndian.PutUint64(duplicateSymbol[800:808], 72) // .dynsym size
	compressedStrings := ociTestRubyRuntimeELF("3.3.12")
	binary.LittleEndian.PutUint64(compressedStrings[712:720], 0x802) // .dynstr flags
	for _, test := range []struct {
		name      string
		upper     []ociTestEntry
		want      bool
		wantIssue string
	}{
		{name: "base", want: true},
		{name: "whiteout", upper: []ociTestEntry{{name: "usr/local/lib/.wh.libruby.so.3.3.12"}}},
		{name: "invalid_replacement", upper: []ociTestEntry{{name: ociRubyRuntimePath, data: []byte("not ELF")}}, wantIssue: "ruby_runtime_invalid"},
		{name: "wrong_version", upper: []ociTestEntry{{name: ociRubyRuntimePath, data: wrongVersion}}, wantIssue: "ruby_runtime_invalid"},
		{name: "missing_symbol", upper: []ociTestEntry{{name: ociRubyRuntimePath, data: missingSymbol}}, wantIssue: "ruby_runtime_invalid"},
		{name: "duplicate_symbol", upper: []ociTestEntry{{name: ociRubyRuntimePath, data: duplicateSymbol}}, wantIssue: "ruby_runtime_invalid"},
		{name: "compressed_dynamic_strings", upper: []ociTestEntry{{name: ociRubyRuntimePath, data: compressedStrings}}, wantIssue: "ruby_runtime_invalid"},
		{name: "symlink_replacement", upper: []ociTestEntry{{name: ociRubyRuntimePath, typeflag: tar.TypeSymlink, linkname: "/outside"}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			layout := ociTestLayout(t)
			layers := []ociTestLayer{{entries: []ociTestEntry{{name: ociRubyRuntimePath, data: ociTestRubyRuntimeELF("3.3.12")}}}}
			if test.upper != nil {
				layers = append(layers, ociTestLayer{entries: test.upper})
			}
			image := ociTestImage(t, layout, "linux", "amd64", layers)
			ociTestIndex(t, layout, image)
			doc, output, code := ociTestScan(t, layout)
			if code != 0 {
				t.Fatalf("Ruby runtime scan failed: code=%d output=%s", code, output)
			}
			if test.want {
				if len(doc.Components) != 1 || doc.Components[0].Name != "ruby" || doc.Components[0].Version != "3.3.12" || len(doc.Components[0].Hashes) != 1 || !strings.Contains(doc.Components[0].Context, "runtime=cruby;image=linux/amd64") || doc.Components[0].Evidence[0].Pointer != "elf/offset/400" {
					t.Fatalf("Ruby runtime identity or evidence incorrect: %#v", doc.Components)
				}
			} else if len(doc.Components) != 0 {
				t.Fatalf("removed or invalid Ruby runtime remained: %#v", doc.Components)
			}
			if test.wantIssue != "" {
				found := false
				for _, issue := range doc.Coverage.Issues {
					found = found || issue.Code == test.wantIssue
				}
				if !found {
					t.Fatalf("Ruby runtime issue missing: %#v", doc.Coverage.Issues)
				}
			}
		})
	}
}

func TestOCIRubyRuntimeUnderSameLayerSymlinkRejected(t *testing.T) {
	layout := ociTestLayout(t)
	image := ociTestImage(t, layout, "linux", "amd64", []ociTestLayer{{entries: []ociTestEntry{
		{name: "usr/local/lib", typeflag: tar.TypeSymlink, linkname: "/outside"},
		{name: ociRubyRuntimePath, data: ociTestRubyRuntimeELF("3.3.12")},
	}}})
	ociTestIndex(t, layout, image)
	_, output, code := ociTestScan(t, layout)
	if code != 1 || !strings.Contains(output, "non-directory entry") {
		t.Fatalf("Ruby runtime beneath symlink accepted: code=%d output=%s", code, output)
	}
}

func TestOCIRubyRuntimeAndInstalledGemTogether(t *testing.T) {
	layout := ociTestLayout(t)
	image := ociTestImage(t, layout, "linux", "amd64", []ociTestLayer{{entries: []ociTestEntry{
		{name: ociRubyRuntimePath, data: ociTestRubyRuntimeELF("3.3.12")},
		{name: ociRubyDefaultSpec, data: ociTestInstalledRubySpec("uri", "0.13.3", "ruby")},
	}}})
	ociTestIndex(t, layout, image)
	doc, output, code := ociTestScan(t, layout)
	if code != 0 || len(doc.Components) != 2 {
		t.Fatalf("Ruby runtime and gem were not both inventoried: code=%d output=%s components=%#v", code, output, doc.Components)
	}
	got := map[string]string{}
	for _, component := range doc.Components {
		got[component.Name] = component.Version
	}
	if got["ruby"] != "3.3.12" || got["uri"] != "0.13.3" {
		t.Fatalf("Ruby runtime or gem identity incorrect: %#v", got)
	}
}
