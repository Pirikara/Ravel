package oci

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func testELF64WithSectionNames() []byte {
	data := make([]byte, 208)
	copy(data, "\x7fELF")
	data[4], data[5], data[6] = 2, 1, 1
	binary.LittleEndian.PutUint64(data[40:48], 64)    // section table offset
	binary.LittleEndian.PutUint16(data[58:60], 64)    // section header size
	binary.LittleEndian.PutUint16(data[60:62], 2)     // section count
	binary.LittleEndian.PutUint16(data[62:64], 1)     // section-name index
	binary.LittleEndian.PutUint64(data[152:160], 192) // section-name data offset
	binary.LittleEndian.PutUint64(data[160:168], 16)  // section-name data size
	copy(data[192:], "\x00.shstrtab\x00")
	return data
}

func TestGoBuildInfoMagicStreamAcrossChunks(t *testing.T) {
	for _, test := range []struct {
		data []byte
		want bool
	}{
		{data: bytes.Repeat([]byte("x"), 70000), want: false},
		{data: append(append(bytes.Repeat([]byte("x"), (32<<10)-2), []byte(goBuildInfoMagic)...), bytes.Repeat([]byte("y"), 40000)...), want: true},
	} {
		found, err := hasGoBuildInfoMagic(bytes.NewReader(test.data), int64(len(test.data)))
		if err != nil || found != test.want {
			t.Fatalf("streamed Go marker detection incorrect: found=%t want=%t err=%v", found, test.want, err)
		}
	}
}

func TestGuardELFMetadataBoundsSectionNames(t *testing.T) {
	if err := guardELFMetadata(testELF64WithSectionNames()); err != nil {
		t.Fatalf("valid bounded ELF header rejected: %v", err)
	}
	for _, test := range []struct {
		name   string
		change func([]byte)
	}{
		{name: "compressed_names", change: func(data []byte) { binary.LittleEndian.PutUint64(data[136:144], 0x800) }},
		{name: "oversized_names", change: func(data []byte) { binary.LittleEndian.PutUint64(data[160:168], maxELFSectionNames+1) }},
		{name: "truncated_section_table", change: func(data []byte) { binary.LittleEndian.PutUint64(data[40:48], 200) }},
		{name: "extended_index", change: func(data []byte) { binary.LittleEndian.PutUint16(data[62:64], 0xffff) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			data := testELF64WithSectionNames()
			test.change(data)
			if err := guardELFMetadata(data); err == nil {
				t.Fatal("malformed ELF metadata accepted")
			}
		})
	}
}

func TestInspectGoBinaryIgnoresELFWithoutBuildInfo(t *testing.T) {
	doc, recognized, err := inspectGoBinary(testELF64WithSectionNames(), "oci:sha256:test!/bin/native", "fixture", "bin/native")
	if err != nil || recognized || len(doc.Components) != 0 {
		t.Fatalf("ordinary ELF treated as Go binary: recognized=%t err=%v doc=%#v", recognized, err, doc)
	}
	if !isELFMagic([]byte("\x7fELF")) || isELFMagic([]byte("\x7fELX")) {
		t.Fatal("ELF magic detection incorrect")
	}
}
