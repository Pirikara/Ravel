package oci

import (
	"bytes"
	"encoding/binary"
	"math/bits"
	"os"
	"path/filepath"
	"testing"
)

func TestManagedAssemblyHeaders(t *testing.T) {
	fixture, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "oci", "dotnet-managed-assembly", "Acme.Runtime.dll"))
	if err != nil {
		t.Fatal(err)
	}
	if !isManagedAssembly(fixture) || inspectDotnetAssembly(fixture).digest == "" {
		t.Fatal("generated .NET assembly was not recognized")
	}
	if state := inspectDotnetAssembly(fixture); state.name != "Acme.Runtime" || state.version != "1.2.3" {
		t.Fatalf("generated VERSIONINFO was not read: %#v", state)
	}
	for _, tc := range []struct {
		name   string
		change func([]byte)
	}{
		{"resource outside file", func(data []byte) {
			pe := binary.LittleEndian.Uint32(data[0x3c:])
			binary.LittleEndian.PutUint32(data[pe+24+96+2*8:], ^uint32(0))
		}},
		{"resource too large", func(data []byte) {
			pe := binary.LittleEndian.Uint32(data[0x3c:])
			binary.LittleEndian.PutUint32(data[pe+24+96+2*8+4:], 1<<20+1)
		}},
		{"invalid version root", func(data []byte) {
			key := bytes.Index(data, []byte{'V', 0, 'S', 0, '_', 0, 'V', 0})
			if key < 6 {
				t.Fatal("fixture has no version resource")
			}
			binary.LittleEndian.PutUint16(data[key-6:], 0)
		}},
		{"invalid fixed signature", func(data []byte) {
			signature := bytes.Index(data, []byte{0xbd, 0x04, 0xef, 0xfe})
			if signature < 0 {
				t.Fatal("fixture has no VS_FIXEDFILEINFO signature")
			}
			data[signature] = 0
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := append([]byte(nil), fixture...)
			tc.change(data)
			if name, version := managedPEVersion(data); name != "" || version != "" {
				t.Fatalf("malformed VERSIONINFO was accepted: %q %q", name, version)
			}
		})
	}
	for _, tc := range []struct {
		name   string
		change func([]byte) []byte
	}{
		{"short DOS", func(data []byte) []byte { return data[:63] }},
		{"missing MZ", func(data []byte) []byte { data[0] = 0; return data }},
		{"PE offset outside file", func(data []byte) []byte { binary.LittleEndian.PutUint32(data[0x3c:], ^uint32(0)); return data }},
		{"section count too large", func(data []byte) []byte {
			pe := binary.LittleEndian.Uint32(data[0x3c:])
			binary.LittleEndian.PutUint16(data[pe+6:], 97)
			return data
		}},
		{"missing CLR directory", func(data []byte) []byte {
			pe := binary.LittleEndian.Uint32(data[0x3c:])
			optional := pe + 24
			binary.LittleEndian.PutUint32(data[optional+96+14*8:], 0)
			return data
		}},
		{"missing Assembly table", func(data []byte) []byte {
			mask := assemblyTableMaskOffset(t, data)
			valid := binary.LittleEndian.Uint64(data[mask:])
			binary.LittleEndian.PutUint64(data[mask:], valid&^(uint64(1)<<32))
			return data
		}},
		{"empty Assembly table", func(data []byte) []byte {
			mask := assemblyTableMaskOffset(t, data)
			valid := binary.LittleEndian.Uint64(data[mask:])
			row := mask + 16 + 4*bits.OnesCount64(valid&((uint64(1)<<32)-1))
			binary.LittleEndian.PutUint32(data[row:], 0)
			return data
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := tc.change(append([]byte(nil), fixture...))
			if isManagedAssembly(data) || inspectDotnetAssembly(data).status != "invalid" {
				t.Fatal("malformed PE was accepted")
			}
		})
	}
	for length := 0; length < len(fixture); length++ {
		// Every truncation must be safe; a complete metadata section can
		// legitimately precede unrelated bytes at the end of the PE file.
		isManagedAssembly(fixture[:length])
	}
}

func assemblyTableMaskOffset(t *testing.T, data []byte) int {
	t.Helper()
	root := bytes.Index(data, []byte("BSJB"))
	if root < 0 {
		t.Fatal("fixture has no CLI metadata root")
	}
	versionSize := binary.LittleEndian.Uint32(data[root+12:])
	streamHeader := root + 16 + int((versionSize+3)&^uint32(3))
	count := int(binary.LittleEndian.Uint16(data[streamHeader+2:]))
	current := streamHeader + 4
	for i := 0; i < count; i++ {
		nameStart := current + 8
		nameEnd := nameStart + bytes.IndexByte(data[nameStart:], 0)
		if string(data[nameStart:nameEnd]) == "#~" {
			return root + int(binary.LittleEndian.Uint32(data[current:])) + 8
		}
		current = nameStart + ((nameEnd - nameStart + 4) &^ 3)
	}
	t.Fatal("fixture has no #~ metadata tables stream")
	return 0
}
