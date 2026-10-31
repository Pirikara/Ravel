package oci

import (
	"encoding/binary"
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
