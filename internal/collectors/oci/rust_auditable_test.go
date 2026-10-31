package oci

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"io"
	"testing"
)

type endlessZeroReader struct{}

func (endlessZeroReader) Read(data []byte) (int, error) {
	clear(data)
	return len(data), nil
}

func TestLargeRustAuditableBinaryStreams(t *testing.T) {
	payload := []byte(`{"format":1,"packages":[{"name":"uv","version":"0.13.4","source":"local","root":true,"dependencies":[1]},{"name":"adler2","version":"2.0.1","source":"crates.io"}]}`)
	var compressed bytes.Buffer
	zw := zlib.NewWriter(&compressed)
	if _, err := zw.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	names := []byte("\x00.shstrtab\x00.dep-v0\x00")
	depOffset := 64 + len(names)
	sectionsOffset := (depOffset + compressed.Len() + 7) &^ 7
	elfData := make([]byte, sectionsOffset+3*64)
	copy(elfData[:4], "\x7fELF")
	elfData[4], elfData[5], elfData[6] = 2, 1, 1
	binary.LittleEndian.PutUint16(elfData[16:18], 2)
	binary.LittleEndian.PutUint16(elfData[18:20], 62)
	binary.LittleEndian.PutUint32(elfData[20:24], 1)
	binary.LittleEndian.PutUint64(elfData[40:48], uint64(sectionsOffset))
	binary.LittleEndian.PutUint16(elfData[52:54], 64)
	binary.LittleEndian.PutUint16(elfData[58:60], 64)
	binary.LittleEndian.PutUint16(elfData[60:62], 3)
	binary.LittleEndian.PutUint16(elfData[62:64], 1)
	copy(elfData[64:], names)
	copy(elfData[depOffset:], compressed.Bytes())
	shstr := elfData[sectionsOffset+64 : sectionsOffset+128]
	binary.LittleEndian.PutUint32(shstr[0:4], 1)
	binary.LittleEndian.PutUint32(shstr[4:8], 3)
	binary.LittleEndian.PutUint64(shstr[24:32], 64)
	binary.LittleEndian.PutUint64(shstr[32:40], uint64(len(names)))
	dep := elfData[sectionsOffset+128 : sectionsOffset+192]
	binary.LittleEndian.PutUint32(dep[0:4], 11)
	binary.LittleEndian.PutUint32(dep[4:8], 1)
	binary.LittleEndian.PutUint64(dep[24:32], uint64(depOffset))
	binary.LittleEndian.PutUint64(dep[32:40], uint64(compressed.Len()))

	const size = int64(64<<20) + 1
	reader := io.MultiReader(bytes.NewReader(elfData[4:]), endlessZeroReader{})
	result, err := inspectLargeELFBinaries(elfData[:4], reader, size, "oci:sha256:layer!/usr/bin/uv", "image", "usr/bin/uv")
	if err != nil || !result.rustRecognized || result.rustError != nil || len(result.rustDocument.Components) != 2 || result.goRecognized || result.goError != nil {
		t.Fatalf("large Rust ELF was not streamed and inventoried: result=%#v err=%v", result, err)
	}
}
