package oci

import (
	"bytes"
	"testing"
)

func TestBunVersionAcrossReadWindows(t *testing.T) {
	prefix := bytes.Repeat([]byte{'x'}, 64<<10-10)
	data := append(prefix, []byte("\x00Bun v1.4.4 (Linux arm64)\x00")...)
	data = append(data, bytes.Repeat([]byte{'x'}, 200)...)
	data = append(data, []byte("\x00Bun/1.4.4\x00")...)
	version, offset, err := bunVersionInROData(bytes.NewReader(data), int64(len(data)), "arm64")
	if err != nil || version != "1.4.4" || offset != int64(len(prefix)+len("\x00Bun v")) {
		t.Fatalf("split Bun evidence was not recognized: version=%q offset=%d err=%v", version, offset, err)
	}
	data = append(data, []byte("\x00Bun/1.4.3\x00")...)
	version, _, err = bunVersionInROData(bytes.NewReader(data), int64(len(data)), "arm64")
	if err != nil || version != "" {
		t.Fatalf("conflicting Bun evidence was reported: version=%q err=%v", version, err)
	}
}
