package oci

import (
	"bytes"
	"testing"
)

func TestDenoVersionAcrossReadWindows(t *testing.T) {
	prefix := bytes.Repeat([]byte{'x'}, 64<<10-12)
	signature := []byte("2.9.82.9.8+fe7ed01Deno/2.9.8Deno/2.9.8+fe7ed01")
	data := append(prefix, signature...)
	version, offset, err := denoVersionInROData(bytes.NewReader(data), int64(len(data)))
	if err != nil || version != "2.9.8" || offset != int64(len(prefix)+len("2.9.82.9.8+fe7ed01Deno/")) {
		t.Fatalf("split Deno evidence was not recognized: version=%q offset=%d err=%v", version, offset, err)
	}
	data = append(data, []byte("\x00"+"2.8.32.8.3+ba69908Deno/2.8.3Deno/2.8.3+ba69908")...)
	version, _, err = denoVersionInROData(bytes.NewReader(data), int64(len(data)))
	if err != nil || version != "" {
		t.Fatalf("conflicting Deno evidence was reported: version=%q err=%v", version, err)
	}
}
