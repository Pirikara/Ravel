package oci

import (
	"bytes"
	"testing"
)

func TestHTTPDVersionRequiresNearbyStrings(t *testing.T) {
	data := []byte("\x00Server version: %s\n\x00\x00Apache/2.4.69\x00")
	data = append(data, bytes.Repeat([]byte{'x'}, 600)...)
	data = append(data, []byte("\x00Apache/2.4.69 (Unix)\x00")...)
	if version, _, ok := httpdVersionInROData(data); ok || version != "" {
		t.Fatalf("distant Apache strings identified a server: %q", version)
	}
}
