package oci

import "testing"

func TestMemcachedVersionRejectsConflictingWireResponse(t *testing.T) {
	data := []byte("\x00memcached 1.6.45\x00\x00memcached 1.6.45\n\x00\x00VERSION 1.6.45\x00\x00VERSION 1.6.44\x00")
	if version, _, ok := memcachedVersionInROData(data); ok || version != "" {
		t.Fatalf("conflicting wire version identified a server: %q", version)
	}
}
