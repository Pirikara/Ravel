package oci

import "testing"

func TestHAProxyVersionRejectsAmbiguousBuilds(t *testing.T) {
	data := []byte("\x00HAProxy version %s %s - https://haproxy.org/\n\x00" +
		"\x003.4.7-8872a26\x00\x00haproxy_server_\x00" +
		"\x003.4.7-8872a27\x00\x00haproxy_server_\x00" +
		"\x00HAProxy's dummy HTTP server for benchmarks - version 3.4.7-8872a26.")
	if version, revision, _, ok := haproxyVersionInROData(data); ok || version != "" || revision != "" {
		t.Fatalf("conflicting HAProxy builds identified a server: %q %q", version, revision)
	}
}
