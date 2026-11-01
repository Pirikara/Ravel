package conan

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReference(t *testing.T) {
	ref, err := parseReference("openssl/3.0.5@acme/stable#0123456789abcdef%1675278901.123")
	if err != nil || ref.name != "openssl" || ref.version != "3.0.5" || ref.user != "acme" || ref.channel != "stable" || ref.rrev != "0123456789abcdef" || ref.purl() != "pkg:conan/openssl@3.0.5?channel=stable&rrev=0123456789abcdef&user=acme" {
		t.Fatalf("Conan reference: %#v %v", ref, err)
	}
	for _, raw := range []string{"", "openssl", "openssl/", "/3.0.5", "openssl/3.0.5@acme", "openssl/3.0.5#", "openssl/3.0.5@acme/stable/extra", "openssl/3.0.5\nignored/9.0"} {
		if _, err := parseReference(raw); err == nil {
			t.Fatalf("invalid Conan reference accepted: %q", raw)
		}
	}
}

func TestRejectsMalformedLock(t *testing.T) {
	for _, data := range []string{
		`{"version":"0.4"}`,
		`{"version":"0.6","requires":["zlib/1.2.13"]}`,
		`{"version":"0.5","graph_lock":{"nodes":{}},"requires":[]}`,
		`{"version":"0.5","requires":[`,
	} {
		filename := filepath.Join(t.TempDir(), "conan.lock")
		if err := os.WriteFile(filename, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := Collect(filename, "sample"); err == nil {
			t.Fatalf("malformed Conan lock accepted: %s", data)
		}
	}
}
