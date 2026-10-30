package common

import "testing"

func TestDefaultNpmRegistry(t *testing.T) {
	for _, tc := range []struct {
		resolved string
		want     bool
	}{
		{"https://registry.npmjs.org/is-number/-/is-number-7.0.0.tgz", true},
		{"registry.npmjs.org", true},
		{"https://registry.npmjs.org.evil.test/is-number/-/is-number-7.0.0.tgz", false},
		{"https://registry.example.test/is-number/-/is-number-7.0.0.tgz", false},
		{"file:../local-package", false},
		{"https://registry.npmjs.org/other/path", false},
	} {
		if got := DefaultNpmRegistry(tc.resolved); got != tc.want {
			t.Fatalf("DefaultNpmRegistry(%q) = %v, want %v", tc.resolved, got, tc.want)
		}
	}
	if got := NpmPURL("@scope/tool", "1.0.0"); got != "pkg:npm/%40scope/tool@1.0.0" {
		t.Fatalf("scoped npm PURL not canonical: %s", got)
	}
}
