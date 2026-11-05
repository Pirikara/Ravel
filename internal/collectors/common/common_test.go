package common

import "testing"

func TestDefaultNpmRegistry(t *testing.T) {
	for _, tc := range []struct {
		resolved string
		want     bool
	}{
		{"https://registry.npmjs.org/is-number/-/is-number-7.0.0.tgz", true},
		{"registry.npmjs.org", true},
		{"https://registry.yarnpkg.com/is-number/-/is-number-7.0.0.tgz", true},
		{"registry.yarnpkg.com", true},
		{"https://registry.npmjs.org.evil.test/is-number/-/is-number-7.0.0.tgz", false},
		{"https://registry.yarnpkg.com.evil.test/is-number/-/is-number-7.0.0.tgz", false},
		{"https://registry.example.test/is-number/-/is-number-7.0.0.tgz", false},
		{"https://registry.yarnpkg.com/other/path", false},
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

func TestPURLVersion(t *testing.T) {
	if got := PURLVersion("v3.5.1+incompatible"); got != "v3.5.1%2Bincompatible" {
		t.Fatalf("plus was not encoded: %q", got)
	}
	if got := GoModulePURL("github.com/blang/semver", "v3.5.1+incompatible"); got != "pkg:golang/github.com/blang/semver@v3.5.1%2Bincompatible" {
		t.Fatalf("Go PURL version is not canonical: %q", got)
	}
}
