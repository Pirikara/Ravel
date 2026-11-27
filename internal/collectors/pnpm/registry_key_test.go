package pnpm

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRegistryPrefixedPackageKeys(t *testing.T) {
	for _, tc := range []struct {
		key, name, version, host string
		valid                    bool
	}{
		{"registry.npmjs.org/core@1.0.0", "core", "1.0.0", "registry.npmjs.org", true},
		{"mirror.example.test/@team/core@2.0.0", "@team/core", "2.0.0", "mirror.example.test", true},
		{"localhost:4873/core@1.0.0", "core", "1.0.0", "localhost:4873", true},
		{"registry/core@1.0.0", "core", "1.0.0", "registry", true},
		{"../core@1.0.0", "", "", "", false},
		{"@team/core@1.0.0", "", "", "", false},
		{"user@mirror.example.test/core@1.0.0", "", "", "", false},
		{"mirror.example.test/", "", "", "", false},
	} {
		name, version, host, ok := splitRegistryPackage(tc.key)
		if ok != tc.valid || ok && (name != tc.name || version != tc.version || host != tc.host) {
			t.Fatalf("%s: %s %s %s %t", tc.key, name, version, host, ok)
		}
	}
}

func TestMismatchedDirectoryMetadataIsNotAnArchive(t *testing.T) {
	pkg := packageEntry{Version: "1.0.0"}
	pkg.Resolution.Type = "directory"
	pkg.Resolution.Directory = "different"
	if _, ok := identifyPackage("site@file:packages/site", pkg); ok {
		t.Fatal("directory mismatch was silently treated as an archive")
	}
}

func TestV5PeerDialectRemainsExplicitlyUnsupported(t *testing.T) {
	file := filepath.Join(t.TempDir(), "pnpm-lock.yaml")
	if err := os.WriteFile(file, []byte("lockfileVersion: '5.4'\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Collect(file, "test"); err == nil || !strings.Contains(err.Error(), "unsupported pnpm lockfile version") {
		t.Fatalf("unsupported format was not explicit: %v", err)
	}
}
