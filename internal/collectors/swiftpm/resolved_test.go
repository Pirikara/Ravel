package swiftpm

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolvedSwiftIdentityAndJSONEvidence(t *testing.T) {
	dir := t.TempDir()
	manifest := filepath.Join(dir, "Package.swift")
	if err := os.WriteFile(manifest, []byte("// swift-tools-version: 6.0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	graph := `{"identity":"app","name":"App","dependencies":[{"identity":"released","name":"DisplayLibrary","url":"https://code.example.test/Acme/Released.git","version":"1.2.3","dependencies":[]},{"identity":"unversioned","name":"Unversioned","url":"https://code.example.test/Acme/Unversioned.git","version":"unspecified","dependencies":[]}]}` + "\n"
	bin := t.TempDir()
	script := "#!/bin/sh\nwhile [ \"$#\" -gt 0 ]; do\nif [ \"$1\" = '--output-path' ]; then\nshift\ncat > \"$1\" <<'RAVEL_GRAPH'\n" + graph + "RAVEL_GRAPH\nexit 0\nfi\nshift\ndone\nexit 1\n"
	if err := os.WriteFile(filepath.Join(bin, "swift"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	doc, err := CollectResolved(manifest, "App", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Components) != 2 || len(doc.Edges) != 2 {
		t.Fatal(doc)
	}
	digest := fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(graph)))
	for _, c := range doc.Components {
		if c.Name == "DisplayLibrary" && !strings.HasPrefix(c.PURL, "pkg:swift/code.example.test/Acme/Released@1.2.3?") {
			t.Fatal("known resolver identity missing", c)
		}
		if c.Name == "Unversioned" && (c.PURL != "" || c.Version != "") {
			t.Fatal("resolver invented a versioned identity", c)
		}
		for _, e := range c.Evidence {
			if e.InputPath != swiftGraphEvidenceSource || e.InputDigest != digest || e.Method != "resolver-output" {
				t.Fatal("resolver evidence identifies manifest bytes instead of graph JSON", e)
			}
		}
	}
	for _, e := range doc.Edges {
		if e.Evidence.InputPath != swiftGraphEvidenceSource || e.Evidence.InputDigest != digest {
			t.Fatal("dependency evidence lost resolver JSON", e)
		}
	}
	for _, o := range doc.Origins {
		if o.Kind != "vcs" || o.VCSType != "git" {
			t.Fatal(o)
		}
	}
}
