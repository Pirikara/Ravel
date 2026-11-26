package deno

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVersionTwoNormalizationBoundaries(t *testing.T) {
	for _, sample := range []struct {
		name, input string
		valid       bool
	}{
		{"scoped", `{"npm":{"specifiers":{"@sample/lib@^1":"@sample/lib@1.2.3"},"packages":{"@sample/lib@1.2.3":{"dependencies":{}}}}}`, true},
		{"remote-only", `{"remote":{"https://example.test/mod.ts":"digest"}}`, true},
		{"bad-pin", `{"npm":{"specifiers":{"lib@^1":"not-a-pin"}}}`, false},
		{"wrong-dependencies", `{"npm":{"packages":{"lib@1.0.0":{"dependencies":["other@1.0.0"]}}}}`, false},
		{"wrong-npm-shape", `{"npm":[]}`, false},
	} {
		t.Run(sample.name, func(t *testing.T) {
			lock := lockfile{Remote: map[string]string{"https://example.test/mod.ts": "digest"}}
			err := normalizeV2(&lock, []byte(sample.input))
			if (err == nil) != sample.valid {
				t.Fatal(err)
			}
			if sample.name == "scoped" && (lock.Specifiers["npm:@sample/lib@^1"] != "1.2.3" || len(lock.NPM) != 1) {
				t.Fatal(lock)
			}
			if lock.Remote["https://example.test/mod.ts"] != "digest" {
				t.Fatal("remote records changed")
			}
		})
	}
}

func TestUnsupportedDenoVersionStillRejected(t *testing.T) {
	file := filepath.Join(t.TempDir(), "deno.lock")
	if err := os.WriteFile(file, []byte(`{"version":"1"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Collect(file, "sample"); err == nil || !strings.Contains(err.Error(), "unsupported deno.lock version") {
		t.Fatal(err)
	}
}

func TestVersionTwoSpecifierNamedDependencies(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "deno.lock")
	lock := `{"version":"2","npm":{"specifiers":{"dependencies":"dependencies@1.2.3"},"packages":{"dependencies@1.2.3":{"dependencies":{}}}}}`
	if err := os.WriteFile(file, []byte(lock), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "main.ts"), []byte(`import "npm:dependencies";`), 0600); err != nil {
		t.Fatal(err)
	}
	doc, err := Collect(file, "sample")
	if err != nil || len(doc.Components) != 1 || doc.Components[0].Name != "dependencies" {
		t.Fatal(err, doc.Components)
	}
}
