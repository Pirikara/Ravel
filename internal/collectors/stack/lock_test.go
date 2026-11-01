package stack

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStackRejectsAliasesAndInvalidInput(t *testing.T) {
	for _, data := range []string{
		"packages: &packages []\nsnapshots: *packages\n",
		"packages: [\n",
		"something: else\n",
	} {
		filename := filepath.Join(t.TempDir(), "stack.yaml.lock")
		if err := os.WriteFile(filename, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := CollectLock(filename, "sample"); err == nil {
			t.Fatalf("invalid Stack lockfile accepted: %s", data)
		}
	}
}

func TestStackSkipsUnsafeGitSubdir(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "stack.yaml.lock")
	data := []byte("packages:\n- completed:\n    git: https://example.invalid/repo.git\n    commit: abcdef0123456789\n    name: sample\n    version: 1.0.0\n    subdir: ../outside\nsnapshots: []\n")
	if err := os.WriteFile(filename, data, 0o644); err != nil {
		t.Fatal(err)
	}
	doc, err := CollectLock(filename, "sample")
	if err != nil || doc.Coverage.Packages != 0 || len(doc.Coverage.Issues) == 0 {
		t.Fatalf("unsafe Stack subdir was accepted: %#v %v", doc, err)
	}
}
