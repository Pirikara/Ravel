package cabal

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFreezeNoFinalNewline(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "cabal.project.freeze")
	if err := os.WriteFile(filename, []byte("constraints: any.foo ==1.2.3"), 0o644); err != nil {
		t.Fatal(err)
	}
	doc, err := CollectFreeze(filename, "sample")
	if err != nil || doc.Coverage.Packages != 1 || doc.Components[0].Name != "foo" || doc.Components[0].Version != "1.2.3" {
		t.Fatalf("Cabal final constraint: %#v %v", doc, err)
	}
}

func TestFreezeRequiresConstraints(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "cabal.project.freeze")
	if err := os.WriteFile(filename, []byte("index-state: HEAD\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := CollectFreeze(filename, "sample"); err == nil {
		t.Fatal("freeze file without constraints was accepted")
	}
}
