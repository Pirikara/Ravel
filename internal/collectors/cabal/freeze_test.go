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

func TestFreezeIndexStateWithoutPins(t *testing.T) {
	for _, data := range []string{"index-state: HEAD\n", "index-state: hackage.haskell.org 2026-01-02T03:04:05Z\n", "index-state:\n  hackage.haskell.org 2026-01-02T03:04:05Z\n"} {
		filename := filepath.Join(t.TempDir(), "cabal.project.freeze")
		if err := os.WriteFile(filename, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
		doc, err := CollectFreeze(filename, "sample")
		if err != nil || len(doc.Components) != 0 || len(doc.Edges) != 0 || doc.Coverage.GraphState != "partial" {
			t.Fatalf("index-only freeze: %#v %v", doc, err)
		}
		found := false
		for _, issue := range doc.Coverage.Issues {
			found = found || issue.Code == "cabal_freeze_version_pins_unavailable"
		}
		if !found {
			t.Fatal("index-only freeze silently presented as package inventory")
		}
	}
}

func TestFreezeRequiresRecognizedField(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "cabal.project.freeze")
	if err := os.WriteFile(filename, []byte("unrecognized: value\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := CollectFreeze(filename, "sample"); err == nil {
		t.Fatal("file without a recognized freeze field was accepted")
	}
}
