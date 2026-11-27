package pnpm

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Pirikara/Ravel/internal/collectors/common"
	"github.com/Pirikara/Ravel/internal/model"
)

func TestLocalIdentityRemainsWithinProject(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "local"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "local", "package.json"), []byte(`{"name":"local","version":"1.2.3"}`), 0600); err != nil {
		t.Fatal(err)
	}
	for _, sample := range []struct {
		directory, name string
		valid           bool
	}{
		{"local", "local", true}, {"local", "different", false}, {"missing", "local", false}, {"../outside", "local", false},
	} {
		doc := common.NewDocument(filepath.Join(root, "pnpm-lock.yaml"), "test", "pnpm", nil)
		component := model.Component{ID: "pkg", Name: sample.name, Kind: "application"}
		got := collectLocalIdentity(&doc, filepath.Join(root, "pnpm-lock.yaml"), sample.directory, &component)
		if got != sample.valid || got && component.Version != "1.2.3" {
			t.Fatal(sample, component)
		}
		if component.PURL != "" || len(doc.Origins) != 0 {
			t.Fatal("local identity became a registry assertion")
		}
	}
}
