package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestScanDirectoriesSkipsGeneratedAndFixtureTrees(t *testing.T) {
	root := t.TempDir()
	for _, relative := range []string{
		"Gemfile.lock",
		"gems/example/Gemfile.lock",
		"tmp/tests/Gemfile.lock",
		"spec/fixtures/example/Gemfile.lock",
	} {
		path := filepath.Join(root, relative)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("fixture"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	got, err := scanDirectories(root)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{root, filepath.Join(root, "gems/example")}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("scan directories = %q, want %q", got, want)
	}
}
