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
		"gems/alternate/Gemfile.next.lock",
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

	got, err := scanDirectories(root, false)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{root, filepath.Join(root, "gems/alternate"), filepath.Join(root, "gems/example")}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("scan directories = %q, want %q", got, want)
	}
	got, err = scanDirectories(root, true)
	if err != nil {
		t.Fatal(err)
	}
	want = []string{root, filepath.Join(root, "gems/alternate"), filepath.Join(root, "gems/example"), filepath.Join(root, "spec/fixtures/example"), filepath.Join(root, "tmp/tests")}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("inclusive scan directories = %q, want %q", got, want)
	}
}

func TestBundlerLockNames(t *testing.T) {
	for _, item := range []struct {
		name string
		want bool
	}{
		{"Gemfile.lock", true},
		{"Gemfile.next.lock", true},
		{"Gemfile.rails-8.lock", true},
		{"Gemfile.ruby_3.4.lock", true},
		{"Gemfile..lock", false},
		{"Gemfile.foo/.lock", false},
		{"Gemfile.lock.bak", false},
		{"OtherGemfile.lock", false},
	} {
		if got := isBundlerLockName(item.name); got != item.want {
			t.Errorf("isBundlerLockName(%q) = %v, want %v", item.name, got, item.want)
		}
	}
}
