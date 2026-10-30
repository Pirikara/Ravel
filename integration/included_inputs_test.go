package integration_test

import (
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCompanionInputsCannotBeOverwritten(t *testing.T) {
	for _, tc := range []struct{ fixture, companion string }{
		{"yarn-classic-basic", "package.json"},
		{"cargo-basic", "Cargo.toml"},
		{"composer-generated-2", "composer.json"},
		{"pipenv-basic", "Pipfile"},
		{"poetry-basic", "pyproject.toml"},
		{"pdm-basic", "pyproject.toml"},
		{"deno-v4", "deno.jsonc"},
		{"go-vendor-basic", "go.mod"},
	} {
		t.Run(tc.fixture, func(t *testing.T) {
			source := filepath.Join("..", "testdata", "fixtures", tc.fixture)
			project := t.TempDir()
			if err := filepath.WalkDir(source, func(path string, entry fs.DirEntry, err error) error {
				if err != nil {
					return err
				}
				relative, err := filepath.Rel(source, path)
				if err != nil {
					return err
				}
				target := filepath.Join(project, relative)
				if entry.IsDir() {
					return os.MkdirAll(target, 0o700)
				}
				data, err := os.ReadFile(path)
				if err != nil {
					return err
				}
				return os.WriteFile(target, data, 0o600)
			}); err != nil {
				t.Fatal(err)
			}
			companion := filepath.Join(project, tc.companion)
			original, err := os.ReadFile(companion)
			if err != nil {
				t.Fatal(err)
			}
			for _, flag := range []string{"", "--all"} {
				args := []string{"scan", project, "--output", companion}
				if flag != "" {
					args = append(args, flag)
				}
				output, err := exec.Command(executable, args...).CombinedOutput()
				if err == nil || !strings.Contains(string(output), "cannot overwrite") {
					t.Fatalf("%s scan overwrote a companion input: %v, %s", flag, err, output)
				}
				current, err := os.ReadFile(companion)
				if err != nil || string(current) != string(original) {
					t.Fatal("companion input changed during scan")
				}
			}
		})
	}
}
