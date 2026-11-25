package oci

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestImageLockParsersAndEvidence(t *testing.T) {
	for _, tc := range []struct{ fixture, file string }{
		{"npm-v1", "package-lock.json"},
		{"pnpm-basic", "pnpm-lock.yaml"},
		{"yarn-berry-basic", "yarn.lock"},
		{"yarn-classic-optional", "yarn.lock"},
		{"bun-basic", "bun.lock"},
		{"deno-v4", "deno.lock"},
		{"uv-basic", "uv.lock"},
		{"poetry-basic", "poetry.lock"},
		{"pdm-basic", "pdm.lock"},
		{"pipenv-basic", "Pipfile.lock"},
		{"pylock-basic", "pylock.toml"},
		{"requirements-conditional", "requirements.txt"},
		{"bundler-basic", "Gemfile.lock"},
		{"composer-basic", "composer.lock"},
		{"nuget-single", "packages.lock.json"},
		{"cargo-basic", "Cargo.lock"},
		{"go-vendor-basic", "go.mod"},
		{"gradle-basic", "gradle.lockfile"},
		{"maven-basic", "dependency-tree.json"},
		{"sbt-basic", "build.sbt.lock"},
		{"renv-basic", "renv.lock"},
		{"conda-lock-basic", "conda-lock.yml"},
		{"pixi-v6", "pixi.lock"},
		{"pixi-v7", "pixi.lock"},
	} {
		t.Run(tc.fixture, func(t *testing.T) {
			files := map[string]imageProjectFile{}
			base := filepath.Join("..", "..", "..", "testdata", "fixtures", tc.fixture)
			entries, err := os.ReadDir(base)
			if err != nil {
				t.Fatal(err)
			}
			for _, e := range entries {
				if e.IsDir() || !isImageProjectFile(e.Name()) {
					continue
				}
				data, err := os.ReadFile(filepath.Join(base, e.Name()))
				if err != nil {
					t.Fatal(err)
				}
				files["app/"+e.Name()] = imageProjectFile{data: data, layer: "sha256:sample"}
			}
			locks, issues, err := parseImageLocks(files, "test")
			if err != nil || len(issues) != 0 {
				t.Fatalf("parse: %v %#v", err, issues)
			}
			found := false
			for _, lock := range locks {
				if lock.name != "app/"+tc.file {
					continue
				}
				found = true
				if len(lock.doc.Components) == 0 {
					t.Fatal("fixture yielded no components")
				}
				for _, c := range lock.doc.Components {
					for _, e := range c.Evidence {
						if !strings.HasPrefix(e.InputPath, "oci:sha256:sample!/app/") || e.Method != "image-lockfile-correlation" || !strings.HasPrefix(e.InputDigest, "sha256:") {
							t.Fatalf("host path or missing layer evidence: %#v", e)
						}
					}
				}
			}
			if !found {
				t.Fatal("lockfile not selected")
			}
		})
	}
}

func TestImageRequirementsIncludesStayInStagedImage(t *testing.T) {
	files := map[string]imageProjectFile{
		"app/requirements.txt":       {data: []byte("-r requirements-child.txt\n"), layer: "sha256:test"},
		"app/requirements-child.txt": {data: []byte("demo==1.2.3\n"), layer: "sha256:test"},
	}
	locks, issues, err := parseImageLocks(files, "test")
	if err != nil || len(issues) != 0 || len(locks) != 2 || len(locks[0].doc.Components) != 1 {
		t.Fatalf("staged include: %v %#v", err, issues)
	}
	files["app/requirements.txt"] = imageProjectFile{data: []byte("-r ../../../../../../etc/hosts\n"), layer: "sha256:test"}
	_, issues, err = parseImageLocks(files, "test")
	if err != nil || len(issues) != 1 || issues[0].Code != "image_lockfile_invalid" || issues[0].Name != "app/requirements.txt" {
		t.Fatalf("escape was not rejected: %v %#v", err, issues)
	}
}

func TestImageProjectStagingRejectsEscapingNames(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "uv.lock")
	if err := os.WriteFile(outside, []byte("untouched"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{outside, "../outside/uv.lock", "app/../../outside/uv.lock", "app/../uv.lock"} {
		_, _, err := parseImageLocks(map[string]imageProjectFile{name: {data: []byte("overwrite"), layer: "sha256:test"}}, "test")
		if err == nil {
			t.Fatalf("accepted unsafe staging path %q", name)
		}
	}
	data, err := os.ReadFile(outside)
	if err != nil || string(data) != "untouched" {
		t.Fatal("outside file changed")
	}
}
