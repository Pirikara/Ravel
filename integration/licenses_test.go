package integration_test

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Pirikara/Ravel/internal/collectors/composer"
	"github.com/Pirikara/Ravel/internal/collectors/conda"
	"github.com/Pirikara/Ravel/internal/collectors/npm"
	"github.com/Pirikara/Ravel/internal/collectors/python"
	"github.com/Pirikara/Ravel/internal/export"
	"github.com/Pirikara/Ravel/internal/model"
)

func licenseFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "testdata", "licenses", name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestLicenseLockfilesAndManifests(t *testing.T) {
	npmExpected := map[string]string{"standard": "MIT", "expression": "MIT OR Apache-2.0", "exception": "GPL-2.0-only WITH Classpath-exception-2.0", "legacy-object": "BSD-2-Clause", "legacy-array": "NOASSERTION", "custom": "NOASSERTION", "custom-ref": "NOASSERTION", "unlicensed": "NOASSERTION", "long-notice": "NOASSERTION", "url": "NOASSERTION", "empty": "NOASSERTION"}
	for _, test := range []struct {
		dir, file string
		expected  map[string]string
		root      string
	}{
		{"npm-v1", "package-lock.json", npmExpected, "MIT"},
		{"npm-v2", "package-lock.json", npmExpected, "MIT"},
		{"npm-v3", "package-lock.json", npmExpected, "NOASSERTION"},
		{"composer", "composer.lock", map[string]string{"example/choice": "(MIT) OR (Apache-2.0)", "example/custom": "NOASSERTION", "example/single": "BSD-3-Clause"}, ""},
		{"ruby", "sample.gemspec", map[string]string{"licensed": "NOASSERTION"}, ""},
		{"apk", "installed", map[string]string{"licensed": "MIT OR BSD-2-Clause", "custom": "NOASSERTION"}, ""},
		{"cargo", "Cargo.lock", map[string]string{}, "MIT OR Apache-2.0"},
		{"maven", "pom.xml", map[string]string{}, "NOASSERTION"},
	} {
		t.Run(test.dir, func(t *testing.T) {
			input := filepath.Join("..", "testdata", "licenses", test.dir, test.file)
			if test.dir == "apk" { // discovery requires the installed database's conventional path.
				input = filepath.Join(t.TempDir(), "lib", "apk", "db", "installed")
				if err := os.MkdirAll(filepath.Dir(input), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(input, licenseFixture(t, "apk/installed"), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			out, err := exec.Command(executable, "scan", input, "--format", "ravel-json").Output()
			if err != nil {
				t.Fatalf("scan: %v %s", err, out)
			}
			var doc model.Document
			if err := json.Unmarshal(out, &doc); err != nil {
				t.Fatal(err)
			}
			assertLicenseExports(t, doc, test.expected, test.root)
			// Exercise CLI serializers too, rather than relying solely on calls to exporters.
			for _, format := range []string{"cyclonedx-json", "spdx-json"} {
				data, err := exec.Command(executable, "scan", input, "--format", format).Output()
				if err != nil {
					t.Fatalf("%s: %v %s", format, err, data)
				}
				var raw any
				if err := json.Unmarshal(data, &raw); err != nil {
					t.Fatal(err)
				}
				validateMergedSBOMSchema(t, format, raw)
			}
		})
	}
}

func TestInstalledLicenseMetadata(t *testing.T) {
	for _, test := range []struct {
		name, fixture, path, want string
		collect                   func([]byte, string, string, string) (model.Document, error)
	}{
		{"npm", "installed/package.json", "app/node_modules/installed-sample/package.json", "ISC", npm.CollectInstalledPackage},
		{"composer", "installed/composer.json", "app/vendor/composer/installed.json", "(MIT) OR (BSD-2-Clause)", composer.CollectInstalled},
		{"conda", "installed/conda.json", "opt/conda/conda-meta/licensed-1.2.3-py_0.json", "BSD-3-Clause", conda.CollectInstalledMetadata},
		{"python-expression", "python-modern/METADATA", "usr/lib/python3.14/site-packages/licensed-1.2.3.dist-info/METADATA", "MIT AND BSD-2-Clause", python.CollectInstalledMetadata},
		{"python-legacy", "python-legacy/PKG-INFO", "usr/lib/python3.14/site-packages/legacy-1.0.0.egg-info/PKG-INFO", "NOASSERTION", python.CollectInstalledMetadata},
		{"python-classifier", "python-classifier/METADATA", "usr/lib/python3.14/site-packages/classifier-1.0.0.dist-info/METADATA", "NOASSERTION", python.CollectInstalledMetadata},
	} {
		t.Run(test.name, func(t *testing.T) {
			doc, err := test.collect(licenseFixture(t, test.fixture), test.path, "licenses", test.path)
			if err != nil {
				t.Fatal(err)
			}
			if len(doc.Components) != 1 {
				t.Fatal(doc.Components)
			}
			assertLicenseExports(t, doc, map[string]string{doc.Components[0].Name: test.want}, "")
		})
	}
}

func TestJavaScriptManifestLicenseDoesNotLeakToDependencies(t *testing.T) {
	for _, test := range []struct{ fixture, file, name string }{
		{"bun-basic", "bun.lock", "bun-basic"},
		{"pnpm-basic", "pnpm-lock.yaml", "demo"},
		{"yarn-berry-basic", "yarn.lock", "demo"},
		{"yarn-classic-optional", "yarn.lock", "demo"},
	} {
		t.Run(test.fixture, func(t *testing.T) {
			root := t.TempDir()
			input := filepath.Join(root, test.file)
			data, err := os.ReadFile(filepath.Join("..", "testdata", "fixtures", test.fixture, test.file))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(input, data, 0o644); err != nil {
				t.Fatal(err)
			}
			manifest, _ := json.Marshal(map[string]any{"name": test.name, "version": "1.0.0", "license": "MIT", "dependencies": map[string]string{"alpha": "^1.0.0", "main": "1.0.0"}})
			if err := os.WriteFile(filepath.Join(root, "package.json"), manifest, 0o644); err != nil {
				t.Fatal(err)
			}
			out, err := exec.Command(executable, "scan", input, "--format", "ravel-json").Output()
			if err != nil {
				t.Fatal(err)
			}
			var doc model.Document
			if err := json.Unmarshal(out, &doc); err != nil {
				t.Fatal(err)
			}
			if doc.Root == nil || len(doc.Root.Licenses) != 1 || doc.Root.Licenses[0].Expression != "MIT" {
				t.Fatalf("root license lost: %+v", doc.Root)
			}
			for _, c := range doc.Components {
				if len(c.Licenses) > 0 {
					t.Fatalf("root license assigned to dependency: %+v", c)
				}
			}
		})
	}
}

func TestLicenseArchives(t *testing.T) {
	root := t.TempDir()
	for _, test := range []struct{ name, file, entry, fixture, want string }{
		{"nuget-expression", "expression.nupkg", "expression.nuspec", "nuget/expression.nuspec", "MIT OR Apache-2.0"},
		{"nuget-file", "file.nupkg", "file.nuspec", "nuget/file.nuspec", "NOASSERTION"},
		{"nuget-custom", "custom.nupkg", "custom.nuspec", "nuget/custom.nuspec", "NOASSERTION"},
		{"nuget-url", "url.nupkg", "url.nuspec", "nuget/url.nuspec", "NOASSERTION"},
		{"wheel", "licensed-1.2.3-py3-none-any.whl", "licensed-1.2.3.dist-info/METADATA", "python-modern/METADATA", "MIT AND BSD-2-Clause"},
		{"gem", "licensed-1.0.0.gem", "metadata", "ruby/metadata", "NOASSERTION"},
		{"npm", "licensed.tgz", "package/package.json", "installed/package.json", "ISC"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var content bytes.Buffer
			data := licenseFixture(t, test.fixture)
			if strings.HasSuffix(test.file, ".nupkg") || strings.HasSuffix(test.file, ".whl") {
				w := zip.NewWriter(&content)
				entry, err := w.Create(test.entry)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = entry.Write(data); err != nil {
					t.Fatal(err)
				}
				if strings.HasSuffix(test.file, ".whl") {
					for _, name := range []string{"WHEEL", "RECORD"} {
						if _, err := w.Create("licensed-1.2.3.dist-info/" + name); err != nil {
							t.Fatal(err)
						}
					}
				}
				if err = w.Close(); err != nil {
					t.Fatal(err)
				}
			} else {
				var target = &content
				var gz *gzip.Writer
				if strings.HasSuffix(test.file, ".tgz") {
					gz = gzip.NewWriter(&content)
					target = nil
				}
				var tw *tar.Writer
				if target != nil {
					tw = tar.NewWriter(target)
				} else {
					tw = tar.NewWriter(gz)
				}
				if err := tw.WriteHeader(&tar.Header{Name: test.entry, Mode: 0o644, Size: int64(len(data))}); err != nil {
					t.Fatal(err)
				}
				if _, err := tw.Write(data); err != nil {
					t.Fatal(err)
				}
				if strings.HasSuffix(test.file, ".gem") {
					var payload bytes.Buffer
					gz := gzip.NewWriter(&payload)
					tarball := tar.NewWriter(gz)
					if err := tarball.Close(); err != nil {
						t.Fatal(err)
					}
					if err := gz.Close(); err != nil {
						t.Fatal(err)
					}
					if err := tw.WriteHeader(&tar.Header{Name: "data.tar.gz", Mode: 0o644, Size: int64(payload.Len())}); err != nil {
						t.Fatal(err)
					}
					if _, err := tw.Write(payload.Bytes()); err != nil {
						t.Fatal(err)
					}
				}
				if err := tw.Close(); err != nil {
					t.Fatal(err)
				}
				if gz != nil {
					if err := gz.Close(); err != nil {
						t.Fatal(err)
					}
				}
			}
			file := filepath.Join(root, test.file)
			if err := os.WriteFile(file, content.Bytes(), 0o644); err != nil {
				t.Fatal(err)
			}
			out, err := exec.Command(executable, "scan", file, "--format", "ravel-json").Output()
			if err != nil {
				t.Fatalf("%v %s", err, out)
			}
			var doc model.Document
			if err := json.Unmarshal(out, &doc); err != nil {
				t.Fatal(err)
			}
			if len(doc.Components) != 1 || doc.Components[0].Kind != "package" {
				t.Fatalf("archive metadata rejected: %+v", doc)
			}
			assertLicenseExports(t, doc, map[string]string{doc.Components[0].Name: test.want}, "")
		})
	}
}

func assertLicenseExports(t *testing.T, doc model.Document, expected map[string]string, rootLicense string) {
	t.Helper()
	if len(doc.Components) != len(expected) {
		t.Fatalf("components: got %d want %d", len(doc.Components), len(expected))
	}
	for _, c := range doc.Components {
		if _, ok := expected[c.Name]; !ok {
			t.Fatalf("unexpected component %s", c.Name)
		}
		if c.Name != "empty" && len(c.Licenses) == 0 {
			t.Fatalf("missing declarations for %s", c.Name)
		}
		for _, d := range c.Licenses {
			for _, e := range d.Evidence {
				if e.InputPath == "" || e.InputDigest == "" || e.Pointer == "" {
					t.Fatalf("incomplete license evidence: %+v", e)
				}
			}
		}
	}
	spdxData, err := export.SPDX23(doc)
	if err != nil {
		t.Fatal(err)
	}
	var spdx struct {
		Packages []struct{ Name, LicenseDeclared, LicenseConcluded, LicenseComments string }
	}
	if err := json.Unmarshal(spdxData, &spdx); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, p := range spdx.Packages {
		want, ok := expected[p.Name]
		if doc.Root != nil && p.Name == doc.Root.Name {
			want, ok = rootLicense, true
		}
		if !ok {
			continue
		}
		seen[p.Name] = true
		if p.LicenseDeclared != want || p.LicenseConcluded != "NOASSERTION" {
			t.Fatalf("%s: declared=%q concluded=%q, want declared=%q", p.Name, p.LicenseDeclared, p.LicenseConcluded, want)
		}
		if p.Name != "empty" && p.LicenseComments == "" {
			t.Fatalf("raw license metadata missing for %s", p.Name)
		}
	}
	for name := range expected {
		if !seen[name] {
			t.Fatalf("SPDX package missing: %s", name)
		}
	}
	if rootLicense != "" && (doc.Root == nil || !seen[doc.Root.Name]) {
		t.Fatal("root declaration lost")
	}
	cdxData, err := export.CycloneDX(doc)
	if err != nil {
		t.Fatal(err)
	}
	var cdx struct {
		Components []struct {
			Name       string
			Licenses   []map[string]any
			Properties []struct{ Name, Value string }
		}
	}
	if err := json.Unmarshal(cdxData, &cdx); err != nil {
		t.Fatal(err)
	}
	for _, c := range cdx.Components {
		if _, ok := expected[c.Name]; !ok {
			continue
		}
		if c.Name != "empty" {
			found := false
			for _, p := range c.Properties {
				if p.Name == "ravel:licenseDeclaration" {
					found = true
				}
			}
			if !found {
				t.Fatalf("CycloneDX declaration/evidence missing: %s", c.Name)
			}
		}
		for _, choice := range c.Licenses {
			if l, ok := choice["license"].(map[string]any); ok {
				if l["acknowledgement"] != "declared" {
					t.Fatal(choice)
				}
			} else if choice["acknowledgement"] != "declared" {
				t.Fatal(choice)
			}
		}
	}
	for format, data := range map[string][]byte{"cyclonedx-json": cdxData, "spdx-json": spdxData} {
		var raw any
		if err := json.Unmarshal(data, &raw); err != nil {
			t.Fatal(err)
		}
		validateMergedSBOMSchema(t, format, raw)
	}
}
