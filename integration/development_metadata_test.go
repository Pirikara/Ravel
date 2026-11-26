package integration_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Pirikara/Ravel/internal/collectors/npm"
	"github.com/Pirikara/Ravel/internal/collectors/python"
	"github.com/Pirikara/Ravel/internal/export"
	"github.com/Pirikara/Ravel/internal/merge"
	"github.com/Pirikara/Ravel/internal/model"
)

func developmentFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "testdata", "development", name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func scanDevelopmentSample(t *testing.T, input string) model.Document {
	t.Helper()
	out, err := exec.Command(executable, "scan", input, "--format", "ravel-json").Output()
	if err != nil {
		t.Fatal(err)
	}
	var doc model.Document
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func TestInstalledDevelopmentMetadata(t *testing.T) {
	for _, test := range []struct {
		name, file, path, url, status, directory string
		collect                                  func([]byte, string, string, string) (model.Document, error)
	}{
		{"node", "node/package.json", "app/node_modules/source-sample/package.json", "https://code.example.test/team/source.git", "declared", "packages/source", npm.CollectInstalledPackage},
		{"python-source", "python/METADATA", "usr/lib/python3.14/site-packages/source_sample-1.2.3.dist-info/METADATA", "https://code.example.test/python/source", "declared", "", python.CollectInstalledMetadata},
		{"python-homepage", "python-legacy/PKG-INFO", "usr/lib/python3.14/site-packages/source_sample.egg-info/PKG-INFO", "https://github.com/owner/source", "inferred_from_homepage", "", python.CollectInstalledMetadata},
	} {
		t.Run(test.name, func(t *testing.T) {
			doc, err := test.collect(developmentFixture(t, test.file), test.path, "sample", test.path)
			if err != nil {
				t.Fatal(err)
			}
			if len(doc.Development) != 1 || doc.Development[0].SafeURL != test.url || doc.Development[0].Status != test.status || doc.Development[0].Directory != test.directory {
				t.Fatal(doc.Development)
			}
			if len(doc.Origins) != 0 || strings.Contains(doc.Components[0].PURL, "repository_url") || doc.Components[0].PURLBasis != "ecosystem_inferred" {
				t.Fatal("development source changed distribution identity", doc)
			}
			assertDevelopmentExports(t, doc)
		})
	}
}

func TestRootDevelopmentMetadataAndMerge(t *testing.T) {
	var inputs []model.Document
	for _, test := range []struct{ fixture, file, name string }{
		{"npm-generated-12", "package-lock.json", "ravel-npm-generated"},
		{"npm-v1-generated-12", "package-lock.json", "ravel-npm-v1-generated-12"},
		{"bun-basic", "bun.lock", "bun-basic"},
		{"pnpm-basic", "pnpm-lock.yaml", "demo"},
		{"yarn-classic-optional", "yarn.lock", "demo"},
		{"yarn-berry-basic", "yarn.lock", "demo"},
	} {
		t.Run(test.fixture, func(t *testing.T) {
			root := t.TempDir()
			data, err := os.ReadFile(filepath.Join("..", "testdata", "fixtures", test.fixture, test.file))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, test.file), data, 0o644); err != nil {
				t.Fatal(err)
			}
			var manifest map[string]any
			if data, err := os.ReadFile(filepath.Join("..", "testdata", "fixtures", test.fixture, "package.json")); err == nil {
				if err = json.Unmarshal(data, &manifest); err != nil {
					t.Fatal(err)
				}
			}
			if manifest == nil {
				manifest = map[string]any{"name": test.name, "version": "1.0.0"}
			}
			manifest["repository"] = map[string]string{"url": "github:owner/project", "directory": "packages/app"}
			data, _ = json.Marshal(manifest)
			if err := os.WriteFile(filepath.Join(root, "package.json"), data, 0o644); err != nil {
				t.Fatal(err)
			}
			doc := scanDevelopmentSample(t, filepath.Join(root, test.file))
			if len(doc.Development) != 1 || doc.Development[0].Occurrence != "root" || doc.Development[0].Directory != "packages/app" {
				t.Fatal(doc.Development)
			}
			assertDevelopmentExports(t, doc)
			inputs = append(inputs, doc)
		})
	}
	for _, test := range []struct {
		directory, file string
		count           int
	}{{"ruby", "source.gemspec", 1}, {"cargo", "Cargo.lock", 1}, {"maven", "pom.xml", 2}} {
		t.Run(test.directory, func(t *testing.T) {
			doc := scanDevelopmentSample(t, filepath.Join("..", "testdata", "development", test.directory, test.file))
			if len(doc.Development) != test.count {
				t.Fatal(doc.Development)
			}
			assertDevelopmentExports(t, doc)
			inputs = append(inputs, doc)
		})
	}
	combined, err := merge.Documents("combined", inputs)
	if err != nil {
		t.Fatal(err)
	}
	if len(combined.Development) != 10 {
		t.Fatal(combined.Development)
	}
	assertDevelopmentExports(t, combined)
}

func TestRealProjectDevelopmentRegressions(t *testing.T) {
	for _, sample := range []string{"ruby-mixed", "ruby-reference"} {
		t.Run(sample, func(t *testing.T) {
			doc := scanDevelopmentSample(t, filepath.Join("..", "testdata", "development", sample, "source.gemspec"))
			if len(doc.Components) != 1 || doc.Components[0].Version != "1.2.3" || len(doc.Development) != 1 || doc.Development[0].Status != "declared" {
				t.Fatal(doc.Components, doc.Development)
			}
			assertDevelopmentExports(t, doc)
		})
	}
	var documents []model.Document
	for _, sample := range []struct{ fixture, file, manifest string }{
		{"uv-basic", "uv.lock", "python-project"},
		{"poetry-basic", "poetry.lock", "python-poetry"},
		{"pdm-basic", "pdm.lock", "python-project"},
		{"pylock-basic", "pylock.toml", "python-project"},
		{"pipenv-basic", "Pipfile.lock", "python-project"},
		{"requirements-url", "requirements.txt", "python-project"},
	} {
		t.Run(sample.fixture, func(t *testing.T) {
			root := t.TempDir()
			lock, err := os.ReadFile(filepath.Join("..", "testdata", "fixtures", sample.fixture, sample.file))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, sample.file), lock, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "pyproject.toml"), developmentFixture(t, sample.manifest+"/pyproject.toml"), 0600); err != nil {
				t.Fatal(err)
			}
			doc := scanDevelopmentSample(t, filepath.Join(root, sample.file))
			if len(doc.Development) != 1 || doc.Development[0].Status != "declared" || doc.Development[0].SafeURL != "https://code.example.test/demo" {
				t.Fatal(doc.Development, doc.Coverage.Issues)
			}
			if sample.fixture == "uv-basic" {
				if !strings.HasPrefix(doc.Development[0].Occurrence, "uv-main:") || doc.Root != nil {
					t.Fatal("UV application duplicated", doc)
				}
			} else if doc.Root == nil || doc.Root.Name != "demo" || doc.Development[0].Occurrence != "root" {
				t.Fatal("application metadata lost", doc.Root, doc.Development)
			}
			assertDevelopmentExports(t, doc)
			documents = append(documents, doc)
		})
	}
	combined, err := merge.Documents("projects", documents)
	if err != nil {
		t.Fatal(err)
	}
	if len(combined.Development) != 6 {
		t.Fatal(combined.Development)
	}
	assertDevelopmentExports(t, combined)
}

func TestOCIDevelopmentMetadataPropagation(t *testing.T) {
	layout := ociTestLayout(t)
	image := ociTestImage(t, layout, "linux", "arm64", []ociTestLayer{{entries: []ociTestEntry{
		{name: "usr/local/lib/node_modules/source-sample/package.json", data: developmentFixture(t, "node/package.json")},
		{name: "usr/local/lib/python3.14/site-packages/source_sample-1.2.3.dist-info/METADATA", data: developmentFixture(t, "python/METADATA")},
		{name: "usr/local/bundle/specifications/source-sample-1.2.3.gemspec", data: developmentFixture(t, "ruby/installed.gemspec")},
		{name: "usr/local/lib/R/library/sourcesample/DESCRIPTION", data: developmentFixture(t, "r/DESCRIPTION")},
		{name: "usr/local/lib/python3.14/site-packages/setuptools-1.0.0.dist-info/METADATA", data: []byte("Metadata-Version: 2.4\nName: setuptools\nVersion: 1.0.0\n")},
		{name: "usr/local/lib/python3.14/site-packages/setuptools/_vendor/vendored_source-0.1.0.dist-info/METADATA", data: []byte("Metadata-Version: 2.4\nName: vendored-source\nVersion: 0.1.0\nProject-URL: Source, https://code.example.test/vendor/source\nLicense-Expression: MIT\n")},
	}}})
	ociTestIndex(t, layout, image)
	doc := scanDevelopmentSample(t, layout)
	if len(doc.Components) != 6 || len(doc.Development) != 5 {
		t.Fatalf("installed declarations lost: %+v", doc.Development)
	}
	for _, source := range doc.Development {
		expectedStatus := "declared"
		if source.Evidence.Collector == "r-installed-description" {
			expectedStatus = "inferred_from_project_url"
		}
		if source.Status != expectedStatus || !strings.HasPrefix(source.Evidence.InputPath, "oci:sha256:") {
			t.Fatal(source)
		}
	}
	assertDevelopmentExports(t, doc)
	// A final-layer removal must remove both presence and repository metadata.
	image = ociTestImage(t, layout, "linux", "arm64", []ociTestLayer{{entries: []ociTestEntry{
		{name: "usr/local/lib/node_modules/source-sample/package.json", data: developmentFixture(t, "node/package.json")},
	}}, {entries: []ociTestEntry{{name: "usr/local/lib/node_modules/source-sample/.wh.package.json"}}}})
	ociTestIndex(t, layout, image)
	doc = scanDevelopmentSample(t, layout)
	if len(doc.Components) != 0 || len(doc.Development) != 0 {
		t.Fatalf("removed repository survived: %+v", doc.Development)
	}
}

func TestGemArchiveDevelopmentMetadata(t *testing.T) {
	for _, test := range []struct{ name, extra, homepage, url, status string }{
		{"homepage", "", "https://github.com/owner/source", "https://github.com/owner/source", "inferred_from_homepage"},
		{"explicit", "metadata:\n  source_code_uri: https://code.example.test/ruby/source\n", "https://github.com/owner/source", "https://code.example.test/ruby/source", "declared"},
		{"website", "", "https://project.example.test/source", "", ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			metadata := strings.Replace(string(developmentFixture(t, "ruby/metadata")), "https://github.com/owner/source", test.homepage, 1) + test.extra
			file := writeGemTestArchive(t, []gemTestEntry{{"metadata", []byte(metadata)}, {"data.tar.gz", gemTestContents(t)}})
			doc := scanDevelopmentSample(t, file)
			if len(doc.Components) != 1 || doc.Components[0].Kind != "package" {
				t.Fatal(doc.Components)
			}
			if test.url == "" {
				if len(doc.Development) != 0 {
					t.Fatal(doc.Development)
				}
			} else if len(doc.Development) != 1 || doc.Development[0].SafeURL != test.url || doc.Development[0].Status != test.status {
				t.Fatal(doc.Development)
			}
			assertDevelopmentExports(t, doc)
		})
	}
}

func assertDevelopmentExports(t *testing.T, doc model.Document) {
	t.Helper()
	for _, source := range doc.Development {
		if source.Evidence.InputPath == "" || source.Evidence.InputDigest == "" || source.Evidence.Pointer == "" {
			t.Fatalf("missing source evidence: %+v", source)
		}
	}
	cdx, err := export.CycloneDX(doc)
	if err != nil {
		t.Fatal(err)
	}
	spdx, err := export.SPDX23(doc)
	if err != nil {
		t.Fatal(err)
	}
	for format, data := range map[string][]byte{"cyclonedx-json": cdx, "spdx-json": spdx} {
		if strings.Contains(string(data), "secret") {
			t.Fatal("URL credentials exported")
		}
		var raw any
		if err := json.Unmarshal(data, &raw); err != nil {
			t.Fatal(err)
		}
		validateMergedSBOMSchema(t, format, raw)
		for _, source := range doc.Development {
			if !strings.Contains(string(data), source.SafeURL) || !strings.Contains(string(data), source.Status) || !strings.Contains(string(data), source.Evidence.InputDigest) {
				t.Fatalf("%s source metadata lost: %+v", format, source)
			}
			if source.Directory != "" && !strings.Contains(string(data), source.Directory) {
				t.Fatal("monorepo directory lost")
			}
		}
	}
	var bom struct {
		Metadata struct {
			Component struct {
				Properties []struct{ Name, Value string }
			}
		}
		Components []struct {
			Properties []struct{ Name, Value string }
		}
	}
	if err := json.Unmarshal(cdx, &bom); err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, component := range bom.Components {
		for _, p := range component.Properties {
			if p.Name == "ravel:developmentRepositoryEvidence" {
				count++
			}
		}
	}
	for _, p := range bom.Metadata.Component.Properties {
		if p.Name == "ravel:developmentRepositoryEvidence" {
			count++
		}
	}
	if count != len(doc.Development) {
		t.Fatalf("source evidence count %d, want %d", count, len(doc.Development))
	}
}
