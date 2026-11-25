package integration_test

import (
	"archive/tar"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Pirikara/Ravel/internal/model"
)

func imageLockFixture(t *testing.T, dir, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "testdata", "fixtures", dir, name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestOCIImageLockfileCorrelationAcrossManagers(t *testing.T) {
	for _, tc := range []struct{ fixture, lock, ecosystem, name, version string }{
		{"pnpm-basic", "pnpm-lock.yaml", "npm", "alpha", "1.0.0"},
		{"bun-basic", "bun.lock", "npm", "alpha", "1.0.0"},
		{"yarn-berry-basic", "yarn.lock", "npm", "alpha", "1.1.0"},
		{"uv-basic", "uv.lock", "pypi", "Requests", "2.32.3"},
		{"poetry-basic", "poetry.lock", "pypi", "Requests", "2.32.3"},
		{"pipenv-basic", "Pipfile.lock", "pypi", "Requests", "2.32.3"},
		{"pdm-basic", "pdm.lock", "pypi", "alpha", "1.0.0"},
		{"pylock-basic", "pylock.toml", "pypi", "click", "8.1.3"},
		{"bundler-basic", "Gemfile.lock", "gem", "alpha", "1.0.0"},
	} {
		t.Run(tc.fixture, func(t *testing.T) {
			entries := []ociTestEntry{{name: "app/" + tc.lock, data: imageLockFixture(t, tc.fixture, tc.lock)}}
			switch tc.ecosystem {
			case "npm":
				entries = append(entries, ociTestEntry{name: "app/node_modules/" + tc.name + "/package.json", data: []byte(fmt.Sprintf(`{"name":%q,"version":%q}`, tc.name, tc.version))})
			case "pypi":
				entries = append(entries, ociTestEntry{name: "usr/local/lib/python3.13/site-packages/" + strings.ToLower(tc.name) + "-" + tc.version + ".dist-info/METADATA", data: []byte("Metadata-Version: 2.3\nName: " + tc.name + "\nVersion: " + tc.version + "\n")})
			case "gem":
				entries = append(entries, ociTestEntry{name: "usr/local/bundle/specifications/" + tc.name + "-" + tc.version + ".gemspec", data: ociTestInstalledRubySpec(tc.name, tc.version, "ruby")})
			}
			layout := ociTestLayout(t)
			ociTestIndex(t, layout, ociTestImage(t, layout, "linux", "amd64", []ociTestLayer{{entries: entries}}))
			doc, output, code := ociTestScan(t, layout)
			if code != 0 || len(doc.Components) != 1 {
				t.Fatalf("scan: %d %s", code, output)
			}
			c := doc.Components[0]
			basis := "ecosystem_inferred"
			if tc.fixture == "pnpm-basic" || tc.fixture == "uv-basic" || tc.fixture == "poetry-basic" || tc.fixture == "pylock-basic" || tc.fixture == "bundler-basic" {
				basis = "source_qualified"
			}
			if c.Name != tc.name || c.Version != tc.version || c.PURL == "" || c.PURLBasis != basis || len(c.Hashes) != 0 {
				t.Fatalf("installed occurrence changed: %#v", c)
			}
			matched := false
			for _, e := range c.Evidence {
				matched = matched || e.Method == "image-lockfile-correlation" && strings.HasSuffix(e.InputPath, "!/app/"+tc.lock)
			}
			if !matched {
				t.Fatalf("missing lock correlation: %s", output)
			}
			for _, o := range doc.Origins {
				if o.Occurrence != c.ID || o.Status != "correlated_from_lockfile" || strings.Contains(o.SafeURL, "secret") || strings.Contains(o.SafeURL, "token=") {
					t.Fatalf("origin overclaimed or leaked: %#v", o)
				}
			}
		})
	}
}

const imageNpmLock = `{"lockfileVersion":3,"packages":{"":{"name":"app","dependencies":{"alpha":"1.0.0"}},"node_modules/alpha":{"version":"1.0.0","resolved":"https://user:secret@registry.example.test/alpha.tgz?token=hidden","integrity":"sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","dependencies":{"beta":"2.0.0"}},"node_modules/beta":{"version":"2.0.0","resolved":"https://registry.example.test/beta.tgz"},"node_modules/dev-only":{"version":"3.0.0","resolved":"https://registry.example.test/dev.tgz","dev":true}}}`

func imageNpmInstalledEntries() []ociTestEntry {
	return []ociTestEntry{
		{name: "app/node_modules/alpha/package.json", data: []byte(`{"name":"alpha","version":"1.0.0"}`)},
		{name: "app/node_modules/beta/package.json", data: []byte(`{"name":"beta","version":"2.0.0"}`)},
	}
}

func TestOCIImageLockfileOriginsAndConditionalGraph(t *testing.T) {
	layout := ociTestLayout(t)
	entries := append(imageNpmInstalledEntries(), ociTestEntry{name: "app/package-lock.json", data: []byte(imageNpmLock)})
	ociTestIndex(t, layout, ociTestImage(t, layout, "linux", "amd64", []ociTestLayer{{entries: entries}}))
	for _, input := range []string{layout, ociTestArchive(t, layout, "locks.oci.tar")} {
		doc, output, code := ociTestScan(t, input)
		if code != 0 || len(doc.Components) != 2 || len(doc.Origins) != 2 {
			t.Fatalf("correlation: %d %s", code, output)
		}
		names := map[string]string{}
		for _, c := range doc.Components {
			names[c.ID] = c.Name
			if len(c.Hashes) != 0 || len(c.Evidence) != 2 || c.Evidence[1].Method != "image-lockfile-correlation" {
				t.Fatalf("lock hash promoted or evidence lost: %#v", c)
			}
		}
		for _, o := range doc.Origins {
			if o.Status != "correlated_from_lockfile" || strings.ContainsAny(o.SafeURL, "?@") || o.Evidence.InputDigest == "" {
				t.Fatalf("origin claim: %#v", o)
			}
		}
		linked := false
		for _, edge := range doc.Edges {
			if names[edge.From] == "alpha" && names[edge.To] == "beta" {
				linked = true
				if edge.Condition != "lockfile_installation=unverified" || !strings.HasSuffix(edge.Evidence.InputPath, "!/app/package-lock.json") {
					t.Fatalf("unverified lock graph became installed fact: %#v", edge)
				}
			}
			if edge.Kind == "direct" {
				t.Fatalf("project roots became image direct dependencies: %#v", edge)
			}
		}
		if !linked || !dotnetIssue(doc, "image_lockfile_installation_unverified") {
			t.Fatalf("lock graph missing: %s", output)
		}
	}
}

func TestOCIImageLockfileFinalLayerSemantics(t *testing.T) {
	for _, tc := range []struct {
		name       string
		updates    []ociTestEntry
		correlated bool
		issue      string
	}{
		{"deleted", []ociTestEntry{{name: "app/.wh.package-lock.json"}}, false, ""},
		{"opaque", []ociTestEntry{{name: "app/.wh..wh..opq"}}, false, ""},
		{"replaced-invalid", []ociTestEntry{{name: "app/package-lock.json", data: []byte("broken")}}, false, "image_lockfile_invalid"},
		{"replaced-symlink", []ociTestEntry{{name: "app/package-lock.json", typeflag: tar.TypeSymlink, linkname: "/outside"}}, false, "image_project_file_unsupported"},
		{"replaced-directory", []ociTestEntry{{name: "app/package-lock.json", typeflag: tar.TypeDir}}, false, "image_project_file_unsupported"},
		{"updated", []ociTestEntry{{name: "app/package-lock.json", data: []byte(strings.ReplaceAll(imageNpmLock, "registry.example.test", "new.example.test"))}}, true, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			layout := ociTestLayout(t)
			updates := append(append([]ociTestEntry{}, tc.updates...), imageNpmInstalledEntries()...)
			ociTestIndex(t, layout, ociTestImage(t, layout, "linux", "amd64", []ociTestLayer{
				{entries: []ociTestEntry{{name: "app/package-lock.json", data: []byte(imageNpmLock)}}},
				{entries: updates},
			}))
			doc, output, code := ociTestScan(t, layout)
			if code != 0 || len(doc.Components) != 2 || (len(doc.Origins) > 0) != tc.correlated {
				t.Fatalf("final layer: %d %s", code, output)
			}
			if tc.issue != "" && !dotnetIssue(doc, tc.issue) {
				t.Fatalf("missing issue %s: %s", tc.issue, output)
			}
			for _, o := range doc.Origins {
				if !strings.HasPrefix(o.SafeURL, "https://new.example.test/") {
					t.Fatalf("stale lock used: %#v", o)
				}
			}
		})
	}
}

func TestOCIImageLockfileConflictingSourcesRemainAmbiguous(t *testing.T) {
	for _, differentScopes := range []bool{false, true} {
		t.Run(fmt.Sprint(differentScopes), func(t *testing.T) {
			name := "app/Gemfile.other.lock"
			if differentScopes {
				name = "other/Gemfile.lock"
			}
			lock := "GEM\n  remote: https://one.example.test\n  specs:\n    alpha (1.0.0)\n\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n  alpha\n"
			layout := ociTestLayout(t)
			ociTestIndex(t, layout, ociTestImage(t, layout, "linux", "amd64", []ociTestLayer{{entries: []ociTestEntry{
				{name: "app/Gemfile.lock", data: []byte(lock)},
				{name: name, data: []byte(strings.ReplaceAll(lock, "one.example.test", "two.example.test"))},
				{name: "usr/local/bundle/specifications/alpha-1.0.0.gemspec", data: ociTestInstalledRubySpec("alpha", "1.0.0", "ruby")},
			}}}))
			doc, output, code := ociTestScan(t, layout)
			if code != 0 || len(doc.Components) != 1 || len(doc.Origins) != 0 || len(doc.Components[0].Evidence) != 1 {
				t.Fatalf("conflicting/global lock selected: %d %s", code, output)
			}
			if !differentScopes && !dotnetIssue(doc, "image_lockfile_match_ambiguous") {
				t.Fatalf("ambiguity omitted: %s", output)
			}
		})
	}
}

func TestOCIImageLockfileNeverAddsUninstalledPackages(t *testing.T) {
	layout := ociTestLayout(t)
	ociTestIndex(t, layout, ociTestImage(t, layout, "linux", "amd64", []ociTestLayer{{entries: []ociTestEntry{{name: "app/package-lock.json", data: []byte(imageNpmLock)}}}}))
	doc, output, code := ociTestScan(t, layout)
	if code != 0 || len(doc.Components) != 0 || len(doc.Origins) != 0 || !dotnetIssue(doc, "image_lockfile_no_installed_match") {
		t.Fatalf("lock entries became installed: %d %s", code, output)
	}
}

func TestOCIImageLockfileNpmOccurrencePaths(t *testing.T) {
	lock := `{"lockfileVersion":3,"packages":{"":{},"node_modules/alpha":{"version":"1.0.0","resolved":"https://one.example.test/alpha.tgz"},"node_modules/other/node_modules/alpha":{"version":"1.0.0","resolved":"https://two.example.test/alpha.tgz"}}}`
	layout := ociTestLayout(t)
	ociTestIndex(t, layout, ociTestImage(t, layout, "linux", "amd64", []ociTestLayer{{entries: []ociTestEntry{
		{name: "app/package-lock.json", data: []byte(lock)},
		{name: "app/node_modules/alpha/package.json", data: []byte(`{"name":"alpha","version":"1.0.0"}`)},
		{name: "app/node_modules/other/node_modules/alpha/package.json", data: []byte(`{"name":"alpha","version":"1.0.0"}`)},
	}}}))
	doc, output, code := ociTestScan(t, layout)
	if code != 0 || len(doc.Components) != 2 || len(doc.Origins) != 2 {
		t.Fatalf("path correlation: %d %s", code, output)
	}
	byID := map[string]model.Component{}
	for _, c := range doc.Components {
		byID[c.ID] = c
	}
	for _, o := range doc.Origins {
		nested := strings.Contains(installedPathForTest(byID[o.Occurrence]), "/other/")
		if nested != strings.Contains(o.SafeURL, "two.example.test") {
			t.Fatalf("same-version occurrences mixed: %#v", o)
		}
	}
}

func installedPathForTest(c model.Component) string { return c.Evidence[0].InputPath }

func TestOCIOtherEcosystemLockfileCorrelation(t *testing.T) {
	for _, tc := range []struct {
		name, lockName    string
		lock              []byte
		installed         ociTestEntry
		packageName, purl string
	}{
		{"composer", "composer.lock", imageLockFixture(t, "composer-basic", "composer.lock"), ociTestEntry{name: "app/vendor/composer/installed.json", data: []byte(`[{"name":"monolog/monolog","version":"3.0.0"}]`)}, "monolog/monolog", "pkg:composer/monolog/monolog@3.0.0?download_url=https:%2F%2Fapi.github.com%2Frepos%2FSeldaek%2Fmonolog%2Fzipball%2Fabcdef1234567890"},
		{"nuget", "packages.lock.json", imageLockFixture(t, "nuget-single", "packages.lock.json"), ociTestEntry{name: "app/main.deps.json", data: []byte(`{"runtimeTarget":{"name":".NETCoreApp,Version=v8.0"},"targets":{".NETCoreApp,Version=v8.0":{"Example.Core/2.0.0":{"runtime":{"lib/net8.0/Example.Core.dll":{}}}}},"libraries":{"Example.Core/2.0.0":{"type":"package"}}}`)}, "Example.Core", "pkg:nuget/Example.Core@2.0.0"},
		{"nuget-assets", "obj/project.assets.json", []byte(`{"version":3,"targets":{"net8.0":{"Example.Core/2.0.0":{"type":"package"}},"net9.0":{"Example.Core/2.0.0":{"type":"package"}}}}`), ociTestEntry{name: "app/main.deps.json", data: []byte(`{"runtimeTarget":{"name":".NETCoreApp,Version=v8.0"},"targets":{".NETCoreApp,Version=v8.0":{"Example.Core/2.0.0":{"runtime":{"lib/net8.0/Example.Core.dll":{}}}}},"libraries":{"Example.Core/2.0.0":{"type":"package"}}}`)}, "Example.Core", "pkg:nuget/Example.Core@2.0.0"},
		{"conda", "conda-lock.yml", imageLockFixture(t, "conda-lock-basic", "conda-lock.yml"), ociTestEntry{name: "opt/conda/conda-meta/python-3.12.7-h1_0.json", data: []byte(`{"name":"python","version":"3.12.7","build":"h1_0","subdir":"linux-64"}`)}, "python", "pkg:conda/python@3.12.7?build=h1_0&download_url=https:%2F%2Fconda.anaconda.org%2Fconda-forge%2Flinux-64%2Fpython-3.12.7-h1_0.conda&subdir=linux-64"},
		{"r", "renv.lock", imageLockFixture(t, "renv-basic", "renv.lock"), ociTestEntry{name: "usr/local/lib/R/site-library/markdown/DESCRIPTION", data: []byte("Package: markdown\nVersion: 1.13\nBuilt: R 4.4.2; x86_64-pc-linux-gnu\nRepository: CRAN\n")}, "markdown", "pkg:cran/markdown@1.13?repository_url=https:%2F%2Fcloud.r-project.org"},
		{"maven", "dependency-tree.json", []byte(`{"groupId":"com.example","artifactId":"app","version":"1.0.0","children":[{"groupId":"com.example","artifactId":"sample","version":"1.0.0","type":"jar","scope":"compile"}]}`), ociTestEntry{name: "app/sample.jar", data: javaFixtureArchive(t, "java-jar-basic", "sample.jar")}, "com.example:sample", "pkg:maven/com.example/sample@1.0.0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			layout := ociTestLayout(t)
			ociTestIndex(t, layout, ociTestImage(t, layout, "linux", "amd64", []ociTestLayer{{entries: []ociTestEntry{{name: "app/" + tc.lockName, data: tc.lock}, tc.installed}}}))
			doc, output, code := ociTestScan(t, layout)
			if code != 0 {
				t.Fatalf("scan: %d %s", code, output)
			}
			c := dotnetComponent(t, doc, tc.packageName)
			basis := "ecosystem_inferred"
			if tc.name == "composer" || tc.name == "conda" || tc.name == "r" {
				basis = "source_qualified"
			}
			if c.PURL != tc.purl || c.PURLBasis != basis {
				t.Fatalf("missing typed PURL: %#v", c)
			}
			matched := false
			for _, e := range c.Evidence {
				matched = matched || e.Method == "image-lockfile-correlation" && strings.HasSuffix(e.InputPath, "!/app/"+tc.lockName)
			}
			if !matched {
				t.Fatalf("missing lock evidence: %s", output)
			}
		})
	}
}

func TestOCIRPMInferredPURLs(t *testing.T) {
	for _, id := range []string{"fedora", "debian"} {
		t.Run(id, func(t *testing.T) {
			layout := ociTestLayout(t)
			ociTestIndex(t, layout, ociTestImage(t, layout, "linux", "amd64", []ociTestLayer{{entries: []ociTestEntry{
				{name: "etc/os-release", data: []byte("ID=" + id + "\nVERSION_ID=42\n")},
				{name: "usr/lib/sysimage/rpm/rpmdb.sqlite", data: rpmFixtureDatabase(t, "rpm-sqlite-basic")},
			}}}))
			doc, output, code := ociTestScan(t, layout)
			if code != 0 || len(doc.Components) == 0 {
				t.Fatalf("RPM scan: %d %s", code, output)
			}
			for _, c := range doc.Components {
				if id == "fedora" {
					if !strings.HasPrefix(c.PURL, "pkg:rpm/fedora/") || c.PURLBasis != "ecosystem_inferred" {
						t.Fatalf("RPM PURL missing: %#v", c)
					}
				} else if c.PURL != "" {
					t.Fatalf("RPM package relabeled Debian: %#v", c)
				}
			}
		})
	}
}

func TestOCIImageProjectFileLimits(t *testing.T) {
	entries := imageNpmInstalledEntries()
	for i := 0; i < 260; i++ {
		entries = append(entries, ociTestEntry{name: fmt.Sprintf("app/%03d/package-lock.json", i), data: []byte(imageNpmLock)})
	}
	layout := ociTestLayout(t)
	ociTestIndex(t, layout, ociTestImage(t, layout, "linux", "amd64", []ociTestLayer{{entries: entries}}))
	doc, output, code := ociTestScan(t, layout)
	if code != 0 || len(doc.Components) != 2 || !dotnetIssue(doc, "image_lockfile_scan_limited") {
		t.Fatalf("project limit: %d %s", code, output)
	}
}

func TestOCIImageLockfileStandardFormatAnnotations(t *testing.T) {
	layout := ociTestLayout(t)
	entries := append(imageNpmInstalledEntries(), ociTestEntry{name: "app/package-lock.json", data: []byte(imageNpmLock)})
	ociTestIndex(t, layout, ociTestImage(t, layout, "linux", "amd64", []ociTestLayer{{entries: entries}}))
	for _, format := range []string{"cyclonedx-json", "spdx-json"} {
		data, err := exec.Command(executable, "scan", layout, "--format", format).Output()
		if err != nil {
			t.Fatal(err)
		}
		var bom struct {
			Components []struct {
				Name       string
				Properties []struct{ Name, Value string }
			}
			Packages []struct{ Name, Comment string }
		}
		if err := json.Unmarshal(data, &bom); err != nil {
			t.Fatal(err)
		}
		annotations := ""
		if format == "cyclonedx-json" {
			for _, c := range bom.Components {
				if c.Name != "alpha" {
					continue
				}
				for _, prop := range c.Properties {
					annotations += prop.Name + "=" + prop.Value + "\n"
				}
			}
		} else {
			for _, p := range bom.Packages {
				if p.Name == "alpha" {
					annotations = p.Comment
				}
			}
		}
		for _, required := range []string{"ravel:occurrence", "ravel:lockfileOrigin", "correlated_from_lockfile", "ravel:lockfileEvidence", "ravel:lockfileDependency", "lockfile_installation=unverified", "!/app/package-lock.json"} {
			if !strings.Contains(annotations, required) {
				t.Fatalf("%s lost %s: %s", format, required, annotations)
			}
		}
		if strings.Contains(annotations, "secret") || strings.Contains(annotations, "token=") || strings.Contains(annotations, "ravel-image-locks-") {
			t.Fatalf("host path or credentials escaped staging: %s", annotations)
		}
	}
}

func TestOCIImageLockfileConflictsWithInstalledOrigin(t *testing.T) {
	layout := ociTestLayout(t)
	ociTestIndex(t, layout, ociTestImage(t, layout, "linux", "amd64", []ociTestLayer{{entries: []ociTestEntry{
		{name: "app/conda-lock.yml", data: imageLockFixture(t, "conda-lock-basic", "conda-lock.yml")},
		{name: "opt/conda/conda-meta/python-3.12.7-h1_0.json", data: []byte(`{"name":"python","version":"3.12.7","build":"h1_0","subdir":"linux-64","url":"https://different.example.test/linux-64/python-3.12.7-h1_0.conda"}`)},
	}}}))
	doc, output, code := ociTestScan(t, layout)
	if code != 0 || len(doc.Origins) != 1 || doc.Origins[0].Status != "recorded_in_install_metadata" || !dotnetIssue(doc, "image_lockfile_source_conflict") {
		t.Fatalf("contradictory source imported: %d %s", code, output)
	}
}

func TestOCIInstalledSourceRecordsWithoutLockfiles(t *testing.T) {
	const pythonMetadata = "usr/local/lib/python3.13/site-packages/demo-1.0.0.dist-info/"
	for _, tc := range []struct {
		name      string
		entries   []ociTestEntry
		kind, url string
	}{
		{"npm", []ociTestEntry{{name: "app/node_modules/demo/package.json", data: []byte(`{"name":"demo","version":"1.0.0","_resolved":"https://user:secret@registry.example.test/demo.tgz?token=hidden"}`)}}, "download_url", "https://registry.example.test/demo.tgz"},
		{"npm-git", []ociTestEntry{{name: "app/node_modules/demo/package.json", data: []byte(`{"name":"demo","version":"1.0.0","_resolved":"git@github.com:org/demo.git"}`)}}, "vcs", "ssh://github.com/org/demo.git"},
		{"composer", []ociTestEntry{{name: "app/vendor/composer/installed.json", data: []byte(`[{"name":"acme/demo","version":"1.0.0","dist":{"type":"zip","url":"https://user:secret@repo.example.test/demo.zip?token=hidden","shasum":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}]`)}}, "download_url", "https://repo.example.test/demo.zip"},
		{"python-archive", []ociTestEntry{{name: pythonMetadata + "METADATA", data: []byte("Metadata-Version: 2.3\nName: demo\nVersion: 1.0.0\n")}, {name: pythonMetadata + "direct_url.json", data: []byte(`{"url":"https://user:secret@repo.example.test/demo.whl?token=hidden","archive_info":{"hashes":{"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}}`)}}, "download_url", "https://repo.example.test/demo.whl"},
		{"python-git", []ociTestEntry{{name: pythonMetadata + "METADATA", data: []byte("Metadata-Version: 2.3\nName: demo\nVersion: 1.0.0\n")}, {name: pythonMetadata + "direct_url.json", data: []byte(`{"url":"https://user:secret@example.test/org/repo.git?token=hidden","vcs_info":{"vcs":"git","commit_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"subdirectory":"packages/demo"}`)}}, "vcs", "https://example.test/org/repo.git"},
		{"python-local", []ociTestEntry{{name: pythonMetadata + "METADATA", data: []byte("Metadata-Version: 2.3\nName: demo\nVersion: 1.0.0\n")}, {name: pythonMetadata + "direct_url.json", data: []byte(`{"url":"file:///build/private-project","dir_info":{"editable":true}}`)}}, "local", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			layout := ociTestLayout(t)
			ociTestIndex(t, layout, ociTestImage(t, layout, "linux", "amd64", []ociTestLayer{{entries: tc.entries}}))
			doc, output, code := ociTestScan(t, layout)
			if code != 0 || len(doc.Components) != 1 || len(doc.Origins) != 1 {
				t.Fatalf("installed source: %d %s", code, output)
			}
			origin := doc.Origins[0]
			if origin.Status != "recorded_in_install_metadata" || origin.Kind != tc.kind || origin.SafeURL != tc.url || origin.Evidence.InputDigest == "" || doc.Components[0].PURL == "" || len(doc.Components[0].Hashes) != 0 {
				t.Fatalf("source evidence or hashes overclaimed: %s", output)
			}
			if tc.name == "python-git" && (origin.Revision != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" || origin.Target != "subdirectory=packages/demo") {
				t.Fatalf("VCS identity missing: %#v", origin)
			}
			for _, format := range []string{"cyclonedx-json", "spdx-json"} {
				data, err := exec.Command(executable, "scan", layout, "--format", format).Output()
				if err != nil || !strings.Contains(string(data), "ravel:installedOrigin") || !strings.Contains(string(data), "recorded_in_install_metadata") || strings.Contains(string(data), "secret") || strings.Contains(string(data), "token=") || strings.Contains(string(data), "/build/private-project") {
					t.Fatalf("installed source annotation: %s %v %s", format, err, data)
				}
			}
		})
	}
}

func TestOCIPythonDirectURLFinalLayerAndInvalidRecords(t *testing.T) {
	const metadata = "usr/local/lib/python3.13/site-packages/demo-1.0.0.dist-info/"
	for _, tc := range []struct {
		name  string
		entry ociTestEntry
		issue string
	}{
		{"whiteout", ociTestEntry{name: metadata + ".wh.direct_url.json"}, ""},
		{"symlink", ociTestEntry{name: metadata + "direct_url.json", typeflag: tar.TypeSymlink, linkname: "/outside"}, "python_direct_url_invalid"},
		{"invalid", ociTestEntry{name: metadata + "direct_url.json", data: []byte(`{"url":"https://example.test/demo.whl","archive_info":{},"dir_info":{}}`)}, "python_direct_url_invalid"},
		{"oversized", ociTestEntry{name: metadata + "direct_url.json", data: []byte(strings.Repeat(" ", 64<<10) + `{}`)}, "python_direct_url_invalid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			layout := ociTestLayout(t)
			ociTestIndex(t, layout, ociTestImage(t, layout, "linux", "amd64", []ociTestLayer{
				{entries: []ociTestEntry{{name: metadata + "METADATA", data: []byte("Metadata-Version: 2.3\nName: demo\nVersion: 1.0.0\n")}, {name: metadata + "direct_url.json", data: []byte(`{"url":"https://example.test/demo.whl","archive_info":{}}`)}}},
				{entries: []ociTestEntry{tc.entry}},
			}))
			doc, output, code := ociTestScan(t, layout)
			if code != 0 || len(doc.Components) != 1 || len(doc.Origins) != 0 || tc.issue != "" && !dotnetIssue(doc, tc.issue) {
				t.Fatalf("direct URL final state: %d %s", code, output)
			}
		})
	}
}

func TestOCIRubyVersionedGemHomesAndGlobalLock(t *testing.T) {
	for _, home := range []string{"app/vendor/bundle/ruby/3.3.0", "usr/local/bundle/ruby/3.3.0", "var/lib/gems/3.3.0", "usr/share/gems"} {
		t.Run(home, func(t *testing.T) {
			layout := ociTestLayout(t)
			ociTestIndex(t, layout, ociTestImage(t, layout, "linux", "amd64", []ociTestLayer{{entries: []ociTestEntry{
				{name: "app/Gemfile.lock", data: imageLockFixture(t, "bundler-basic", "Gemfile.lock")},
				{name: home + "/specifications/alpha-1.0.0.gemspec", data: ociTestInstalledRubySpec("alpha", "1.0.0", "ruby")},
				{name: "usr/local/lib/ruby/gems/3.3.0/specifications/default/base-1.0.0.gemspec", data: ociTestInstalledRubySpec("base", "1.0.0", "ruby")},
			}}}))
			doc, output, code := ociTestScan(t, layout)
			if code != 0 || len(doc.Components) != 2 || len(doc.Origins) != 1 {
				t.Fatalf("gem home or global match: %d %s", code, output)
			}
			c := dotnetComponent(t, doc, "alpha")
			if c.PURL != "pkg:gem/alpha@1.0.0?repository_url=https:%2F%2Fgems.example.test%2Fruby" || c.PURLBasis != "source_qualified" || len(c.Evidence) != 2 {
				t.Fatalf("gem identity: %#v", c)
			}
		})
	}
}

func TestOCIImageLockfileNearestProjectDoesNotFallBackOnConflict(t *testing.T) {
	layout := ociTestLayout(t)
	ociTestIndex(t, layout, ociTestImage(t, layout, "linux", "amd64", []ociTestLayer{{entries: []ociTestEntry{
		{name: "app/package-lock.json", data: []byte(`{"lockfileVersion":3,"packages":{"":{},"sub/node_modules/alpha":{"version":"1.0.0","resolved":"https://one.example.test/alpha.tgz"}}}`)},
		{name: "app/sub/package-lock.json", data: []byte(`{"lockfileVersion":3,"packages":{"":{},"node_modules/alpha":{"version":"1.0.0","resolved":"https://two.example.test/alpha.tgz"}}}`)},
		{name: "app/sub/node_modules/alpha/package.json", data: []byte(`{"name":"alpha","version":"1.0.0","_resolved":"https://one.example.test/alpha.tgz"}`)},
	}}}))
	doc, output, code := ociTestScan(t, layout)
	if code != 0 || len(doc.Components) != 1 || len(doc.Components[0].Evidence) != 1 || len(doc.Origins) != 1 || doc.Origins[0].Status != "recorded_in_install_metadata" || !dotnetIssue(doc, "image_lockfile_source_conflict") {
		t.Fatalf("broader project used after nearest source conflict: %d %s", code, output)
	}
}
