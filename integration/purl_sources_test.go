package integration_test

import (
	"encoding/json"
	"github.com/Pirikara/Ravel/internal/model"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	packageurl "github.com/package-url/packageurl-go"
)

func purlSource(raw, typ, key, location string) bool {
	p, err := packageurl.FromString(raw)
	if err != nil || p.Type != typ {
		return false
	}
	value := p.Qualifiers.Map()[key]
	return value != "" && (location == "" || value == location)
}

// Read only standard fields: a consumer need not understand Ravel properties
// or SPDX package comments to retain the package's recorded source.
func TestPortablePackageSources(t *testing.T) {
	for _, tc := range []struct{ fixture, name, purl, distribution, vcs, download string }{
		{"uv-basic", "Requests", "pkg:pypi/requests@2.32.3?repository_url=https:%2F%2Fpypi.example.test%2Fsimple", "https://pypi.example.test/simple", "", "NOASSERTION"},
		{"bun-v2-private", "private-lib", "pkg:npm/private-lib@1.0.0?download_url=https:%2F%2Fpackages.example.test%2Fprivate-lib%2F-%2Fprivate-lib-1.0.0.tgz", "https://packages.example.test/private-lib/-/private-lib-1.0.0.tgz", "", "https://packages.example.test/private-lib/-/private-lib-1.0.0.tgz"},
		{"bundler-basic", "alpha", "pkg:gem/alpha@1.0.0?repository_url=https:%2F%2Fgems.example.test%2Fruby", "https://gems.example.test/ruby", "", "NOASSERTION"},
		{"cargo-git", "git-lib", "pkg:cargo/git-lib@1.0.0?vcs_url=git%2Bhttps:%2F%2Fgithub.com%2Fteam%2Fgit-lib%40abcdef1234567890", "", "git+https://github.com/team/git-lib@abcdef1234567890", "git+https://github.com/team/git-lib@abcdef1234567890"},
		{"npm-generated-12", "is-number", "pkg:npm/is-number@7.0.0", "https://registry.npmjs.org/is-number/-/is-number-7.0.0.tgz", "", "https://registry.npmjs.org/is-number/-/is-number-7.0.0.tgz"},
	} {
		t.Run(tc.fixture, func(t *testing.T) {
			input := filepath.Join("..", "testdata", "fixtures", tc.fixture)
			for _, format := range []string{"cyclonedx-json", "spdx-json"} {
				out, err := exec.Command(executable, "scan", input, "--format", format).Output()
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(string(out), "secret") || strings.Contains(string(out), "hidden") {
					t.Fatal("source credentials leaked")
				}
				found := false
				if format == "cyclonedx-json" {
					var doc struct {
						Components []struct {
							Name string `json:"name"`
							PURL string `json:"purl"`
							Refs []struct {
								Type    string `json:"type"`
								URL     string `json:"url"`
								Comment string `json:"comment"`
							} `json:"externalReferences"`
						} `json:"components"`
					}
					if err := json.Unmarshal(out, &doc); err != nil {
						t.Fatal(err)
					}
					for _, c := range doc.Components {
						if c.Name != tc.name {
							continue
						}
						found = true
						if c.PURL != tc.purl {
							t.Fatalf("PURL: %s", c.PURL)
						}
						distribution, vcs := tc.distribution == "", tc.vcs == ""
						for _, ref := range c.Refs {
							distribution = distribution || ref.Type == "distribution" && ref.URL == tc.distribution && ref.Comment != ""
							vcs = vcs || ref.Type == "vcs" && ref.URL == tc.vcs && ref.Comment != ""
						}
						if !distribution || !vcs {
							t.Fatalf("missing standard reference: %+v", c.Refs)
						}
					}
				} else {
					var doc struct {
						Packages []struct {
							Name     string `json:"name"`
							Download string `json:"downloadLocation"`
							Source   string `json:"sourceInfo"`
							Refs     []struct {
								Type    string `json:"referenceType"`
								Locator string `json:"referenceLocator"`
							} `json:"externalRefs"`
						} `json:"packages"`
					}
					if err := json.Unmarshal(out, &doc); err != nil {
						t.Fatal(err)
					}
					for _, p := range doc.Packages {
						if p.Name != tc.name {
							continue
						}
						found = true
						purl := ""
						for _, ref := range p.Refs {
							if ref.Type == "purl" {
								purl = ref.Locator
							}
						}
						if purl != tc.purl || p.Download != tc.download || p.Source == "" || !strings.Contains(p.Source, "not independently verified") {
							t.Fatalf("standard SPDX source: %+v", p)
						}
						if tc.distribution != "" && !strings.Contains(p.Source, tc.distribution) {
							t.Fatalf("registry or distribution lost: %s", p.Source)
						}
					}
				}
				if !found {
					t.Fatalf("missing %s in %s", tc.name, format)
				}
			}
		})
	}
}

func TestPylockPreservesVCSType(t *testing.T) {
	input := filepath.Join(t.TempDir(), "pylock.toml")
	data := `lock-version = "1.0"
created-by = "source-test"
[[packages]]
name = "demo"
version = "1.0"
[packages.vcs]
type = "hg"
url = "https://user:secret@hg.example.test/demo?token=hidden"
commit-id = "abcdef1234567890"
`
	if err := os.WriteFile(input, []byte(data), 0o600); err != nil {
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
	if len(doc.Components) != 1 || doc.Components[0].PURL != "pkg:pypi/demo@1.0?vcs_url=hg%2Bhttps:%2F%2Fhg.example.test%2Fdemo%40abcdef1234567890" || len(doc.Origins) != 1 || doc.Origins[0].VCSType != "hg" {
		t.Fatalf("VCS tool lost: %s", out)
	}
}
