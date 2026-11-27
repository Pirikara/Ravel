package integration_test

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Pirikara/Ravel/internal/export"
)

func TestSwiftRevisionOnlyIdentityAndStandardSources(t *testing.T) {
	doc := scanDevelopmentSample(t, filepath.Join("..", "testdata", "fixtures", "swift-revision-only", "Package.resolved"))
	if len(doc.Components) != 3 || len(doc.Edges) != 0 || doc.Coverage.GraphState != "unknown" {
		t.Fatal(doc.Components, doc.Coverage)
	}
	locations := map[string]string{
		"branchonly": "git+https://code.example.test/Acme/BranchOnly.git@" + strings.Repeat("a", 40),
		"released":   "git+https://code.example.test/Acme/Released.git@" + strings.Repeat("b", 40),
	}
	for _, c := range doc.Components {
		if c.Name == "unresolved" {
			if c.PURL != "" || c.Version != "" {
				t.Fatal("unresolved pin assigned an identity", c)
			}
			continue
		}
		base, query, ok := strings.Cut(c.PURL, "?")
		values, err := url.ParseQuery(query)
		if err != nil || !ok || values.Get("vcs_url") != locations[c.Name] {
			t.Fatal("Swift source locator lost", c)
		}
		if c.Name == "branchonly" && (c.Version != "" || base != "pkg:swift/code.example.test/Acme/BranchOnly") {
			t.Fatal("revision became a release version", c)
		}
		if c.Name == "released" && (c.Version != "1.2.3" || base != "pkg:swift/code.example.test/Acme/Released@1.2.3") {
			t.Fatal("repository case or version changed", c)
		}
	}
	for _, o := range doc.Origins {
		if o.VCSType != "git" {
			t.Fatal("Swift Git origin untyped", o)
		}
	}
	data, err := export.SPDX23(doc)
	if err != nil {
		t.Fatal(err)
	}
	var spdx struct {
		Packages []struct {
			Name     string
			Version  string `json:"versionInfo"`
			Location string `json:"downloadLocation"`
		}
	}
	if err := json.Unmarshal(data, &spdx); err != nil {
		t.Fatal(err)
	}
	for _, p := range spdx.Packages {
		if location, ok := locations[p.Name]; ok && p.Location != location {
			t.Fatal("SPDX lost pinned Git location", p)
		}
		if p.Name == "unresolved" && p.Location != "NOASSERTION" {
			t.Fatal("unresolved revision became an exact download location", p)
		}
	}
	data, err = export.CycloneDX(doc)
	if err != nil {
		t.Fatal(err)
	}
	var cdx struct {
		Components []struct {
			Name       string
			References []struct {
				Type string
				URL  string
			} `json:"externalReferences"`
		}
	}
	if err := json.Unmarshal(data, &cdx); err != nil {
		t.Fatal(err)
	}
	for _, c := range cdx.Components {
		if location, ok := locations[c.Name]; ok {
			found := false
			for _, r := range c.References {
				if r.Type == "vcs" && r.URL == location {
					found = true
				}
			}
			if !found {
				t.Fatal("CycloneDX lost pinned Git reference", c)
			}
		}
	}
	assertDevelopmentExports(t, doc)
}

func TestSwiftLegacyRevisionOnlyPin(t *testing.T) {
	file := filepath.Join(t.TempDir(), "Package.resolved")
	data := `{"version":1,"object":{"pins":[{"package":"branchonly","repositoryURL":"https://code.example.test/Acme/BranchOnly.git","state":{"branch":"stable","revision":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}]}}`
	if err := os.WriteFile(file, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	doc := scanDevelopmentSample(t, file)
	if len(doc.Components) != 1 || doc.Components[0].Version != "" || !strings.HasPrefix(doc.Components[0].PURL, "pkg:swift/code.example.test/Acme/BranchOnly?") || len(doc.Origins) != 1 || doc.Origins[0].VCSType != "git" {
		t.Fatal(doc)
	}
	assertDevelopmentExports(t, doc)
}
