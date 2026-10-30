package bundler_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ravel/internal/collectors/bundler"
	"ravel/internal/export"
)

func writeLock(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "Gemfile.lock")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestGraphOriginsAndRedaction(t *testing.T) {
	path := writeLock(t, `GEM
  remote: https://user:supersecret@registry.example.test/gems?token=hidden#private
  specs:
    alpha (1.0.0)
      beta (~> 2.0)
    beta (2.1.0)

GIT
  remote: https://user:anothersecret@git.example.test/team/gitgem.git?auth=hidden
  revision: 0123456789abcdef0123456789abcdef01234567
  specs:
    gitgem (0.3.0)
      beta

PATH
  remote: ../localgem
  specs:
    localgem (0.1.0)

DEPENDENCIES
  alpha
  gitgem!
  localgem!
`)
	doc, err := bundler.Collect(path, "sample")
	if err != nil {
		t.Fatal(err)
	}
	if doc.Coverage.Packages != 4 || doc.Coverage.Edges != 5 {
		t.Fatalf("unexpected graph: %#v", doc.Coverage)
	}
	if doc.Coverage.GraphState != "complete_for_scope" || doc.Coverage.OriginState != "complete_for_scope" {
		t.Fatalf("unexpected coverage: %#v", doc.Coverage)
	}
	if len(doc.Origins) != 4 {
		t.Fatalf("got %d origins", len(doc.Origins))
	}
	for _, component := range doc.Components {
		if component.PURL != "" {
			t.Fatalf("non-default registry, Git, or path package assigned RubyGems PURL: %#v", component)
		}
	}
	var sawRegistry, sawGit, sawPath bool
	for _, o := range doc.Origins {
		switch o.Kind {
		case "declared_registry":
			sawRegistry = o.SafeURL == "https://registry.example.test/gems"
		case "vcs":
			sawGit = o.SafeURL == "https://git.example.test/team/gitgem.git" && o.Revision == "0123456789abcdef0123456789abcdef01234567"
		case "local":
			sawPath = o.LocalPath == "../localgem"
		}
	}
	if !sawRegistry || !sawGit || !sawPath {
		t.Fatalf("origin semantics lost: %#v", doc.Origins)
	}
	if len(doc.Development) != 1 || doc.Development[0].SafeURL != "https://git.example.test/team/gitgem.git" || doc.Development[0].Status != "inferred_from_vcs_source" {
		t.Fatalf("Bundler Git source was not exposed as a development candidate: %#v", doc.Development)
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	cdx, err := export.CycloneDX(doc)
	if err != nil {
		t.Fatal(err)
	}
	for _, payload := range [][]byte{raw, cdx} {
		for _, secret := range []string{"supersecret", "anothersecret", "hidden", "user:"} {
			if strings.Contains(string(payload), secret) {
				t.Fatalf("secret leaked into output: %s", secret)
			}
		}
	}
}

func TestAmbiguousPackageKeepsDistinctOccurrences(t *testing.T) {
	path := writeLock(t, `GEM
  remote: https://one.example.test/
  specs:
    foo (1.0.0)
    parent (2.0.0)
      foo

GEM
  remote: https://two.example.test/
  specs:
    foo (1.0.0)

DEPENDENCIES
  parent
`)
	doc, err := bundler.Collect(path, "sample")
	if err != nil {
		t.Fatal(err)
	}
	if doc.Coverage.Packages != 3 || doc.Coverage.GraphState != "partial" || doc.Coverage.OriginState != "complete_for_scope" {
		t.Fatalf("unexpected coverage: %#v", doc.Coverage)
	}
	if doc.Coverage.Edges != 1 {
		t.Fatalf("ambiguous dependency should be omitted: %#v", doc.Edges)
	}
	if len(doc.Origins) != 3 {
		t.Fatalf("sources should remain distinct: %#v", doc.Origins)
	}
}

func TestMultiplePlatformsDoNotBecomeUnconditionalSBOMEdges(t *testing.T) {
	path := writeLock(t, `GEM
  remote: https://rubygems.org/
  specs:
    alpha (1.0.0)
      beta
    beta (2.0.0-x86_64-linux)

PLATFORMS
  ruby
  x86_64-linux

DEPENDENCIES
  alpha
`)
	doc, err := bundler.Collect(path, "sample")
	if err != nil {
		t.Fatal(err)
	}
	if doc.Coverage.GraphState != "partial" || len(doc.Edges) != 2 {
		t.Fatalf("expected conditional graph, got %#v", doc.Coverage)
	}
	for _, e := range doc.Edges {
		if e.Condition == "" {
			t.Fatalf("unconditional edge: %#v", e)
		}
	}
	var foundPlatform bool
	for _, c := range doc.Components {
		if c.Name == "beta" {
			foundPlatform = c.Version == "2.0.0" && c.Platform == "x86_64-linux" && strings.Contains(c.PURL, "platform=x86_64-linux")
		}
	}
	if !foundPlatform {
		t.Fatalf("platform variant lost: %#v", doc.Components)
	}
	cdx, err := export.CycloneDX(doc)
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		Dependencies []any `json:"dependencies"`
	}
	if err := json.Unmarshal(cdx, &parsed); err != nil {
		t.Fatal(err)
	}
	if len(parsed.Dependencies) != 0 {
		t.Fatalf("conditional edges leaked into CycloneDX: %s", cdx)
	}
}
