package integration_test

import (
	"encoding/json"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/Pirikara/Ravel/internal/model"
)

func scanBBPFixture(t *testing.T, name string, recursive bool) model.Document {
	t.Helper()
	args := []string{"scan", filepath.Join("..", "testdata", "fixtures", name), "--all", "--format", "ravel-json"}
	if recursive {
		args = append(args, "--recursive")
	}
	output, err := exec.Command(executable, args...).Output()
	if err != nil {
		t.Fatalf("scan %s: %v: %s", name, err, output)
	}
	var doc model.Document
	if err := json.Unmarshal(output, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func TestGitHubActionTokenNameDoesNotAbortRepositoryScan(t *testing.T) {
	doc := scanBBPFixture(t, "github-actions-token-merge", true)
	if doc.Coverage.Manager != "multi" || len(doc.Components) != 4 {
		t.Fatalf("merged package and workflow inputs missing: %#v", doc.Coverage)
	}
	var packageFound, actionFound, originFound, developmentFound bool
	for _, component := range doc.Components {
		packageFound = packageFound || component.Name == "is-number" && component.PURL == "pkg:npm/is-number@7.0.0"
		actionFound = actionFound || component.Name == "actions/create-github-app-token" && component.PURL != ""
	}
	for _, origin := range doc.Origins {
		originFound = originFound || origin.SafeURL == "https://github.com/actions/create-github-app-token"
	}
	for _, source := range doc.Development {
		developmentFound = developmentFound || source.SafeURL == "https://github.com/actions/create-github-app-token"
	}
	if !packageFound || !actionFound || !originFound || !developmentFound {
		t.Fatalf("action or unrelated npm package was lost: %#v", doc)
	}
}

func TestPublishedPubPackageWithLeadingUnderscore(t *testing.T) {
	doc := scanBBPFixture(t, "pub-bbp-wallet", false)
	if len(doc.Components) != 58 {
		t.Fatalf("BBP Pub lockfile was not scanned in full: got %d packages", len(doc.Components))
	}
	for _, component := range doc.Components {
		if component.Name == "_fe_analyzer_shared" {
			if component.Version != "82.0.0" || component.PURL != "pkg:pub/_fe_analyzer_shared@82.0.0" {
				t.Fatalf("published Pub package lost its identity: %#v", component)
			}
			return
		}
	}
	t.Fatal("published leading-underscore Pub package missing")
}

func TestYarnOfficialRegistryProducesNpmIdentity(t *testing.T) {
	doc := scanBBPFixture(t, "yarn-classic-yarn-registry", false)
	if len(doc.Components) != 1 || doc.Components[0].PURL != "pkg:npm/is-number@7.0.0" {
		t.Fatalf("official Yarn registry package identity missing: %#v", doc.Components)
	}
	if len(doc.Origins) != 1 || doc.Origins[0].SafeURL != "https://registry.yarnpkg.com/is-number/-/is-number-7.0.0.tgz" {
		t.Fatalf("actual Yarn distribution URL was lost: %#v", doc.Origins)
	}
}

func TestNuGetLockPreservesProjectReferences(t *testing.T) {
	doc := scanBBPFixture(t, "nuget-project-references", false)
	if doc.Coverage.Packages != 3 || doc.Coverage.Edges != 3 || doc.Coverage.GraphState != "partial" {
		t.Fatalf("NuGet project graph was dropped or overstated: %#v", doc.Coverage)
	}
	ids := map[string]string{}
	for _, c := range doc.Components {
		ids[c.Name] = c.ID
		if c.Name == "Example.Package" {
			if c.PURL != "pkg:nuget/Example.Package@2.0.0" {
				t.Fatalf("external package identity changed: %#v", c)
			}
		} else if c.Kind != "application" || c.PURL != "" || c.Version != "" {
			t.Fatalf("local project was attributed to NuGet: %#v", c)
		}
	}
	seen := map[[2]string]bool{}
	for _, e := range doc.Edges {
		seen[[2]string{e.From, e.To}] = true
	}
	for _, edge := range [][2]string{
		{ids["App.Core"], ids["App.Data"]},
		{ids["App.Core"], ids["Example.Package"]},
		{"root", ids["Example.Package"]},
	} {
		if !seen[edge] {
			t.Fatalf("NuGet edge missing: %#v", edge)
		}
	}
}
