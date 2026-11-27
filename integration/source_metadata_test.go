package integration_test

import (
	"encoding/json"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/Pirikara/Ravel/internal/model"
	"github.com/pelletier/go-toml/v2"
	"gopkg.in/yaml.v3"
)

func assertMetadataPointers(t *testing.T, doc model.Document) {
	t.Helper()
	files := map[string]any{}
	check := func(e model.Evidence) {
		if e.Pointer == "" {
			return
		}
		value, found := files[e.InputPath]
		if !found {
			data, err := os.ReadFile(e.InputPath)
			if err != nil {
				t.Fatal(err)
			}
			switch filepath.Ext(e.InputPath) {
			case ".toml":
				var d map[string]any
				if err := toml.Unmarshal(data, &d); err != nil {
					t.Fatal(err)
				}
				value = d
			default:
				if json.Valid(data) {
					if err := json.Unmarshal(data, &value); err != nil {
						t.Fatal(err)
					}
				} else {
					if err := yaml.Unmarshal(data, &value); err != nil {
						t.Fatal(err)
					}
				}
			}
			files[e.InputPath] = value
		}
		for _, part := range strings.Split(strings.TrimPrefix(e.Pointer, "/"), "/") {
			part = strings.ReplaceAll(strings.ReplaceAll(part, "~1", "/"), "~0", "~")
			switch v := value.(type) {
			case map[string]any:
				var ok bool
				value, ok = v[part]
				if !ok {
					t.Fatalf("evidence does not resolve: %#v", e)
				}
			case []any:
				i, err := strconv.Atoi(part)
				if err != nil || i < 0 || i >= len(v) {
					t.Fatalf("invalid array evidence: %#v", e)
				}
				value = v[i]
			default:
				t.Fatalf("evidence traverses a scalar: %#v", e)
			}
		}
	}
	for _, c := range doc.Components {
		for _, e := range c.Evidence {
			check(e)
		}
		for _, l := range c.Licenses {
			for _, e := range l.Evidence {
				check(e)
			}
		}
	}
	for _, e := range doc.Edges {
		check(e.Evidence)
	}
	for _, o := range doc.Origins {
		check(o.Evidence)
	}
	for _, d := range doc.Development {
		check(d.Evidence)
	}
}

func TestRenvRichMetadata(t *testing.T) {
	doc := scanRenv(t, filepath.Join("..", "testdata", "fixtures", "renv-rich-metadata"))
	if len(doc.Components) != 6 || len(doc.Edges) != 4 || len(doc.Development) != 1 {
		t.Fatal(doc.Components, doc.Edges, doc.Development)
	}
	ids := map[string]string{}
	for _, c := range doc.Components {
		ids[c.ID] = c.Name
		if len(c.Hashes) != 0 {
			t.Fatal("renv cache hash became an artifact hash", c)
		}
		if c.Name == "Optional" && c.PURL != "" {
			t.Fatal("local package received registry identity", c)
		}
		if c.Name == "Analyzer" && (c.PURL != "pkg:cran/Analyzer@2.0.0" || len(c.Licenses) != 1 || c.Licenses[0].Value != "MIT") {
			t.Fatal("R identity or license omitted", c)
		}
		if c.Name == "Headers" {
			_, query, _ := strings.Cut(c.PURL, "?")
			values, err := url.ParseQuery(query)
			if err != nil || values.Get("repository_url") != "https://r.example.test/packages" {
				t.Fatal("private R repository discarded", c)
			}
		}
	}
	legacy := 0
	for _, e := range doc.Edges {
		if ids[e.From] != "Analyzer" || ids[e.To] == "Optional" || e.Condition == "" {
			t.Fatal("dependency declaration misclassified", e)
		}
		if ids[e.To] == "Legacy" {
			legacy++
			if e.Evidence.Pointer != "/Packages/Analyzer/Requirements/2" {
				t.Fatal(e)
			}
		}
		if strings.Contains(e.Condition, "category=LinkingTo") && (!strings.Contains(e.Condition, "kind=build") || ids[e.To] != "Headers") {
			t.Fatal("R build category lost", e)
		}
	}
	if legacy != 1 || !dotnetIssue(doc, "renv_metadata_invalid") || !dotnetIssue(doc, "unresolved_dependency") {
		t.Fatal(doc.Coverage)
	}
	if d := doc.Development[0]; d.Status != "inferred_from_project_url" || d.SafeURL != "https://github.com/example/Analyzer" {
		t.Fatal(d)
	}
	assertMetadataPointers(t, doc)
	assertDevelopmentExports(t, doc)
}

func TestRenvSourceKinds(t *testing.T) {
	doc := scanRenv(t, filepath.Join("..", "testdata", "fixtures", "renv-source-kinds"))
	names := map[string]string{}
	for _, c := range doc.Components {
		names[c.ID] = c.Name
	}
	if len(doc.Components) != 5 || len(doc.Origins) != 4 {
		t.Fatal(doc.Components, doc.Origins)
	}
	for _, o := range doc.Origins {
		switch names[o.Occurrence] {
		case "archive":
			if o.Kind != "download_url" || o.SafeURL != "https://files.example.test/source.tar.gz" || o.VCSType != "" {
				t.Fatal(o)
			}
		case "localpkg":
			if o.Kind != "local" || o.LocalPath != "../localpkg" {
				t.Fatal(o)
			}
		case "publicpkg":
			if o.VCSType != "git" || o.SafeURL != "https://github.com/example/publicpkg" {
				t.Fatal(o)
			}
		case "unknown":
			if o.VCSType != "" {
				t.Fatal("unknown remote assumed Git", o)
			}
		default:
			t.Fatal("enterprise remote mapped to public GitHub", o)
		}
	}
	assertMetadataPointers(t, doc)
}

func TestPixiSourceBuildSelections(t *testing.T) {
	doc := scanDevelopmentSample(t, filepath.Join("..", "testdata", "fixtures", "pixi-source-builds"))
	if len(doc.Components) != 4 || len(doc.Edges) != 4 {
		t.Fatal(doc.Components, doc.Edges)
	}
	ids := map[string]string{}
	sourceIDs := map[string]bool{}
	unknown := 0
	for _, c := range doc.Components {
		ids[c.ID] = c.Name
		if len(c.Licenses) != 1 {
			t.Fatal("Pixi license omitted", c)
		}
		if c.Name == "alpha" {
			sourceIDs[c.ID] = true
			if c.PURL != "" || len(c.Hashes) != 0 || !strings.Contains(c.Context, "source-variant=") {
				t.Fatal("source configuration became a distribution assertion", c)
			}
			if c.Version == "" {
				unknown++
				if c.Kind != "module" {
					t.Fatal(c)
				}
			}
		} else if c.Name != "libbase" {
			t.Fatal("unselected build package included in runtime inventory", c)
		}
	}
	if len(sourceIDs) != 3 || unknown != 1 || !dotnetIssue(doc, "pixi_source_build_graph_unavailable") {
		t.Fatal(doc.Coverage)
	}
	for _, e := range doc.Edges {
		if e.Condition == "" || (e.From != "root" && (ids[e.From] != "alpha" || ids[e.To] != "libbase")) {
			t.Fatal(e)
		}
	}
	assertMetadataPointers(t, doc)
	assertDevelopmentExports(t, doc)
}

func TestPixiSourceOriginsAndStandardLocations(t *testing.T) {
	input := filepath.Join("..", "testdata", "fixtures", "pixi-source-origins")
	doc := scanDevelopmentSample(t, input)
	names := map[string]string{}
	if len(doc.Components) != 4 || len(doc.Origins) != 4 {
		t.Fatal(doc.Components, doc.Origins)
	}
	for _, c := range doc.Components {
		names[c.ID] = c.Name
		if c.PURL != "" || len(c.Hashes) != 0 {
			t.Fatal(c)
		}
	}
	for _, o := range doc.Origins {
		switch names[o.Occurrence] {
		case "local":
			if o.LocalPath != "../directory with spaces" {
				t.Fatal(o)
			}
		case "archive":
			if o.Kind != "download_url" || o.SafeURL != "https://files.example.test/source.tar.gz" {
				t.Fatal(o)
			}
		case "gitpin":
			if o.VCSType != "git" || o.SafeURL != "https://code.example.test/team/repo.git" || o.Revision != strings.Repeat("a", 40) {
				t.Fatal(o)
			}
		case "branch":
			if o.VCSType != "git" || o.Revision != "" {
				t.Fatal("branch assigned an immutable revision", o)
			}
		}
	}
	out, err := exec.Command(executable, "scan", input, "--format", "spdx-json").Output()
	if err != nil {
		t.Fatal(err)
	}
	var bom struct {
		Packages []struct {
			Name     string
			Location string `json:"downloadLocation"`
		}
	}
	if err := json.Unmarshal(out, &bom); err != nil {
		t.Fatal(err)
	}
	locations := map[string]string{"local": "NOASSERTION", "branch": "NOASSERTION", "archive": "https://files.example.test/source.tar.gz", "gitpin": "git+https://code.example.test/team/repo.git@" + strings.Repeat("a", 40)}
	for _, c := range bom.Packages {
		if want, ok := locations[c.Name]; ok && c.Location != want {
			t.Fatal("source location changed", c)
		}
	}
	assertMetadataPointers(t, doc)
}

func TestArrayDependencyEvidenceResolves(t *testing.T) {
	for _, fixture := range []string{"julia-v2", "pixi-v7", "renv-basic", "renv-rich-metadata"} {
		t.Run(fixture, func(t *testing.T) {
			doc := scanDevelopmentSample(t, filepath.Join("..", "testdata", "fixtures", fixture))
			assertMetadataPointers(t, doc)
		})
	}
}
