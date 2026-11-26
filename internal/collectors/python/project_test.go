package python

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Pirikara/Ravel/internal/collectors/common"
	"github.com/Pirikara/Ravel/internal/model"
)

func TestProjectDevelopmentBoundaries(t *testing.T) {
	for _, test := range []struct {
		name, manifest, status string
		count                  int
		application            *model.Component
		issue                  string
	}{
		{"pep621", "[project]\nname='demo'\nversion='1.0'\n[project.urls]\nRepository='https://code.example.test/demo'", "declared", 1, nil, ""},
		{"homepage", "[project]\nname='demo'\n[project.urls]\nHomepage='https://github.com/owner/demo'", "inferred_from_homepage", 1, nil, ""},
		{"poetry", "[tool.poetry]\nname='demo'\nrepository='https://code.example.test/demo'", "declared", 1, nil, ""},
		{"dynamic", "[project]\nname='demo'\ndynamic=['urls']\n[project.urls]\nRepository='https://code.example.test/demo'", "", 0, nil, "development_source_unresolved"},
		{"no-identity", "[project.urls]\nRepository='https://code.example.test/demo'", "", 0, nil, ""},
		{"pep621-precedence", "[project]\nname='demo'\n[tool.poetry]\nname='other'\nrepository='https://code.example.test/other'", "", 0, nil, ""},
		{"docs-only", "[project]\nname='demo'\n[project.urls]\nDocumentation='https://github.com/owner/demo'", "", 0, nil, ""},
		{"bad-toml", "[project", "", 0, nil, "development_source_unresolved"},
		{"matching-lock", "[project]\nname='demo'\nversion='1.0'\n[project.urls]\nSource='https://code.example.test/demo'", "declared", 1, &model.Component{ID: "app", Kind: "application", Name: "demo", Version: "1.0"}, ""},
		{"stale-version", "[project]\nname='demo'\nversion='2.0'\n[project.urls]\nSource='https://code.example.test/demo'", "", 0, &model.Component{ID: "app", Kind: "application", Name: "demo", Version: "1.0"}, "manifest_identity_mismatch"},
		{"wrong-application", "[project]\nname='other'\n[project.urls]\nSource='https://code.example.test/other'", "", 0, &model.Component{ID: "app", Kind: "application", Name: "demo", Version: "1.0"}, "manifest_identity_mismatch"},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.WriteFile(filepath.Join(root, "pyproject.toml"), []byte(test.manifest), 0600); err != nil {
				t.Fatal(err)
			}
			doc := common.NewDocument(filepath.Join(root, "uv.lock"), "test", "uv", nil)
			doc.Components = append(doc.Components, model.Component{ID: "dependency", Kind: "package", Name: "dependency", Version: "1"})
			if test.application != nil {
				doc.Components = append(doc.Components, *test.application)
			}
			collectProjectDevelopment(&doc, filepath.Join(root, "uv.lock"))
			if len(doc.Development) != test.count {
				t.Fatal(doc.Development, doc.Coverage.Issues)
			}
			if test.count > 0 {
				want := "root"
				if test.application != nil {
					want = "app"
				}
				got := doc.Development[0]
				if got.Occurrence != want || got.Status != test.status || got.Evidence.InputDigest == "" {
					t.Fatal(got)
				}
			}
			found := false
			for _, issue := range doc.Coverage.Issues {
				found = found || issue.Code == test.issue
			}
			if (test.issue != "") != found {
				t.Fatal(doc.Coverage.Issues)
			}
			if len(doc.Origins) != 0 {
				t.Fatal("project URL became a download origin")
			}
		})
	}
}
