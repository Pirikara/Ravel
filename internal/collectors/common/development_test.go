package common

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Pirikara/Ravel/internal/model"
)

func TestNodeDevelopmentMetadata(t *testing.T) {
	for _, test := range []struct{ value, url, directory string }{
		{`"user/project"`, "https://github.com/user/project.git", ""},
		{`"github:user/project"`, "https://github.com/user/project.git", ""},
		{`"gitlab:team/project"`, "https://gitlab.com/team/project.git", ""},
		{`"gitlab:team/subgroup/project"`, "https://gitlab.com/team/subgroup/project.git", ""},
		{`"github:owner/project#main"`, "https://github.com/owner/project.git", ""},
		{`"bitbucket:team/project"`, "https://bitbucket.org/team/project.git", ""},
		{`"gist:abc123"`, "https://gist.github.com/abc123.git", ""},
		{`{"type":"git","url":"git+https://user:secret@code.example.test/team/project.git?token=secret#main","directory":"packages/sub"}`, "https://code.example.test/team/project.git", "packages/sub"},
		{`"git@code.example.test:team/project.git"`, "ssh://code.example.test/team/project.git", ""},
		{`null`, "", ""}, {`""`, "", ""}, {`false`, "", ""},
		{`"not-a-url"`, "", ""}, {`"../local"`, "", ""},
	} {
		t.Run(test.value, func(t *testing.T) {
			doc := NewDocument("sample/package.json", "sample", "npm", nil)
			CollectNodeDevelopment(&doc, "pkg", []byte(`{"repository":`+test.value+`}`), model.Evidence{InputPath: "sample/package.json", InputDigest: "sha256:sample"})
			if test.url == "" {
				if len(doc.Development) != 0 {
					t.Fatal(doc.Development)
				}
				return
			}
			if len(doc.Development) != 1 || doc.Development[0].SafeURL != test.url || doc.Development[0].Directory != test.directory || doc.Development[0].Status != "declared" {
				t.Fatal(doc.Development)
			}
			if len(doc.Origins) != 0 || doc.Development[0].Evidence.Pointer != "/repository" {
				t.Fatal("repository promoted to origin or evidence lost", doc)
			}
			raw, _ := json.Marshal(doc)
			if strings.Contains(string(raw), "secret") {
				t.Fatal("URL credentials retained")
			}
		})
	}
}

func TestRepositoryHomepageRequiresRecognizedRepositoryShape(t *testing.T) {
	for _, value := range []string{"https://github.com/owner/repo", "https://gitlab.com/team/project/", "https://bitbucket.org/team/project", "https://codeberg.org/team/project"} {
		if RepositoryHomepage(value) == "" {
			t.Fatal(value)
		}
	}
	for _, value := range []string{"https://example.test/project", "https://github.com/owner", "https://github.com/orgs/team", "https://github.com/owner/repo/issues", "https://github.io/owner/repo", "https://github.com/owner/../repo"} {
		if RepositoryHomepage(value) != "" {
			t.Fatal(value)
		}
	}
}
