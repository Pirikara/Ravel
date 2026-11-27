package export

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Pirikara/Ravel/internal/model"
)

func TestStandardSourcesRetainAmbiguityWithoutCredentials(t *testing.T) {
	doc := model.Document{Project: "test", Components: []model.Component{{ID: "p", Name: "demo", Kind: "package", Version: "1.0"}}, Origins: []model.Origin{
		{Occurrence: "p", Kind: "download_url", SafeURL: "https://user:secret@one.example.test/demo.zip?token=hidden", Status: "declared"},
		{Occurrence: "p", Kind: "download_url", SafeURL: "https://two.example.test/demo.zip", Status: "declared"},
	}}
	for _, format := range []string{"spdx", "cdx"} {
		var data []byte
		var err error
		if format == "spdx" {
			data, err = SPDX23(doc)
		} else {
			data, err = CycloneDX(doc)
		}
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), "secret") || strings.Contains(string(data), "hidden") || strings.Contains(string(data), "user:") {
			t.Fatalf("credentials leaked: %s", data)
		}
		if format == "spdx" {
			var parsed spdxDocument
			if err := json.Unmarshal(data, &parsed); err != nil {
				t.Fatal(err)
			}
			p := parsed.Packages[1]
			if p.DownloadLocation != "NOASSERTION" || !strings.Contains(p.SourceInfo, "https://one.example.test/demo.zip") || !strings.Contains(p.SourceInfo, "https://two.example.test/demo.zip") {
				t.Fatalf("ambiguous sources: %+v", p)
			}
		} else {
			var parsed struct {
				Components []struct {
					References []reference `json:"externalReferences"`
				} `json:"components"`
			}
			if err := json.Unmarshal(data, &parsed); err != nil {
				t.Fatal(err)
			}
			if len(parsed.Components[0].References) != 2 {
				t.Fatalf("lost source candidate: %s", data)
			}
		}
	}
}

func TestVCSDownloadLocationRequiresRecordedRevision(t *testing.T) {
	origins := []model.Origin{{Kind: "vcs", VCSType: "hg", SafeURL: "https://hg.example.test/project", Status: "declared"}}
	if got := packageDownloadLocation(origins, model.Component{}); got != "NOASSERTION" {
		t.Fatal(got)
	}
	origins[0].Revision = "abcdef1234567"
	origins[0].Target = "subdirectory=packages/demo"
	if got := packageDownloadLocation(origins, model.Component{}); got != "hg+https://hg.example.test/project@abcdef1234567#packages/demo" {
		t.Fatal(got)
	}
}
