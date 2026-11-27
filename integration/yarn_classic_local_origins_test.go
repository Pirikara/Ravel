package integration_test

import (
	"encoding/json"
	"github.com/Pirikara/Ravel/internal/export"
	"path/filepath"
	"strings"
	"testing"
)

func TestYarnClassicExplicitLocalOrigins(t *testing.T) {
	doc := scanDevelopmentSample(t, filepath.Join("..", "testdata", "fixtures", "yarn-classic-local-origins", "yarn.lock"))
	if len(doc.Components) != 3 || len(doc.Edges) != 4 {
		t.Fatal(doc.Components, doc.Edges)
	}
	local := map[string]string{}
	localIDs := map[string]string{}
	for _, c := range doc.Components {
		if c.Name == "linked" || c.Name == "archive" {
			localIDs[c.ID] = c.Name
			if c.PURL != "" {
				t.Fatal("local source became registry identity", c)
			}
			if c.Name == "linked" && c.Kind != "application" {
				t.Fatal(c)
			}
		}
	}
	for _, o := range doc.Origins {
		if name := localIDs[o.Occurrence]; name != "" {
			if o.Kind != "local" || o.Status != "declared" {
				t.Fatal(o)
			}
			local[name] = o.LocalPath
		}
	}
	if local["linked"] != "./tools/@workspace" || local["archive"] != "./archives/tool.tgz" {
		t.Fatal(local)
	}
	if doc.Coverage.OriginState != "complete_for_scope" {
		t.Fatal(doc.Coverage)
	}
	for _, format := range []string{"cdx", "spdx"} {
		var data []byte
		var err error
		if format == "cdx" {
			data, err = export.CycloneDX(doc)
		} else {
			data, err = export.SPDX23(doc)
		}
		if err != nil || !json.Valid(data) {
			t.Fatal(err)
		}
		// Both standard exports must carry the declared local location.
		if !strings.Contains(string(data), "./tools/@workspace") || !strings.Contains(string(data), "./archives/tool.tgz") {
			t.Fatalf("%s lost local location", format)
		}
	}
	assertDevelopmentExports(t, doc)
}
