package integration_test

import (
	"github.com/Pirikara/Ravel/internal/export"
	"path/filepath"
	"strings"
	"testing"
)

func TestGoLocalReplacementLocation(t *testing.T) {
	doc := scanDevelopmentSample(t, filepath.Join("..", "testdata", "fixtures", "go-local-replacement-location", "go.mod"))
	if len(doc.Components) != 4 || len(doc.Edges) != 3 {
		t.Fatal(doc.Components, doc.Edges)
	}
	ids := map[string]string{}
	for _, c := range doc.Components {
		ids[c.ID] = c.Name
		if (c.Name == "example.com/local" || c.Name == "example.com/fork") && c.PURL != "" {
			t.Fatal("replacement became original registry identity", c)
		}
	}
	local, versioned := false, false
	for _, o := range doc.Origins {
		if ids[o.Occurrence] == "example.com/local" {
			local = o.Kind == "local" && o.LocalPath == "./local modules/component" && o.Status == "declared"
		}
		if ids[o.Occurrence] == "example.com/fork" {
			versioned = o.Kind == "module_replacement" && o.Target == "fork.example/component@v1.3.0"
		}
	}
	if !local || !versioned {
		t.Fatal(doc.Origins)
	}
	for _, e := range doc.Edges {
		if ids[e.To] == "example.com/indirect" {
			t.Fatal("indirect declaration became a direct edge", e)
		}
	}
	if doc.Coverage.GraphState == "complete_for_scope" {
		t.Fatal("static declaration claimed a selected graph")
	}
	for _, format := range []string{"cdx", "spdx"} {
		var data []byte
		var err error
		if format == "cdx" {
			data, err = export.CycloneDX(doc)
		} else {
			data, err = export.SPDX23(doc)
		}
		if err != nil || !strings.Contains(string(data), "./local modules/component") || !strings.Contains(string(data), "fork.example/component@v1.3.0") {
			t.Fatalf("%s lost replacement information: %v", format, err)
		}
	}
	assertDevelopmentExports(t, doc)
}

func TestGoVendorLocalReplacementLocation(t *testing.T) {
	doc := scanDevelopmentSample(t, filepath.Join("..", "testdata", "fixtures", "go-vendor-local", "vendor", "modules.txt"))
	local := ""
	for _, c := range doc.Components {
		if c.Name == "github.com/acme/alpha" {
			local = c.ID
			if c.PURL != "" {
				t.Fatal("local vendor became registry identity", c)
			}
		}
	}
	if local == "" {
		t.Fatal(doc.Components)
	}
	found := false
	for _, o := range doc.Origins {
		if o.Occurrence == local {
			found = o.Kind == "local" && o.LocalPath == "./fork" && o.Status == "declared"
		}
	}
	if !found {
		t.Fatal("vendor local replacement directory lost", doc.Origins)
	}
	for _, format := range []string{"cdx", "spdx"} {
		var data []byte
		var err error
		if format == "cdx" {
			data, err = export.CycloneDX(doc)
		} else {
			data, err = export.SPDX23(doc)
		}
		if err != nil || !strings.Contains(string(data), "./fork") {
			t.Fatalf("%s lost local vendor location: %v", format, err)
		}
	}
	assertDevelopmentExports(t, doc)
}
