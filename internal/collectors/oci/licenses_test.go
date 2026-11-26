package oci

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Pirikara/Ravel/internal/model"
)

func TestImageLicenseCorrelationPreservesSourceAndInstalledDeclaration(t *testing.T) {
	files := map[string]imageProjectFile{}
	for _, name := range []string{"package-lock.json", "package.json"} {
		data, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "licenses", "npm-v2", name))
		if err != nil {
			t.Fatal(err)
		}
		files["app/"+name] = imageProjectFile{data: data, layer: "sha256:sample"}
	}
	for _, installedValue := range []string{"", "BSD-3-Clause"} {
		e := model.Evidence{Collector: "node-package-json", InputPath: "oci:sha256:sample!/app/node_modules/standard/package.json"}
		c := model.Component{ID: "installed", Kind: "package", Name: "standard", Version: "1.0.0", Context: "location=/app/node_modules/standard/package.json", PURL: "pkg:npm/standard@1.0.0", Evidence: []model.Evidence{e}}
		if installedValue != "" {
			c.Licenses = []model.LicenseDeclaration{{Kind: "license", Value: installedValue, Evidence: []model.Evidence{e}}}
		}
		doc := model.Document{Project: "test", Components: []model.Component{c}}
		if err := correlateImageLocks(&doc, files); err != nil {
			t.Fatal(err)
		}
		got := doc.Components[0].Licenses
		want := installedValue
		if want == "" {
			want = "MIT"
		}
		if len(got) != 1 || got[0].Value != want {
			t.Fatalf("installed=%q: %#v issues=%+v", installedValue, got, doc.Coverage.Issues)
		}
		if installedValue == "" {
			for _, ev := range got[0].Evidence {
				if !strings.HasPrefix(ev.InputPath, "oci:sha256:sample!/app/") || ev.Method != "image-lockfile-correlation" {
					t.Fatalf("staging path or source claim leaked: %+v", ev)
				}
			}
		}
	}
	locks, issues, err := parseImageLocks(files, "test")
	if err != nil || len(issues) != 0 {
		t.Fatalf("%v %+v", err, issues)
	}
	for _, lock := range locks {
		if lock.doc.Root != nil {
			for _, d := range lock.doc.Root.Licenses {
				for _, e := range d.Evidence {
					if !strings.HasPrefix(e.InputPath, "oci:") {
						t.Fatal(e)
					}
				}
			}
		}
	}
}

func TestInstalledRubyAndRLicenses(t *testing.T) {
	data := []byte("# stub: licensed 1.0.0 ruby lib\nGem::Specification.new do |s|\n  s.name = \"licensed\"\n  s.version = \"1.0.0\"\n  s.licenses = [\"MIT\".freeze, \"Ruby\".freeze]\nend\n")
	path := "usr/local/bundle/specifications/licensed-1.0.0.gemspec"
	doc, err := inspectInstalledRubySpec(data, "oci:sha256:sample!/"+path, "test", path)
	if err != nil || len(doc.Components) != 1 || len(doc.Components[0].Licenses) != 2 {
		t.Fatalf("%v %+v", err, doc.Components)
	}
	rdata := []byte(rTestDescription + "License: MIT + file LICENSE\n")
	record, installed, err := inspectInstalledRDescription(rdata, "oci:sha256:sample!/"+rTestPath, rTestPath, nil)
	if err != nil || !installed || len(record.component.Licenses) != 1 || record.component.Licenses[0].Expression != "" || record.component.Licenses[0].Value != "MIT + file LICENSE" {
		t.Fatalf("%v %+v", err, record.component)
	}
}
