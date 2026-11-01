package nuget

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPackagesConfigRejectsInvalidXML(t *testing.T) {
	for _, data := range []string{
		`<other><package id="A" version="1.0.0" /></other>`,
		`<!DOCTYPE packages [<!ENTITY secret "unsafe">]><packages />`,
		`<packages><package id="A" version="[1,2)" /></packages>`,
		`<packages><package id="A" version="1.0.0" /><package id="a" version="2.0.0" /></packages>`,
		`<packages><package id="A" version="1.0.0"><bad /></package></packages>`,
		`<packages><package id="A" version="1.0.0" developmentDependency="maybe" /></packages>`,
		`<packages><package id="A" version="1.0.0" id="B" /></packages>`,
	} {
		filename := filepath.Join(t.TempDir(), "packages.config")
		if err := os.WriteFile(filename, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := CollectPackagesConfig(filename, "sample"); err == nil {
			t.Fatalf("invalid packages.config accepted: %s", data)
		}
	}
}

func TestPackagesConfigUTF8BOM(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "packages.config")
	data := append([]byte{0xef, 0xbb, 0xbf}, []byte(`<?xml version="1.0" encoding="utf-8"?><packages><package id="Example.Core" version="2.1.0" targetFramework="net45" /></packages>`)...)
	if err := os.WriteFile(filename, data, 0o644); err != nil {
		t.Fatal(err)
	}
	doc, err := CollectPackagesConfig(filename, "sample")
	if err != nil || doc.Coverage.Packages != 1 || doc.Components[0].Name != "Example.Core" || doc.Components[0].Version != "2.1.0" {
		t.Fatalf("NuGet BOM input: %#v %v", doc.Coverage, err)
	}
}
