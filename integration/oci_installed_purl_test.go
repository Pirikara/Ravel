package integration_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestOCIInstalledPythonAndRubyPURLsInStandardFormats(t *testing.T) {
	layout := ociTestLayout(t)
	image := ociTestImage(t, layout, "linux", "arm64", []ociTestLayer{{entries: []ociTestEntry{
		{name: "usr/local/lib/python3.13/site-packages/acme_foo_bar-1.0+cpu.dist-info/METADATA", data: []byte("Metadata-Version: 2.3\nName: Acme_Foo.BAR\nVersion: 1.0+cpu\n")},
		{name: ociPipMetadataPath, data: []byte("Metadata-Version: 2.3\nName: pip\nVersion: 25.3\n")},
		{name: ociPipVendorPath, data: []byte("CacheControl==0.14.4\n")},
		{name: ociSetuptoolsPath, data: []byte("Metadata-Version: 2.3\nName: setuptools\nVersion: 83.0.0\n")},
		{name: ociVendoredPath, data: []byte("Metadata-Version: 2.3\nName: autocommand\nVersion: 2.2.2\n")},
		{name: "usr/local/bundle/specifications/rack-3.0.0.gemspec", data: ociTestInstalledRubySpec("rack", "3.0.0", "ruby")},
		{name: "usr/local/bundle/specifications/native-1.2.3-aarch64-linux.gemspec", data: ociTestInstalledRubySpec("native", "1.2.3", "aarch64-linux")},
	}}})
	ociTestIndex(t, layout, image)
	want := map[string]bool{
		"pkg:pypi/acme-foo-bar@1.0%2Bcpu":             true,
		"pkg:pypi/pip@25.3":                           true,
		"pkg:pypi/cachecontrol@0.14.4":                true,
		"pkg:pypi/setuptools@83.0.0":                  true,
		"pkg:pypi/autocommand@2.2.2":                  true,
		"pkg:gem/rack@3.0.0":                          true,
		"pkg:gem/native@1.2.3?platform=aarch64-linux": true,
	}
	for _, format := range []string{"cyclonedx-json", "spdx-json"} {
		t.Run(format, func(t *testing.T) {
			output := filepath.Join(t.TempDir(), "sbom.json")
			cmd := exec.Command(executable, "scan", layout, "--format", format, "--output", output)
			if data, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("OCI export: %v: %s", err, data)
			}
			data, err := os.ReadFile(output)
			if err != nil {
				t.Fatal(err)
			}
			var bom struct {
				Components []struct {
					PURL       string `json:"purl"`
					Properties []struct{ Name, Value string }
				} `json:"components"`
				Packages []struct {
					Comment      string
					ExternalRefs []struct{ ReferenceType, ReferenceLocator string }
				} `json:"packages"`
			}
			if err := json.Unmarshal(data, &bom); err != nil {
				t.Fatal(err)
			}
			got := map[string]bool{}
			if format == "cyclonedx-json" {
				for _, component := range bom.Components {
					got[component.PURL] = true
					annotated := false
					for _, property := range component.Properties {
						annotated = annotated || property.Name == "ravel:purlBasis" && property.Value == "ecosystem_inferred"
					}
					if !annotated {
						t.Fatalf("inferred PURL marker missing: %#v", component)
					}
				}
			} else {
				for _, pkg := range bom.Packages {
					for _, ref := range pkg.ExternalRefs {
						if ref.ReferenceType == "purl" {
							got[ref.ReferenceLocator] = true
							if !strings.Contains(pkg.Comment, "Ravel PURL basis: ecosystem_inferred") {
								t.Fatalf("inferred PURL comment missing: %#v", pkg)
							}
						}
					}
				}
			}
			if len(got) != len(want) {
				t.Fatalf("PURL count: got %d want %d: %#v", len(got), len(want), got)
			}
			for purl := range want {
				if !got[purl] {
					t.Errorf("missing %s", purl)
				}
			}
		})
	}
}
