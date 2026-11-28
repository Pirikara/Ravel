package integration_test

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOCIDpkgStatusFragments(t *testing.T) {
	alpha := []byte("Package: alpha\nVersion: 1.2.3\nArchitecture: arm64\nDepends: beta (>= 2.0)\n")
	beta := []byte("Package: beta\nVersion: 2.1\nArchitecture: arm64\n")
	base := []ociTestEntry{{name: "etc/os-release", data: []byte("ID=debian\nVERSION_ID=12\n")}, {name: "var/lib/dpkg/status.d/alpha", data: alpha}, {name: "var/lib/dpkg/status.d/beta", data: beta}, {name: "var/lib/dpkg/status.d/ignored.md5sums", data: alpha}}
	for _, tc := range []struct {
		name  string
		upper []ociTestEntry
		want  int
	}{
		{name: "kept", want: 2},
		{name: "one_removed", upper: []ociTestEntry{{name: "var/lib/dpkg/status.d/.wh.alpha"}}, want: 1},
		{name: "opaque", upper: []ociTestEntry{{name: "var/lib/dpkg/status.d/.wh..wh..opq"}}, want: 0},
		{name: "parent_removed", upper: []ociTestEntry{{name: "var/lib/dpkg/.wh.status.d"}}, want: 0},
		{name: "parent_replaced", upper: []ociTestEntry{{name: "var/lib/dpkg/status.d", data: []byte("ordinary file")}}, want: 0},
		{name: "active_database_preferred", upper: []ociTestEntry{{name: "var/lib/dpkg/status", data: []byte("Package: active\nVersion: 3\nArchitecture: arm64\nStatus: install ok installed\n")}}, want: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			layout := ociTestLayout(t)
			layers := []ociTestLayer{{entries: base}}
			if len(tc.upper) > 0 {
				layers = append(layers, ociTestLayer{entries: tc.upper})
			}
			image := ociTestImage(t, layout, "linux", "arm64", layers)
			ociTestIndex(t, layout, image)
			doc, out, code := ociTestScan(t, layout)
			if code != 0 || len(doc.Components) != tc.want {
				t.Fatal(code, out, doc)
			}
			if tc.name == "kept" {
				if len(doc.Edges) != 3 || hasOCICoverageIssue(doc, "os_package_database_not_found") {
					t.Fatal("fragment graph or OS coverage missing", doc)
				}
				for _, c := range doc.Components {
					if !strings.HasPrefix(c.PURL, "pkg:deb/debian/") || c.PURLBasis != "ecosystem_inferred" || c.Evidence[0].Collector != "dpkg-status-fragment" {
						t.Fatal(c)
					}
				}
			}
			if tc.name == "active_database_preferred" && doc.Components[0].Name != "active" {
				t.Fatal("stale fragment overrode active status database", doc)
			}
		})
	}
}

func TestOCIComposerPHARFinalLayers(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "testdata", "archives", "composer", "deflated.phar"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		upper []ociTestEntry
		want  int
	}{
		{name: "kept", want: 3},
		{name: "removed", upper: []ociTestEntry{{name: "usr/bin/.wh.composer"}}, want: 0},
		{name: "replaced", upper: []ociTestEntry{{name: "usr/bin/composer", data: []byte("#!/bin/sh\nexit 0\n"), mode: 0755}}, want: 0},
		{name: "parent_removed", upper: []ociTestEntry{{name: "usr/.wh.bin"}}, want: 0},
		{name: "opaque", upper: []ociTestEntry{{name: "usr/bin/.wh..wh..opq"}}, want: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			layout := ociTestLayout(t)
			layers := []ociTestLayer{{entries: []ociTestEntry{{name: "usr/bin/composer", data: data, mode: 0755}}}}
			if len(tc.upper) > 0 {
				layers = append(layers, ociTestLayer{entries: tc.upper})
			}
			image := ociTestImage(t, layout, "linux", "arm64", layers)
			ociTestIndex(t, layout, image)
			doc, out, code := ociTestScan(t, layout)
			if code != 0 || len(doc.Components) != tc.want {
				t.Fatal("PHAR final-layer inventory wrong", code, out, doc)
			}
		})
	}
}

func TestOCIJavaReleaseRuntime(t *testing.T) {
	release := []byte("JAVA_VERSION=\"21.0.7\"\nJAVA_RUNTIME_VERSION=\"21.0.7+6-LTS\"\nIMPLEMENTOR=\"Example Runtime\"\nSOURCE_REPO=\"https://example.test/runtime/source.git\"\nBUILD_SOURCE_REPO=\"https://example.test/build/scripts.git\"\n")
	launcher := runtimeELFFixture([]byte("\x00JLI_Launch\x00"))
	for _, home := range []string{"opt/java/openjdk", "usr/lib/jvm/example-jre", "usr/local/openjdk-21"} {
		t.Run(home, func(t *testing.T) {
			layout := ociTestLayout(t)
			image := ociTestImage(t, layout, "linux", "arm64", []ociTestLayer{{entries: []ociTestEntry{{name: home + "/release", data: release}, {name: home + "/bin/java", data: launcher, mode: 0755}}}})
			ociTestIndex(t, layout, image)
			doc, out, code := ociTestScan(t, layout)
			if code != 0 || len(doc.Components) != 1 {
				t.Fatal(code, out, doc)
			}
			c := doc.Components[0]
			digest := sha256.Sum256(release)
			if c.Name != "java" || c.Version != "21.0.7+6-LTS" || c.PURL != "pkg:generic/java@21.0.7%2B6-LTS" || len(c.Hashes) != 0 || len(c.Evidence) != 2 || c.Evidence[0].InputDigest != "sha256:"+hex.EncodeToString(digest[:]) || c.Evidence[0].Line != 2 || c.Evidence[0].Collector != "java-runtime-release" || !hasOCICoverageIssue(doc, "java_runtime_binary_version_unverified") {
				t.Fatal("Java release interpretation/evidence incorrect", c, doc.Coverage)
			}
			if len(doc.Development) != 1 || doc.Development[0].SafeURL != "https://example.test/runtime/source.git" || doc.Development[0].Status != "declared" || doc.Development[0].Evidence.Line != 4 {
				t.Fatal("runtime source repository confused with build tooling", doc.Development)
			}
		})
	}
	for _, tc := range []struct {
		name           string
		upper          []ociTestEntry
		initialRelease []byte
	}{
		{name: "release_removed", upper: []ociTestEntry{{name: "opt/java/openjdk/.wh.release"}}},
		{name: "launcher_removed", upper: []ociTestEntry{{name: "opt/java/openjdk/bin/.wh.java"}}},
		{name: "launcher_script", upper: []ociTestEntry{{name: "opt/java/openjdk/bin/java", data: []byte("#!/bin/sh\nexit 0\n"), mode: 0755}}},
		{name: "launcher_link", upper: []ociTestEntry{{name: "opt/java/openjdk/bin/java", typeflag: tar.TypeSymlink, linkname: "/bin/false"}}},
		{name: "opaque_home", upper: []ociTestEntry{{name: "opt/java/openjdk/.wh..wh..opq"}}},
		{name: "conflicting_version", initialRelease: []byte("JAVA_VERSION=\"21.0.7\"\nJAVA_RUNTIME_VERSION=\"17.0.14+3\"\n")},
		{name: "dynamic_value", initialRelease: []byte("JAVA_VERSION=$JAVA_RUNTIME_VERSION\n")},
		{name: "duplicate_version", initialRelease: []byte("JAVA_VERSION=\"21\"\nJAVA_VERSION=\"17\"\n")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := release
			if tc.initialRelease != nil {
				data = tc.initialRelease
			}
			layout := ociTestLayout(t)
			layers := []ociTestLayer{{entries: []ociTestEntry{{name: "opt/java/openjdk/release", data: data}, {name: "opt/java/openjdk/bin/java", data: launcher, mode: 0755}}}}
			if tc.upper != nil {
				layers = append(layers, ociTestLayer{entries: tc.upper})
			}
			image := ociTestImage(t, layout, "linux", "arm64", layers)
			ociTestIndex(t, layout, image)
			doc, out, code := ociTestScan(t, layout)
			if code != 0 || len(doc.Components) != 0 {
				t.Fatal("unavailable/stale Java runtime retained", code, out, doc)
			}
		})
	}
}
