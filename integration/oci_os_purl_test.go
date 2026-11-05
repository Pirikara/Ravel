package integration_test

import (
	"archive/tar"
	"strings"
	"testing"
)

func TestOCIOSPackagePURLsRequireMatchingFinalRelease(t *testing.T) {
	tests := []struct {
		name        string
		packagePath string
		fixture     string
		layers      [][]ociTestEntry
		packageName string
		wantPURL    string
	}{
		{
			name: "debian-etc-release", packagePath: "var/lib/dpkg/status", fixture: "dpkg-basic",
			layers:      [][]ociTestEntry{{{name: "etc/os-release", data: []byte("ID=debian\nVERSION_ID=\"12\"\n")}}},
			packageName: "base-files", wantPURL: "pkg:deb/debian/base-files@12.4%2Bdeb12u9?arch=amd64&distro=debian-12",
		},
		{
			name: "alpine-symlink", packagePath: "lib/apk/db/installed", fixture: "apk-basic",
			layers:      [][]ociTestEntry{{{name: "usr/lib/os-release", data: []byte("ID=alpine\nVERSION_ID=3.20.1\n")}, {name: "etc/os-release", typeflag: tar.TypeSymlink, linkname: "../usr/lib/os-release"}}},
			packageName: "busybox", wantPURL: "pkg:apk/alpine/busybox@1.36.1-r1?arch=x86_64&distro=alpine-3.20.1",
		},
		{
			name: "etc-overrides-usr", packagePath: "var/lib/dpkg/status", fixture: "dpkg-basic",
			layers:      [][]ociTestEntry{{{name: "usr/lib/os-release", data: []byte("ID=debian\nVERSION_ID=12\n")}, {name: "etc/os-release", data: []byte("ID=ubuntu\nVERSION_ID=24.04\n")}}},
			packageName: "base-files", wantPURL: "pkg:deb/ubuntu/base-files@12.4%2Bdeb12u9?arch=amd64&distro=ubuntu-24.04",
		},
		{
			name: "database-mismatch", packagePath: "var/lib/dpkg/status", fixture: "dpkg-basic",
			layers:      [][]ociTestEntry{{{name: "etc/os-release", data: []byte("ID=alpine\nVERSION_ID=3.20.1\n")}}},
			packageName: "base-files",
		},
		{
			name: "unsupported-symlink", packagePath: "var/lib/dpkg/status", fixture: "dpkg-basic",
			layers:      [][]ociTestEntry{{{name: "usr/lib/os-release", data: []byte("ID=debian\nVERSION_ID=12\n")}, {name: "etc/os-release", typeflag: tar.TypeSymlink, linkname: "other"}}},
			packageName: "base-files",
		},
		{
			name: "release-parent-replaced", packagePath: "var/lib/dpkg/status", fixture: "dpkg-basic",
			layers:      [][]ociTestEntry{{{name: "etc/os-release", data: []byte("ID=debian\nVERSION_ID=12\n")}}, {{name: "etc", typeflag: tar.TypeSymlink, linkname: "other"}}},
			packageName: "base-files",
		},
		{
			name: "whiteout-then-fallback", packagePath: "var/lib/dpkg/status", fixture: "dpkg-basic",
			layers:      [][]ociTestEntry{{{name: "usr/lib/os-release", data: []byte("ID=debian\nVERSION_ID=12\n")}, {name: "etc/os-release", data: []byte("ID=ubuntu\nVERSION_ID=24.04\n")}}, {{name: "etc/.wh.os-release"}}},
			packageName: "base-files", wantPURL: "pkg:deb/debian/base-files@12.4%2Bdeb12u9?arch=amd64&distro=debian-12",
		},
		{
			name: "whiteout-after-replacement", packagePath: "var/lib/dpkg/status", fixture: "dpkg-basic",
			layers:      [][]ociTestEntry{{{name: "etc/os-release", data: []byte("ID=debian\nVERSION_ID=11\n")}}, {{name: "etc/os-release", data: []byte("ID=debian\nVERSION_ID=12\n")}, {name: "etc/.wh.os-release"}}},
			packageName: "base-files", wantPURL: "pkg:deb/debian/base-files@12.4%2Bdeb12u9?arch=amd64&distro=debian-12",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			layers := make([]ociTestLayer, len(tt.layers))
			for i, entries := range tt.layers {
				layers[i].entries = entries
			}
			if tt.packagePath == "var/lib/dpkg/status" {
				layers[0].entries = append(layers[0].entries, ociTestEntry{name: tt.packagePath, data: ociTestStatus(t, tt.fixture)})
			} else {
				layers[0].entries = append(layers[0].entries, ociTestEntry{name: tt.packagePath, data: ociTestAPKInstalled(t, tt.fixture)})
			}
			layout := ociTestLayout(t)
			ociTestIndex(t, layout, ociTestImage(t, layout, "linux", "amd64", layers))
			doc, output, code := ociTestScan(t, layout)
			if code != 0 {
				t.Fatalf("scan failed: %s", output)
			}
			found := false
			for _, component := range doc.Components {
				if component.Name != tt.packageName {
					continue
				}
				found = true
				if component.PURL != tt.wantPURL {
					t.Fatalf("PURL = %q, want %q", component.PURL, tt.wantPURL)
				}
				if tt.wantPURL != "" {
					if component.PURLBasis != "ecosystem_inferred" || len(component.Evidence) != 2 || !strings.Contains(component.Evidence[1].InputPath, "os-release") {
						t.Fatalf("inferred PURL evidence missing: %#v", component)
					}
				} else if component.PURLBasis != "" {
					t.Fatalf("unexpected PURL basis: %#v", component)
				}
			}
			if !found {
				t.Fatalf("package %q not found", tt.packageName)
			}
		})
	}
}
