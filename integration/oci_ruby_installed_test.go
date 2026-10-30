package integration_test

import (
	"archive/tar"
	"fmt"
	"strings"
	"testing"
)

const ociRubyDefaultSpec = "usr/local/lib/ruby/gems/3.3.0/specifications/default/uri-0.13.3.gemspec"

func ociTestInstalledRubySpec(name, version, platform string) []byte {
	return []byte(fmt.Sprintf("# stub: %s %s %s lib\nGem::Specification.new do |s|\n  s.name = %q.freeze\n  s.version = %q.freeze\nend\n", name, version, platform, name, version))
}

func TestOCIInstalledRubyGemsAndOverlay(t *testing.T) {
	base := []ociTestEntry{
		{name: ociRubyDefaultSpec, data: ociTestInstalledRubySpec("uri", "0.13.3", "ruby")},
		{name: "usr/local/bundle/specifications/rack-3.0.0.gemspec", data: ociTestInstalledRubySpec("rack", "3.0.0", "ruby")},
	}
	for _, test := range []struct {
		name      string
		upper     []ociTestEntry
		want      string
		wantIssue string
	}{
		{name: "base", want: "uri@0.13.3,rack@3.0.0"},
		{name: "default_whiteout", upper: []ociTestEntry{{name: "usr/local/lib/ruby/gems/3.3.0/specifications/default/.wh.uri-0.13.3.gemspec"}}, want: "rack@3.0.0"},
		{name: "opaque_bundle", upper: []ociTestEntry{{name: "usr/local/bundle/specifications/.wh..wh..opq"}}, want: "uri@0.13.3"},
		{name: "invalid_replacement", upper: []ociTestEntry{{name: ociRubyDefaultSpec, data: ociTestInstalledRubySpec("uri", "0.13.4", "ruby")}}, want: "rack@3.0.0", wantIssue: "ruby_installed_spec_invalid"},
		{name: "ambiguous_replacement", upper: []ociTestEntry{{name: ociRubyDefaultSpec, data: append(ociTestInstalledRubySpec("uri", "0.13.3", "ruby"), []byte("s.name = \"other\"\n")...)}}, want: "rack@3.0.0", wantIssue: "ruby_installed_spec_invalid"},
		{name: "bundle_parent_symlink", upper: []ociTestEntry{{name: "usr/local/bundle/specifications", typeflag: tar.TypeSymlink, linkname: "/outside"}}, want: "uri@0.13.3"},
	} {
		t.Run(test.name, func(t *testing.T) {
			layout := ociTestLayout(t)
			layers := []ociTestLayer{{entries: base}}
			if test.upper != nil {
				layers = append(layers, ociTestLayer{entries: test.upper})
			}
			image := ociTestImage(t, layout, "linux", "amd64", layers)
			ociTestIndex(t, layout, image)
			doc, output, code := ociTestScan(t, layout)
			if code != 0 {
				t.Fatalf("installed Ruby gem scan failed: code=%d output=%s", code, output)
			}
			got := map[string]bool{}
			for _, component := range doc.Components {
				got[component.Name+"@"+component.Version] = true
				if component.PURL != "" || len(component.Hashes) != 0 || len(component.Evidence) != 1 || component.Evidence[0].InputDigest == "" || !strings.Contains(component.Context, "image=linux/amd64") {
					t.Fatalf("installed Ruby gem claimed unsupported provenance: %#v", component)
				}
				if component.Name == "uri" && !strings.Contains(component.Context, "default=true") {
					t.Fatalf("default gem context missing: %#v", component)
				}
			}
			for _, item := range strings.Split(test.want, ",") {
				if !got[item] {
					t.Fatalf("installed Ruby gem %s missing: %#v", item, got)
				}
			}
			if len(got) != len(strings.Split(test.want, ",")) {
				t.Fatalf("stale installed Ruby gem remained: %#v", got)
			}
			for _, code := range []string{"ruby_installed_activation_unresolved", "ruby_installed_origin_unavailable", test.wantIssue} {
				if code == "" {
					continue
				}
				found := false
				for _, issue := range doc.Coverage.Issues {
					found = found || issue.Code == code
				}
				if !found {
					t.Fatalf("installed Ruby gem issue %s missing: %#v", code, doc.Coverage.Issues)
				}
			}
		})
	}
}

func TestOCIInstalledRubyPlatformGem(t *testing.T) {
	const name = "usr/local/bundle/specifications/native-1.2.3-aarch64-linux.gemspec"
	layout := ociTestLayout(t)
	image := ociTestImage(t, layout, "linux", "arm64", []ociTestLayer{{entries: []ociTestEntry{{name: name, data: ociTestInstalledRubySpec("native", "1.2.3", "aarch64-linux")}}}})
	ociTestIndex(t, layout, image)
	doc, output, code := ociTestScan(t, layout)
	if code != 0 || len(doc.Components) != 1 || doc.Components[0].Name != "native" || doc.Components[0].Version != "1.2.3" || !strings.Contains(doc.Components[0].Context, "gem_platform=aarch64-linux;image=linux/arm64") {
		t.Fatalf("platform-specific Ruby gem lost: code=%d output=%s components=%#v", code, output, doc.Components)
	}
}

func TestOCIInstalledRubyGemBeneathSameLayerSymlinkRejected(t *testing.T) {
	layout := ociTestLayout(t)
	image := ociTestImage(t, layout, "linux", "amd64", []ociTestLayer{{entries: []ociTestEntry{
		{name: "usr/local/lib/ruby/gems/3.3.0/specifications/default", typeflag: tar.TypeSymlink, linkname: "/outside"},
		{name: ociRubyDefaultSpec, data: ociTestInstalledRubySpec("uri", "0.13.3", "ruby")},
	}}})
	ociTestIndex(t, layout, image)
	_, output, code := ociTestScan(t, layout)
	if code != 1 || !strings.Contains(output, "non-directory entry") {
		t.Fatalf("installed Ruby gem beneath symlink accepted: code=%d output=%s", code, output)
	}
}
