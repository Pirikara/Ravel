package integration_test

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBundlerArtifactPlatformsIndependentOfHost(t *testing.T) {
	doc := scanDevelopmentSample(t, filepath.Join("..", "testdata", "fixtures", "bundler-artifact-platforms", "Gemfile.lock"))
	expected := map[string][2]string{"native-arm": {"1.2.3", "arm64-darwin"}, "native-universal": {"2.3.4", "universal-darwin"}, "native-bsd": {"3.4.5", "x86_64-freebsd-14"}, "native-linux": {"4.5.6", "x86_64-linux-musl"}, "pure-prerelease": {"5.6.7.pre.2", ""}}
	if len(doc.Components) != len(expected) {
		t.Fatal(doc.Components)
	}
	for _, component := range doc.Components {
		want, ok := expected[component.Name]
		if !ok || component.Version != want[0] || component.Platform != want[1] {
			t.Fatal(component)
		}
		delete(expected, component.Name)
		if want[1] != "" && !strings.Contains(component.PURL, "platform="+want[1]) {
			t.Fatal(component.PURL)
		}
	}
	if len(expected) != 0 {
		t.Fatal(expected)
	}
	assertDevelopmentExports(t, doc)
}
