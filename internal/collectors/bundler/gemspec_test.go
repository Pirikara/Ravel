package bundler

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGemspecDoesNotTreatRubyExpressionAsVersion(t *testing.T) {
	file := filepath.Join(t.TempDir(), "sample.gemspec")
	data := []byte("Gem::Specification.new do |spec|\n  spec.name = 'sample'\n  spec.version = '1' + '2'\nend\n")
	if err := os.WriteFile(file, data, 0o644); err != nil {
		t.Fatal(err)
	}
	doc, err := CollectGemspec(file, "sample")
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Components) != 1 || doc.Components[0].Version != "" {
		t.Fatalf("Ruby expression was treated as a literal version: %#v", doc.Components)
	}
	versionUnresolved := false
	for _, issue := range doc.Coverage.Issues {
		versionUnresolved = versionUnresolved || issue.Code == "version_unresolved"
	}
	if !versionUnresolved {
		t.Fatal("unknown version was not reported")
	}
}
