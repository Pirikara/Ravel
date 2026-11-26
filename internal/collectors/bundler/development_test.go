package bundler

import (
	"testing"

	"github.com/Pirikara/Ravel/internal/collectors/common"
	"github.com/Pirikara/Ravel/internal/model"
)

func TestLiteralGemspecDevelopment(t *testing.T) {
	for _, test := range []struct {
		source, status string
		count          int
		unresolved     bool
	}{
		{`s.metadata = { "source_code_uri" => "https://code.example.test/project".freeze, "rubygems_mfa_required" => "true" }.freeze`, "declared", 1, false},
		{`s.metadata = { "source_code_uri" => "https://code.example.test/project" } if s.respond_to? :metadata=`, "declared", 1, false},
		{`s.metadata = { "source_code_uri" => "https://code.example.test/project" }.freeze if s.respond_to?(:metadata=)`, "declared", 1, false},
		{"s.metadata = {\n  source_code_uri: 'https://code.example.test/project',\n}\ns.homepage = 'https://github.com/other/project'", "declared", 1, false},
		{`s.metadata["source_code_uri"] = "https://code.example.test/project".freeze # source`, "declared", 1, false},
		{`s.homepage = "https://github.com/owner/project".freeze`, "inferred_from_homepage", 1, false},
		{`s.homepage = "https://docs.example.test/project"`, "", 0, false},
		{`s.metadata = { "source_code_uri" => compute_url() }`, "", 0, true},
		{`s.metadata = { "source_code_uri" => "" }`, "", 0, false},
		{`s.metadata["source_code_uri"] = "https://#{host}/project"`, "", 0, true},
		{`other.metadata = { "source_code_uri" => "https://code.example.test/project" }`, "", 0, false},
		{`s.metadata = { 'changelog_uri' => "https://example.test/v#{s.version}", 'source_code_uri' => 'https://code.example.test/project' }`, "declared", 1, false},
		{`s.metadata = { 'unrelated' => lookup([1, 2], { nested: true }), 'source_code_uri' => 'https://code.example.test/project' }`, "declared", 1, false},
		{`s.metadata = { 'source_code_uri' => 'https://code.example.test/project', 'source_code_uri' => computed() }`, "", 0, true},
		{`s.metadata = { 'source_code_uri' => 'https://code.example.test/project' }.merge(other)`, "", 0, true},
		{`s.metadata = { 'source_code_uri' => %q{https://code.example.test/project}, 'unrelated' => true }`, "declared", 1, false},
		{`s.homepage = %q{https://github.com/owner/project}`, "inferred_from_homepage", 1, false},
		{`s.homepage = %Q{https://github.com/owner/project}`, "", 0, false},
		{`s.homepage = %q|https://github.com/owner/project|.freeze`, "inferred_from_homepage", 1, false},
		{"s.homepage = 'https://github.com/owner/project'\ns.metadata['source_code_uri'] = s.homepage", "declared", 1, false},
		{"s.homepage = 'https://github.com/owner/project'\ns.metadata = { source_code_uri: s.homepage }", "declared", 1, false},
		{"s.homepage = 'https://github.com/owner/project'\ns.metadata['source_code_uri'] = s.homepage + '/other'", "inferred_from_homepage", 1, true},
		{"s.homepage = 'https://github.com/owner/project'\ns.homepage = computed()\ns.metadata['source_code_uri'] = s.homepage", "inferred_from_homepage", 1, true},
		{`s.metadata = { 'unrelated' => <<TEXT, 'source_code_uri' => 'https://code.example.test/project' }`, "", 0, true},
		{`s.metadata = { 'unrelated' => "#{lookup('x,y')}", 'source_code_uri' => 'https://code.example.test/project' }`, "", 0, true},
	} {
		doc := common.NewDocument("sample.gemspec", "sample", "gemspec", nil)
		CollectDevelopment(&doc, "pkg", []byte(test.source), "s", model.Evidence{InputPath: "sample.gemspec", InputDigest: "sha256:sample"})
		if len(doc.Development) != test.count || (len(doc.Coverage.Issues) > 0) != test.unresolved {
			t.Fatalf("%s: %+v %+v", test.source, doc.Development, doc.Coverage.Issues)
		}
		if test.count > 0 && (doc.Development[0].Status != test.status || doc.Development[0].Evidence.Line < 1) {
			t.Fatal(doc.Development)
		}
		if len(doc.Origins) != 0 {
			t.Fatal("source declaration became a download claim")
		}
	}
}
