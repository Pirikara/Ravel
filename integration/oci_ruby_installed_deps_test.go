package integration_test

import (
	"strings"
	"testing"

	"ravel/internal/model"
)

func ociTestRubySpecWithDependencies(name, version string, declarations ...string) []byte {
	spec := string(ociTestInstalledRubySpec(name, version, "ruby"))
	return []byte(strings.Replace(spec, "end\n", strings.Join(declarations, "\n")+"\nend\n", 1))
}

func ociTestRubyDependencyScan(t *testing.T, entries []ociTestEntry, upper []ociTestEntry) model.Document {
	t.Helper()
	layout := ociTestLayout(t)
	layers := []ociTestLayer{{entries: entries}}
	if upper != nil {
		layers = append(layers, ociTestLayer{entries: upper})
	}
	image := ociTestImage(t, layout, "linux", "amd64", layers)
	ociTestIndex(t, layout, image)
	doc, output, code := ociTestScan(t, layout)
	if code != 0 {
		t.Fatalf("installed Ruby dependency scan failed: code=%d output=%s", code, output)
	}
	return doc
}

func ociTestRubyDependencyEdges(doc model.Document) map[string]bool {
	byID := map[string]string{}
	for _, component := range doc.Components {
		byID[component.ID] = component.Name + "@" + component.Version
	}
	result := map[string]bool{}
	for _, edge := range doc.Edges {
		if edge.Kind == "depends_on" {
			result[byID[edge.From]+" -> "+byID[edge.To]] = true
		}
	}
	return result
}

func ociTestRubyHasIssue(doc model.Document, code string) bool {
	for _, issue := range doc.Coverage.Issues {
		if issue.Code == code {
			return true
		}
	}
	return false
}

func TestOCIInstalledRubyRuntimeDependencyGraph(t *testing.T) {
	const home = "usr/local/bundle/specifications/"
	entries := []ociTestEntry{
		{name: home + "app-1.0.0.gemspec", data: ociTestRubySpecWithDependencies("app", "1.0.0",
			`  s.add_runtime_dependency(%q<lib>.freeze, [">= 1.2".freeze, "< 2".freeze])`,
			`  s.add_dependency(%q<util>.freeze, ["~> 0.5".freeze])`,
			`  s.add_development_dependency(%q<dev>.freeze, [">= 0".freeze])`)},
		{name: home + "lib-1.3.0.gemspec", data: ociTestInstalledRubySpec("lib", "1.3.0", "ruby")},
		{name: home + "util-0.7.0.gemspec", data: ociTestInstalledRubySpec("util", "0.7.0", "ruby")},
		{name: home + "dev-2.0.0.gemspec", data: ociTestInstalledRubySpec("dev", "2.0.0", "ruby")},
	}
	doc := ociTestRubyDependencyScan(t, entries, nil)
	edges := ociTestRubyDependencyEdges(doc)
	if len(edges) != 2 || !edges["app@1.0.0 -> lib@1.3.0"] || !edges["app@1.0.0 -> util@0.7.0"] {
		t.Fatalf("Ruby runtime dependency edges incorrect: %#v", edges)
	}
	for _, edge := range doc.Edges {
		if edge.Kind == "depends_on" && (edge.Evidence.Line == 0 || edge.Evidence.Pointer == "" || edge.Evidence.InputDigest == "") {
			t.Fatalf("Ruby dependency evidence missing: %#v", edge)
		}
	}
	if !ociTestRubyHasIssue(doc, "ruby_installed_activation_unresolved") || ociTestRubyHasIssue(doc, "ruby_installed_dependency_unresolved") {
		t.Fatalf("Ruby dependency coverage incorrect: %#v", doc.Coverage.Issues)
	}
}

func TestOCIInstalledRubyGraphDoesNotGuessRemovedAmbiguousOrCrossHomePackages(t *testing.T) {
	const home = "usr/local/bundle/specifications/"
	app := ociTestEntry{name: home + "app-1.0.0.gemspec", data: ociTestRubySpecWithDependencies("app", "1.0.0", `  s.add_runtime_dependency(%q<lib>.freeze, [">= 0".freeze])`)}
	lib := ociTestEntry{name: home + "lib-1.0.0.gemspec", data: ociTestInstalledRubySpec("lib", "1.0.0", "ruby")}
	for _, test := range []struct {
		name      string
		entries   []ociTestEntry
		upper     []ociTestEntry
		wantIssue string
	}{
		{name: "whiteouted_target", entries: []ociTestEntry{app, lib}, upper: []ociTestEntry{{name: home + ".wh.lib-1.0.0.gemspec"}}, wantIssue: "ruby_installed_dependency_unresolved"},
		{name: "ambiguous_versions", entries: []ociTestEntry{app, lib, {name: home + "lib-2.0.0.gemspec", data: ociTestInstalledRubySpec("lib", "2.0.0", "ruby")}}, wantIssue: "ruby_installed_dependency_ambiguous"},
		{name: "different_gem_home", entries: []ociTestEntry{app, {name: "usr/local/lib/ruby/gems/3.3.0/specifications/lib-1.0.0.gemspec", data: lib.data}}, wantIssue: "ruby_installed_dependency_unresolved"},
	} {
		t.Run(test.name, func(t *testing.T) {
			doc := ociTestRubyDependencyScan(t, test.entries, test.upper)
			if edges := ociTestRubyDependencyEdges(doc); len(edges) != 0 || !ociTestRubyHasIssue(doc, test.wantIssue) {
				t.Fatalf("Ruby dependency guessed through %s: edges=%#v issues=%#v", test.name, edges, doc.Coverage.Issues)
			}
		})
	}
}

func TestOCIInstalledRubyDefaultGemDependency(t *testing.T) {
	const bundle = "usr/local/bundle/specifications/"
	const defaultSpec = "usr/local/lib/ruby/gems/3.3.0/specifications/default/base64-0.2.0.gemspec"
	app := ociTestEntry{name: bundle + "app-1.0.0.gemspec", data: ociTestRubySpecWithDependencies("app", "1.0.0", `  s.add_runtime_dependency(%q<base64>.freeze, [">= 0.2".freeze])`)}
	defaultGem := ociTestEntry{name: defaultSpec, data: ociTestInstalledRubySpec("base64", "0.2.0", "ruby")}
	runtime := ociTestEntry{name: ociRubyRuntimePath, data: ociTestRubyRuntimeELF("3.3.12")}
	for _, test := range []struct {
		name       string
		entries    []ociTestEntry
		upper      []ociTestEntry
		wantTarget string
		wantIssue  string
	}{
		{name: "verified_runtime", entries: []ociTestEntry{app, defaultGem, runtime}, wantTarget: "base64@0.2.0"},
		{name: "missing_runtime", entries: []ociTestEntry{app, defaultGem}, wantIssue: "ruby_installed_dependency_unresolved"},
		{name: "invalid_runtime", entries: []ociTestEntry{app, defaultGem, {name: ociRubyRuntimePath, data: []byte("not ELF")}}, wantIssue: "ruby_installed_dependency_unresolved"},
		{name: "different_abi", entries: []ociTestEntry{app, runtime, {name: "usr/local/lib/ruby/gems/3.2.0/specifications/default/base64-0.2.0.gemspec", data: defaultGem.data}}, wantIssue: "ruby_installed_dependency_unresolved"},
		{name: "whiteouted_default", entries: []ociTestEntry{app, defaultGem, runtime}, upper: []ociTestEntry{{name: "usr/local/lib/ruby/gems/3.3.0/specifications/default/.wh.base64-0.2.0.gemspec"}}, wantIssue: "ruby_installed_dependency_unresolved"},
		{name: "bundle_candidate_preferred", entries: []ociTestEntry{app, defaultGem, runtime, {name: bundle + "base64-0.3.0.gemspec", data: ociTestInstalledRubySpec("base64", "0.3.0", "ruby")}}, wantTarget: "base64@0.3.0"},
	} {
		t.Run(test.name, func(t *testing.T) {
			doc := ociTestRubyDependencyScan(t, test.entries, test.upper)
			edges := ociTestRubyDependencyEdges(doc)
			wantCount := 0
			if test.wantTarget != "" {
				wantCount = 1
			}
			if len(edges) != wantCount || test.wantTarget != "" && !edges["app@1.0.0 -> "+test.wantTarget] {
				t.Fatalf("default Ruby gem relation incorrect: edges=%#v issues=%#v", edges, doc.Coverage.Issues)
			}
			if test.wantIssue != "" && !ociTestRubyHasIssue(doc, test.wantIssue) {
				t.Fatalf("missing default Ruby gem coverage issue: %#v", doc.Coverage.Issues)
			}
		})
	}
}

func TestOCIInstalledRubyUnsupportedDependencySyntaxReported(t *testing.T) {
	const home = "usr/local/bundle/specifications/"
	doc := ociTestRubyDependencyScan(t, []ociTestEntry{
		{name: home + "app-1.0.0.gemspec", data: ociTestRubySpecWithDependencies("app", "1.0.0",
			`  s.add_runtime_dependency(dynamic_name, [">= 0".freeze])`,
			`  s.add_runtime_dependency(%q<pre>.freeze, [">= 1.0".freeze])`)},
		{name: home + "pre-1.1.0.pre.gemspec", data: ociTestInstalledRubySpec("pre", "1.1.0.pre", "ruby")},
	}, nil)
	if edges := ociTestRubyDependencyEdges(doc); len(edges) != 0 || !ociTestRubyHasIssue(doc, "ruby_installed_dependency_unparsed") || !ociTestRubyHasIssue(doc, "ruby_installed_dependency_constraint_unverified") {
		t.Fatalf("unsupported Ruby dependency syntax was asserted: edges=%#v issues=%#v", edges, doc.Coverage.Issues)
	}
}

func TestOCIInstalledRubyPessimisticRequirementBoundary(t *testing.T) {
	const home = "usr/local/bundle/specifications/"
	app := ociTestEntry{name: home + "app-1.0.0.gemspec", data: ociTestRubySpecWithDependencies("app", "1.0.0", `  s.add_runtime_dependency(%q<lib>.freeze, ["~> 1.2.3".freeze])`)}
	for _, test := range []struct {
		version  string
		wantEdge bool
	}{
		{version: "1.2.2"},
		{version: "1.2.9", wantEdge: true},
		{version: "1.3.0"},
	} {
		t.Run(test.version, func(t *testing.T) {
			doc := ociTestRubyDependencyScan(t, []ociTestEntry{app, {name: home + "lib-" + test.version + ".gemspec", data: ociTestInstalledRubySpec("lib", test.version, "ruby")}}, nil)
			edges := ociTestRubyDependencyEdges(doc)
			expectedEdges := 0
			if test.wantEdge {
				expectedEdges = 1
			}
			if edges["app@1.0.0 -> lib@"+test.version] != test.wantEdge || len(edges) != expectedEdges {
				t.Fatalf("Ruby pessimistic constraint linked wrong version %s: %#v", test.version, edges)
			}
		})
	}
}

func TestOCIInstalledRubyDependencyCallLimit(t *testing.T) {
	const home = "usr/local/bundle/specifications/"
	declarations := make([]string, 129)
	for i := range declarations {
		declarations[i] = `  s.add_runtime_dependency(dynamic_name, [">= 0".freeze])`
	}
	doc := ociTestRubyDependencyScan(t, []ociTestEntry{{name: home + "app-1.0.0.gemspec", data: ociTestRubySpecWithDependencies("app", "1.0.0", declarations...)}}, nil)
	if !ociTestRubyHasIssue(doc, "ruby_installed_dependency_scan_limited") || len(ociTestRubyDependencyEdges(doc)) != 0 {
		t.Fatalf("Ruby dependency call cap was not enforced: %#v", doc.Coverage.Issues)
	}
}
