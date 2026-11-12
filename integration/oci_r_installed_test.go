package integration_test

import (
	"archive/tar"
	"fmt"
	"strings"
	"testing"

	"github.com/Pirikara/Ravel/internal/model"
)

const ociRLibrary = "usr/local/lib/R/library/"
const ociRSiteLibrary = "usr/local/lib/R/site-library/"

func ociTestRDescription(name, version, extra string) []byte {
	return []byte(fmt.Sprintf("Package: %s\nVersion: %s\n%sBuilt: R 4.5.1; aarch64-unknown-linux-gnu; 2025-10-31; unix\n", name, version, extra))
}

func ociScanInstalledR(t *testing.T, layers []ociTestLayer) model.Document {
	return ociScanInstalledRWithEnv(t, layers, nil)
}

func ociScanInstalledRWithEnv(t *testing.T, layers []ociTestLayer, env []string) model.Document {
	t.Helper()
	layout := ociTestLayout(t)
	image := ociTestImageWithEnv(t, layout, "linux", "arm64", layers, "", env)
	ociTestIndex(t, layout, image)
	doc, output, code := ociTestScan(t, layout)
	if code != 0 {
		t.Fatalf("installed R package scan failed: code=%d output=%s", code, output)
	}
	return doc
}

func TestOCIInstalledRConfiguredLibrariesAndFinalLayers(t *testing.T) {
	const custom = "opt/ravel-test/Rlibs/"
	const hostSite = "usr/local/lib/R/host-site-library/"
	base := []ociTestEntry{
		{name: custom + "docopt/DESCRIPTION", data: ociTestRDescription("docopt", "0.7.2", "Imports: stats\n")},
		{name: hostSite + "BiocGenerics/DESCRIPTION", data: ociTestRDescription("BiocGenerics", "0.50.0", "")},
		{name: ociRLibrary + "stats/DESCRIPTION", data: ociTestRDescription("stats", "4.5.1", "")},
		{name: "opt/other/source/pkg/DESCRIPTION", data: ociTestRDescription("pkg", "1.0.0", "")},
	}
	env := []string{"R_LIBS=/opt/ravel-test/Rlibs", "R_LIBS_SITE=/usr/local/lib/R/host-site-library"}
	for _, test := range []struct {
		name  string
		env   []string
		upper []ociTestEntry
		want  string
	}{
		{name: "configured", env: env, want: "docopt@0.7.2,BiocGenerics@0.50.0,stats@4.5.1"},
		{name: "unconfigured", want: "stats@4.5.1"},
		{name: "whiteout", env: env, upper: []ociTestEntry{{name: custom + "docopt/.wh.DESCRIPTION"}}, want: "BiocGenerics@0.50.0,stats@4.5.1"},
		{name: "opaque host library", env: env, upper: []ociTestEntry{{name: hostSite + ".wh..wh..opq"}}, want: "docopt@0.7.2,stats@4.5.1"},
		{name: "parent symlink", env: env, upper: []ociTestEntry{{name: custom + "docopt", typeflag: tar.TypeSymlink, linkname: "/elsewhere"}}, want: "BiocGenerics@0.50.0,stats@4.5.1"},
	} {
		t.Run(test.name, func(t *testing.T) {
			layers := []ociTestLayer{{entries: base}}
			if test.upper != nil {
				layers = append(layers, ociTestLayer{entries: test.upper})
			}
			doc := ociScanInstalledRWithEnv(t, layers, test.env)
			got := ociRComponents(doc)
			for _, label := range strings.Split(test.want, ",") {
				if _, found := got[label]; !found {
					t.Fatalf("configured R package %s missing: %#v", label, got)
				}
			}
			if len(got) != len(strings.Split(test.want, ",")) {
				t.Fatalf("unconfigured or removed R package included: %#v", got)
			}
			for _, label := range []string{"docopt@0.7.2", "BiocGenerics@0.50.0"} {
				if component, found := got[label]; found && (len(component.Evidence) != 2 || component.Evidence[1].Collector != "r-library-config" || !strings.HasPrefix(component.Evidence[1].Pointer, "config.Env/R_LIBS")) {
					t.Fatalf("configured R library evidence missing: %#v", component)
				}
			}
		})
	}
}

func TestOCIInstalledRConfiguredLibraryInvalidPathReported(t *testing.T) {
	doc := ociScanInstalledRWithEnv(t, []ociTestLayer{{entries: []ociTestEntry{
		{name: "opt/ravel-test/Rlibs/docopt/DESCRIPTION", data: ociTestRDescription("docopt", "0.7.2", "")},
	}}}, []string{"R_LIBS=../opt/ravel-test/Rlibs"})
	if len(doc.Components) != 0 || !ociTestRubyHasIssue(doc, "r_installed_library_path_unresolved") {
		t.Fatalf("invalid configured R library path was trusted: components=%#v issues=%#v", doc.Components, doc.Coverage.Issues)
	}
}

func TestOCIInstalledRStartupLibrariesAndFinalLayers(t *testing.T) {
	const environ = "opt/ravel-startup/config/Renviron.site"
	const profile = "opt/ravel-startup/config/Rprofile.site"
	base := []ociTestEntry{
		{name: environ, data: []byte("R_LIBS=/opt/ravel-startup/env-lib\n")},
		{name: profile, data: []byte(".libPaths(c(\"/opt/ravel-startup/profile-lib\", .libPaths()))\n")},
		{name: "opt/ravel-startup/env-lib/docopt/DESCRIPTION", data: ociTestRDescription("docopt", "0.7.2", "")},
		{name: "opt/ravel-startup/profile-lib/littler/DESCRIPTION", data: ociTestRDescription("littler", "0.3.21", "")},
		{name: "opt/old-lib/stale/DESCRIPTION", data: ociTestRDescription("stale", "1.0.0", "")},
		{name: "opt/project/source/DESCRIPTION", data: ociTestRDescription("source", "1.0.0", "")},
	}
	env := []string{"R_LIBS=/opt/old-lib", "R_ENVIRON=/" + environ, "R_PROFILE=/" + profile}
	for _, test := range []struct {
		name  string
		upper []ociTestEntry
		want  string
		issue bool
	}{
		{name: "both startup files", want: "docopt@0.7.2,littler@0.3.21"},
		{name: "profile replaced", upper: []ociTestEntry{{name: profile, data: []byte("if (FALSE) .libPaths('/opt/ravel-startup/profile-lib')\n")}}, want: "docopt@0.7.2", issue: true},
		{name: "environment removed", upper: []ociTestEntry{{name: "opt/ravel-startup/config/.wh.Renviron.site"}}, want: "littler@0.3.21,stale@1.0.0"},
	} {
		t.Run(test.name, func(t *testing.T) {
			layers := []ociTestLayer{{entries: base}}
			if test.upper != nil {
				layers = append(layers, ociTestLayer{entries: test.upper})
			}
			doc := ociScanInstalledRWithEnv(t, layers, env)
			got := ociRComponents(doc)
			if len(got) != len(strings.Split(test.want, ",")) {
				t.Fatalf("startup library count incorrect: %#v", got)
			}
			for _, label := range strings.Split(test.want, ",") {
				if _, found := got[label]; !found {
					t.Fatalf("startup package %s missing: %#v", label, got)
				}
			}
			if ociTestRubyHasIssue(doc, "r_installed_library_path_unresolved") != test.issue {
				t.Fatalf("startup uncertainty incorrect: %#v", doc.Coverage.Issues)
			}
			for _, label := range []string{"docopt@0.7.2", "littler@0.3.21"} {
				if component, found := got[label]; found && (len(component.Evidence) != 3 || component.Evidence[2].Collector != "r-library-startup") {
					t.Fatalf("startup file evidence missing: %#v", component)
				}
			}
		})
	}
}

func ociRComponents(doc model.Document) map[string]model.Component {
	result := map[string]model.Component{}
	for _, component := range doc.Components {
		result[component.Name+"@"+component.Version] = component
	}
	return result
}

func TestOCIInstalledRPackagesAndFinalLayers(t *testing.T) {
	base := []ociTestEntry{
		{name: ociRLibrary + "stats/DESCRIPTION", data: ociTestRDescription("stats", "4.5.1", "")},
		{name: ociRLibrary + "MASS/DESCRIPTION", data: ociTestRDescription("MASS", "7.3-64", "Depends: R (>= 4.4.0), stats\n")},
		{name: ociRSiteLibrary + "docopt/DESCRIPTION", data: ociTestRDescription("docopt", "0.7.2", "Imports: methods\n")},
		{name: ociRLibrary + "translations/DESCRIPTION", data: []byte("Package: translations\nVersion: 4.5.1\n")},
	}
	for _, test := range []struct {
		name  string
		upper []ociTestEntry
		want  string
	}{
		{name: "base", want: "stats@4.5.1,MASS@7.3-64,docopt@0.7.2"},
		{name: "version replacement", upper: []ociTestEntry{{name: ociRLibrary + "MASS/DESCRIPTION", data: ociTestRDescription("MASS", "7.3-65", "Depends: stats\n")}}, want: "stats@4.5.1,MASS@7.3-65,docopt@0.7.2"},
		{name: "whiteout", upper: []ociTestEntry{{name: ociRLibrary + "MASS/.wh.DESCRIPTION"}}, want: "stats@4.5.1,docopt@0.7.2"},
		{name: "opaque library", upper: []ociTestEntry{{name: ociRLibrary + ".wh..wh..opq"}}, want: "docopt@0.7.2"},
		{name: "parent symlink", upper: []ociTestEntry{{name: ociRLibrary + "MASS", typeflag: tar.TypeSymlink, linkname: "/elsewhere"}}, want: "stats@4.5.1,docopt@0.7.2"},
	} {
		t.Run(test.name, func(t *testing.T) {
			layers := []ociTestLayer{{entries: base}}
			if test.upper != nil {
				layers = append(layers, ociTestLayer{entries: test.upper})
			}
			doc := ociScanInstalledR(t, layers)
			got := ociRComponents(doc)
			for _, item := range strings.Split(test.want, ",") {
				if _, found := got[item]; !found {
					t.Fatalf("R package %s missing: %#v", item, got)
				}
			}
			if len(got) != len(strings.Split(test.want, ",")) {
				t.Fatalf("stale or translation-only package included: %#v", got)
			}
			for _, component := range got {
				if component.PURL != "" || len(component.Evidence) != 1 || component.Evidence[0].InputDigest == "" || !strings.Contains(component.Context, "image=linux/arm64") {
					t.Fatalf("R package claimed unsupported source or lost evidence: %#v", component)
				}
			}
			if !ociTestRubyHasIssue(doc, "r_installed_origin_unavailable") {
				t.Fatalf("R distribution origin uncertainty missing: %#v", doc.Coverage.Issues)
			}
		})
	}
}

func TestOCIInstalledRDependencyGraphAndAmbiguity(t *testing.T) {
	entries := []ociTestEntry{
		{name: ociRLibrary + "stats/DESCRIPTION", data: ociTestRDescription("stats", "4.5.1", "")},
		{name: ociRLibrary + "methods/DESCRIPTION", data: ociTestRDescription("methods", "4.5.1", "")},
		{name: ociRSiteLibrary + "app/DESCRIPTION", data: ociTestRDescription("app", "1.0.0", "Depends: R (>= 4.0.0), stats (>= 4.5.0), missing\nImports: methods, broken (>= 2.0)\nLinkingTo: headers, missingBuild\nSuggests: optional\n")},
		{name: ociRLibrary + "broken/DESCRIPTION", data: ociTestRDescription("broken", "1.0.0", "")},
		{name: ociRLibrary + "headers/DESCRIPTION", data: ociTestRDescription("headers", "1.0.0", "")},
	}
	doc := ociScanInstalledR(t, []ociTestLayer{{entries: entries}})
	components := ociRComponents(doc)
	byID := map[string]string{}
	for label, component := range components {
		byID[component.ID] = label
	}
	edges := map[string]bool{}
	for _, edge := range doc.Edges {
		if edge.Kind == "depends_on" && edge.Condition == "" {
			edges[byID[edge.From]+" -> "+byID[edge.To]] = true
			if edge.Evidence.Line == 0 || edge.Evidence.Pointer == "" {
				t.Fatalf("R dependency edge has no field evidence: %#v", edge)
			}
		}
	}
	if len(edges) != 2 || !edges["app@1.0.0 -> stats@4.5.1"] || !edges["app@1.0.0 -> methods@4.5.1"] || !ociTestRubyHasIssue(doc, "r_installed_dependency_unresolved") {
		t.Fatalf("R installed dependency graph incorrect: edges=%#v issues=%#v", edges, doc.Coverage.Issues)
	}
	buildEdge := false
	for _, edge := range doc.Edges {
		buildEdge = buildEdge || edge.Kind == "depends_on" && edge.Condition == "kind=build" && byID[edge.From] == "app@1.0.0" && byID[edge.To] == "headers@1.0.0"
	}
	if !buildEdge {
		t.Fatalf("R LinkingTo build dependency lost: %#v", doc.Edges)
	}
	if _, found := components["optional@1.0.0"]; found {
		t.Fatal("Suggests treated as installed package")
	}
}

func TestOCIInstalledRDescriptionBeneathSameLayerSymlinkRejected(t *testing.T) {
	layout := ociTestLayout(t)
	image := ociTestImage(t, layout, "linux", "arm64", []ociTestLayer{{entries: []ociTestEntry{
		{name: ociRLibrary + "MASS", typeflag: tar.TypeSymlink, linkname: "/elsewhere"},
		{name: ociRLibrary + "MASS/DESCRIPTION", data: ociTestRDescription("MASS", "7.3-65", "")},
	}}})
	ociTestIndex(t, layout, image)
	_, output, code := ociTestScan(t, layout)
	if code != 1 || !strings.Contains(output, "non-directory entry") {
		t.Fatalf("R DESCRIPTION below symlink accepted: code=%d output=%s", code, output)
	}
}

func TestOCIInstalledRStartupBeneathSameLayerSymlinkRejected(t *testing.T) {
	layout := ociTestLayout(t)
	image := ociTestImageWithEnv(t, layout, "linux", "arm64", []ociTestLayer{{entries: []ociTestEntry{
		{name: "opt/ravel-startup/config", typeflag: tar.TypeSymlink, linkname: "/elsewhere"},
		{name: "opt/ravel-startup/config/Renviron.site", data: []byte("R_LIBS=/opt/library\n")},
	}}}, "", []string{"R_ENVIRON=/opt/ravel-startup/config/Renviron.site"})
	ociTestIndex(t, layout, image)
	_, output, code := ociTestScan(t, layout)
	if code != 1 || !strings.Contains(output, "non-directory entry") {
		t.Fatalf("R startup file below symlink accepted: code=%d output=%s", code, output)
	}
}
