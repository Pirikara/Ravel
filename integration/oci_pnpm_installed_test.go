package integration_test

import (
	"archive/tar"
	"strings"
	"testing"

	"ravel/internal/model"
)

// The file+ locator and symlink layout come from a pnpm 10 offline install of
// a locally packed npm tarball. Expectations come from package.json and the
// final image paths, not another SBOM scanner's output.
func TestOCIPnpmVirtualStoreRequiresReachablePackage(t *testing.T) {
	const base = "app/node_modules/"
	const locator = "ravel-probe@file+ravel-probe-1.0.0.tgz"
	physical := base + ".pnpm/" + locator + "/node_modules/ravel-probe/package.json"
	links := []ociTestEntry{
		{name: physical, data: []byte(`{"name":"ravel-probe","version":"1.0.0"}`)},
		{name: base + ".pnpm/orphan@2.0.0/node_modules/orphan/package.json", data: []byte(`{"name":"orphan","version":"2.0.0"}`)},
		{name: base + "ravel-probe", typeflag: tar.TypeSymlink, linkname: ".pnpm/" + locator + "/node_modules/ravel-probe"},
	}
	layout := ociTestLayout(t)
	manifest := ociTestImage(t, layout, "linux", "amd64", []ociTestLayer{{entries: links}})
	ociTestIndex(t, layout, manifest)
	doc, output, code := ociTestScan(t, layout)
	if code != 0 || doc.Coverage.Packages != 1 || doc.Coverage.Edges != 1 || doc.Components[0].Name != "ravel-probe" || doc.Components[0].Version != "1.0.0" {
		t.Fatalf("pnpm installed package inventory incorrect: code=%d output=%s doc=%#v", code, output, doc)
	}
	if !strings.HasSuffix(doc.Components[0].Evidence[0].InputPath, "!/"+physical) || doc.Components[0].PURL != "" {
		t.Fatalf("pnpm identity or provenance was guessed: %#v", doc.Components[0])
	}
	if !ociPnpmHasIssue(doc, "node_pnpm_store_unlinked") {
		t.Fatalf("unreachable store package was not reported: %#v", doc.Coverage.Issues)
	}

	whiteouted := ociTestLayout(t)
	manifest = ociTestImage(t, whiteouted, "linux", "amd64", []ociTestLayer{
		{entries: links},
		{entries: []ociTestEntry{{name: base + ".wh.ravel-probe"}}},
	})
	ociTestIndex(t, whiteouted, manifest)
	doc, output, code = ociTestScan(t, whiteouted)
	if code != 0 || doc.Coverage.Packages != 0 || !ociPnpmHasIssue(doc, "node_pnpm_store_unlinked") {
		t.Fatalf("removed pnpm link retained a package: code=%d output=%s doc=%#v", code, output, doc)
	}
}

func TestOCIPnpmStoreDependencyLinksAcrossLayers(t *testing.T) {
	const base = "app/node_modules/"
	alpha := base + ".pnpm/alpha@1.0.0/node_modules/alpha/package.json"
	beta := base + ".pnpm/beta@2.0.0/node_modules/beta/package.json"
	store := []ociTestEntry{
		{name: alpha, data: []byte(`{"name":"alpha","version":"1.0.0","dependencies":{"beta":"2.0.0"}}`)},
		{name: beta, data: []byte(`{"name":"beta","version":"2.0.0"}`)},
	}
	links := []ociTestEntry{
		{name: base + "alpha", typeflag: tar.TypeSymlink, linkname: ".pnpm/alpha@1.0.0/node_modules/alpha"},
		{name: base + ".pnpm/alpha@1.0.0/node_modules/beta", typeflag: tar.TypeSymlink, linkname: "../../beta@2.0.0/node_modules/beta"},
	}
	layout := ociTestLayout(t)
	manifest := ociTestImage(t, layout, "linux", "amd64", []ociTestLayer{{entries: store}, {entries: links}})
	ociTestIndex(t, layout, manifest)
	doc, output, code := ociTestScan(t, layout)
	if code != 0 || doc.Coverage.Packages != 2 || doc.Coverage.Edges != 3 {
		t.Fatalf("pnpm linked dependency graph incorrect: code=%d output=%s doc=%#v", code, output, doc)
	}
	ids := map[string]string{}
	for _, component := range doc.Components {
		ids[component.Name] = component.ID
	}
	linked := false
	for _, edge := range doc.Edges {
		if edge.From == ids["alpha"] && edge.To == ids["beta"] && edge.Kind == "depends_on" && edge.Condition == "" {
			linked = true
		}
	}
	if !linked || ociPnpmHasIssue(doc, "node_installed_link_unresolved") {
		t.Fatalf("pnpm link did not establish exact dependency: edges=%#v issues=%#v", doc.Edges, doc.Coverage.Issues)
	}

	removed := ociTestLayout(t)
	manifest = ociTestImage(t, removed, "linux", "amd64", []ociTestLayer{
		{entries: store}, {entries: links},
		{entries: []ociTestEntry{{name: base + ".pnpm/beta@2.0.0/node_modules/beta/.wh.package.json"}}},
	})
	ociTestIndex(t, removed, manifest)
	doc, output, code = ociTestScan(t, removed)
	if code != 0 || doc.Coverage.Packages != 1 || !ociPnpmHasIssue(doc, "node_installed_link_unresolved") || !ociPnpmHasIssue(doc, "unresolved_dependency") {
		t.Fatalf("whiteouted pnpm target remained linked: code=%d output=%s doc=%#v", code, output, doc)
	}
}

func TestOCIPnpmUnsafeAndCyclicLinks(t *testing.T) {
	for _, target := range []string{"", "../../../../escape", "../alpha", ".pnpm/missing@1/node_modules/missing"} {
		t.Run(target, func(t *testing.T) {
			layout := ociTestLayout(t)
			manifest := ociTestImage(t, layout, "linux", "amd64", []ociTestLayer{{entries: []ociTestEntry{
				{name: "app/node_modules/alpha", typeflag: tar.TypeSymlink, linkname: target},
			}}})
			ociTestIndex(t, layout, manifest)
			doc, output, code := ociTestScan(t, layout)
			if code != 0 || len(doc.Components) != 0 || !ociPnpmHasIssue(doc, "node_installed_link_unresolved") {
				t.Fatalf("unsafe or dangling link accepted: code=%d output=%s doc=%#v", code, output, doc)
			}
		})
	}
}

func ociPnpmHasIssue(doc model.Document, code string) bool {
	for _, issue := range doc.Coverage.Issues {
		if issue.Code == code {
			return true
		}
	}
	return false
}
