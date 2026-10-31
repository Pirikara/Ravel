package integration_test

import (
	"strings"
	"testing"
)

const systemNodeTestDir = "usr/share/nodejs/"

func TestOCISystemNodePackagesAndDependencies(t *testing.T) {
	layout := ociTestLayout(t)
	image := ociTestImage(t, layout, "linux", "amd64", []ociTestLayer{{entries: []ociTestEntry{
		{name: systemNodeTestDir + "consumer/package.json", data: []byte(`{"name":"consumer","version":"1.0.0","dependencies":{"target":"1.2.3","@scope/tool":"^2.0.0"}}`)},
		{name: systemNodeTestDir + "target/package.json", data: []byte(`{"name":"target","version":"1.2.3"}`)},
		{name: systemNodeTestDir + "@scope/tool/package.json", data: []byte(`{"name":"@scope/tool","version":"2.0.5"}`)},
		{name: systemNodeTestDir + "consumer/examples/package.json", data: []byte(`{"name":"example","version":"9.9.9"}`)},
	}}})
	ociTestIndex(t, layout, image)
	doc, output, code := ociTestScan(t, layout)
	if code != 0 || doc.Coverage.Packages != 3 || doc.Coverage.Edges != 5 {
		t.Fatalf("system Node inventory incorrect: code=%d output=%s coverage=%#v", code, output, doc.Coverage)
	}
	ids := map[string]string{}
	for _, component := range doc.Components {
		ids[component.Name] = component.ID
		if !strings.Contains(component.Context, "location="+systemNodeTestDir) || len(component.Evidence) != 1 || !strings.HasSuffix(component.Evidence[0].InputPath, "/package.json") {
			t.Fatalf("system Node evidence incorrect: %#v", component)
		}
	}
	if ids["consumer"] == "" || ids["target"] == "" || ids["@scope/tool"] == "" || ids["example"] != "" {
		t.Fatalf("system Node path selection incorrect: %#v", doc.Components)
	}
	want := map[string]string{ids["target"]: "", ids["@scope/tool"]: "constraint=(^2.0.0)"}
	for _, edge := range doc.Edges {
		if edge.From != ids["consumer"] {
			continue
		}
		condition, found := want[edge.To]
		if !found || edge.Condition != condition {
			t.Fatalf("system Node dependency incorrect: %#v", edge)
		}
		delete(want, edge.To)
	}
	if len(want) != 0 {
		t.Fatalf("system Node sibling dependencies missing: %#v", want)
	}
}

func TestOCISystemNodeOverlayAndNameMismatch(t *testing.T) {
	for _, test := range []struct {
		name      string
		upper     ociTestEntry
		want      int
		wantIssue string
	}{
		{name: "whiteout", upper: ociTestEntry{name: systemNodeTestDir + "target/.wh.package.json"}, want: 0},
		{name: "parent_whiteout", upper: ociTestEntry{name: systemNodeTestDir + ".wh.target"}, want: 0},
		{name: "name_mismatch", upper: ociTestEntry{name: systemNodeTestDir + "target/package.json", data: []byte(`{"name":"other","version":"1.2.3"}`)}, want: 0, wantIssue: "node_installed_metadata_invalid"},
	} {
		t.Run(test.name, func(t *testing.T) {
			layout := ociTestLayout(t)
			image := ociTestImage(t, layout, "linux", "amd64", []ociTestLayer{
				{entries: []ociTestEntry{{name: systemNodeTestDir + "target/package.json", data: []byte(`{"name":"target","version":"1.2.3"}`)}}},
				{entries: []ociTestEntry{test.upper}},
			})
			ociTestIndex(t, layout, image)
			doc, output, code := ociTestScan(t, layout)
			if code != 0 || len(doc.Components) != test.want {
				t.Fatalf("system Node overlay incorrect: code=%d output=%s components=%#v", code, output, doc.Components)
			}
			if test.wantIssue != "" {
				found := false
				for _, issue := range doc.Coverage.Issues {
					found = found || issue.Code == test.wantIssue
				}
				if !found {
					t.Fatalf("invalid system Node metadata not reported: %#v", doc.Coverage.Issues)
				}
			}
		})
	}
}
