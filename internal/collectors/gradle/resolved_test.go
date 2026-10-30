package gradle

import (
	"strings"
	"testing"
)

const graphSample = `{"root":"project :","configuration":"runtimeClasspath","nodes":[{"id":"project :","kind":"project","name":":","dependencies":["org.example:alpha:1","project :helper"],"failed":0,"variantCount":1},{"id":"org.example:alpha:1","kind":"module","group":"org.example","name":"alpha","version":"1","dependencies":["org.example:beta:2"],"failed":0,"variantCount":1},{"id":"project :helper","kind":"project","name":":helper","dependencies":["org.example:beta:2"],"failed":0,"variantCount":1},{"id":"org.example:beta:2","kind":"module","group":"org.example","name":"beta","version":"2","dependencies":[],"failed":0,"variantCount":1}]}`

func TestCollectGraph(t *testing.T) {
	doc, err := collectGraph("build.gradle", "demo", "runtimeClasspath", []byte(graphSample))
	if err != nil {
		t.Fatal(err)
	}
	if doc.Coverage.Packages != 3 || doc.Coverage.Edges != 4 || doc.Coverage.GraphState != "complete_for_scope" || doc.Coverage.OriginState != "partial" {
		t.Fatalf("unexpected graph coverage: %#v", doc.Coverage)
	}
	for _, component := range doc.Components {
		if component.Name == "org.example:alpha" && (component.PURL != "" || component.Context != "configuration=runtimeClasspath") {
			t.Fatalf("Gradle module identity lost: %#v", component)
		}
	}
	if len(doc.Edges) != 4 {
		t.Fatalf("dependency edges lost: %#v", doc.Edges)
	}
}

func TestCollectGraphRejectsCorruption(t *testing.T) {
	cases := []string{
		strings.Replace(graphSample, `"configuration":"runtimeClasspath"`, `"configuration":"other"`, 1),
		strings.Replace(graphSample, `"id":"org.example:beta:2"`, `"id":"org.example:alpha:1"`, 1),
		strings.Replace(graphSample, `"dependencies":["org.example:beta:2"]`, `"dependencies":["absent"]`, 1),
		strings.Replace(graphSample, `"root":"project :"`, `"root":"missing"`, 1),
	}
	for _, input := range cases {
		if _, err := collectGraph("build.gradle", "demo", "runtimeClasspath", []byte(input)); err == nil {
			t.Fatalf("invalid graph accepted: %s", input)
		}
	}
}

func TestCollectGraphMarksUnresolvedAndVariantUnion(t *testing.T) {
	input := strings.Replace(graphSample, `"failed":0,"variantCount":1`, `"failed":1,"variantCount":2`, 1)
	doc, err := collectGraph("build.gradle", "demo", "runtimeClasspath", []byte(input))
	if err != nil {
		t.Fatal(err)
	}
	if doc.Coverage.GraphState != "partial" {
		t.Fatalf("unresolved/variant graph reported complete: %#v", doc.Coverage)
	}
	var unresolved, variants bool
	for _, issue := range doc.Coverage.Issues {
		unresolved = unresolved || issue.Code == "unresolved_dependency"
		variants = variants || issue.Code == "gradle_variant_union"
	}
	if !unresolved || !variants {
		t.Fatalf("missing graph limitations: %#v", doc.Coverage.Issues)
	}
}
