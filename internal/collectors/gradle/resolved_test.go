package gradle

import (
	"strings"
	"testing"
)

const graphSample = `{"root":"project :","configuration":"runtimeClasspath","nodes":[{"id":"project :","kind":"project","name":":","dependencies":["org.example:alpha:1","project :helper"],"failed":0,"variantCount":1},{"id":"org.example:alpha:1","kind":"module","group":"org.example","name":"alpha","version":"1","dependencies":["org.example:beta:2"],"failed":0,"variantCount":1},{"id":"project :helper","kind":"project","name":":helper","dependencies":["org.example:beta:2"],"failed":0,"variantCount":1},{"id":"org.example:beta:2","kind":"module","group":"org.example","name":"beta","version":"2","dependencies":[],"failed":0,"variantCount":1}]}`

const multiGraphSample = `{"root":"ravel:aggregate-root","configuration":"runtimeClasspath","nodes":[{"id":"ravel:aggregate-root","kind":"project","name":":","projectPath":":","dependencies":[":app|project :app",":lib|project :lib"],"failed":0,"variantCount":1},{"id":":app|project :app","kind":"project","name":":app","projectPath":":app","dependencies":[":app|project :lib"],"failed":0,"variantCount":1},{"id":":app|project :lib","kind":"project","name":":lib","projectPath":":app","dependencies":[],"failed":0,"variantCount":1},{"id":":lib|project :lib","kind":"project","name":":lib","projectPath":":lib","dependencies":[],"failed":0,"variantCount":1}]}`

func TestCollectMultiProjectGraph(t *testing.T) {
	doc, err := collectGraph("build.gradle", "demo", "runtimeClasspath", []byte(multiGraphSample))
	if err != nil {
		t.Fatal(err)
	}
	if doc.Coverage.Packages != 3 || doc.Coverage.Edges != 3 || doc.Coverage.GraphState != "complete_for_scope" {
		t.Fatalf("unexpected multi-project coverage: %+v", doc.Coverage)
	}
	ids := map[string]string{}
	for _, component := range doc.Components {
		ids[component.Name+"|"+component.Context] = component.ID
	}
	app := ids[":app|configuration=runtimeClasspath;project=:app"]
	appLib := ids[":lib|configuration=runtimeClasspath;project=:app"]
	lib := ids[":lib|configuration=runtimeClasspath;project=:lib"]
	if app == "" || appLib == "" || lib == "" || appLib == lib {
		t.Fatalf("Gradle project scopes collapsed: %+v", ids)
	}
	found := map[string]bool{}
	for _, edge := range doc.Edges {
		found[edge.From+"->"+edge.To] = true
	}
	if !found["root->"+app] || !found["root->"+lib] || !found[app+"->"+appLib] {
		t.Fatalf("Gradle multi-project edges missing: %+v", doc.Edges)
	}
}

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
