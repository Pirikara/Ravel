package export

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/Pirikara/Ravel/internal/model"
)

func TestCycloneDXDependencyTargetsAreUnique(t *testing.T) {
	doc := model.Document{
		Project: "workspace",
		Components: []model.Component{
			{ID: "app", Name: "app"},
			{ID: "ui-a", Name: "ui", Version: "1.0"},
			{ID: "ui-b", Name: "ui", Version: "1.0"},
			{ID: "optional", Name: "optional"},
		},
		Edges: []model.Edge{
			{From: "app", To: "ui-b", Kind: "depends_on"},
			{From: "app", To: "ui-a", Kind: "direct_dev"},
			{From: "app", To: "ui-a", Kind: "depends_on"},
			{From: "app", To: "ui-a", Kind: "peer_requirement", Condition: "peer"},
			{From: "app", To: "optional", Kind: "depends_on", Condition: "optional"},
		},
	}
	data, err := CycloneDX(doc)
	if err != nil {
		t.Fatal(err)
	}
	var got bom
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	want := []dependency{{Ref: "app", DependsOn: []string{"ui-a", "ui-b"}}}
	if !reflect.DeepEqual(got.Dependencies, want) {
		t.Fatalf("dependency targets: got %#v, want %#v", got.Dependencies, want)
	}
	if len(got.Components) != 4 || len(doc.Edges) != 5 {
		t.Fatal("component occurrences or native declaration roles were lost")
	}
}
