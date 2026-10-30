package cargo

import (
	"strings"
	"testing"
)

const metadataSample = `{"version":1,"workspace_members":["root"],"packages":[{"id":"root","name":"app","version":"0.1.0","source":null},{"id":"alpha","name":"alpha","version":"1.2.3","source":"registry+https://user:secret@registry.example.test/index?token=hidden","repository":"https://user:secret@code.example.test/alpha?token=hidden"},{"id":"beta","name":"beta","version":"2.0.0","source":"git+https://user:secret@code.example.test/beta?rev=abcd1234#abcd1234"}],"resolve":{"root":"root","nodes":[{"id":"root","dependencies":["alpha","beta"],"deps":[{"name":"alpha","pkg":"alpha","dep_kinds":[{"kind":null,"target":null}]},{"name":"beta","pkg":"beta","dep_kinds":[{"kind":"dev","target":null}]}]},{"id":"alpha","dependencies":["beta"],"deps":[{"name":"beta","pkg":"beta","dep_kinds":[{"kind":null,"target":"cfg(windows)"}]}]},{"id":"beta","dependencies":[],"deps":[]}]}}`

func TestCollectMetadataSourcesAndConditions(t *testing.T) {
	doc, err := collectMetadata("Cargo.toml", "app", []byte(metadataSample))
	if err != nil {
		t.Fatal(err)
	}
	if doc.Coverage.Packages != 2 || doc.Coverage.Edges != 3 || doc.Coverage.GraphState != "partial" || doc.Coverage.OriginState != "complete_for_scope" {
		t.Fatalf("unexpected Cargo metadata coverage: %#v", doc.Coverage)
	}
	var alpha, beta string
	for _, component := range doc.Components {
		switch component.Name {
		case "alpha":
			alpha = component.ID
			if component.PURL != "" {
				t.Fatalf("alternate Cargo registry was conflated with crates.io: %#v", component)
			}
		case "beta":
			beta = component.ID
		}
	}
	if alpha == "" || beta == "" {
		t.Fatalf("Cargo packages missing: %#v", doc.Components)
	}
	var normal, dev, target bool
	for _, edge := range doc.Edges {
		normal = normal || edge.From == "root" && edge.To == alpha && edge.Condition == ""
		dev = dev || edge.From == "root" && edge.To == beta && edge.Condition == "kind=dev"
		target = target || edge.From == alpha && edge.To == beta && edge.Condition == "target=cfg(windows)"
	}
	if !normal || !dev || !target {
		t.Fatalf("Cargo dependency conditions lost: %#v", doc.Edges)
	}
	if len(doc.Origins) != 2 || len(doc.Development) != 2 {
		t.Fatalf("Cargo sources missing: origins=%#v development=%#v", doc.Origins, doc.Development)
	}
	for _, origin := range doc.Origins {
		if strings.Contains(origin.SafeURL, "secret") || strings.Contains(origin.SafeURL, "hidden") {
			t.Fatalf("Cargo origin leaked credentials: %#v", origin)
		}
	}
	for _, source := range doc.Development {
		if strings.Contains(source.SafeURL, "secret") || strings.Contains(source.SafeURL, "hidden") {
			t.Fatalf("Cargo development URL leaked credentials: %#v", source)
		}
	}
}

func TestCollectMetadataRejectsCorruption(t *testing.T) {
	for _, input := range []string{
		strings.Replace(metadataSample, `"version":1`, `"version":2`, 1),
		strings.Replace(metadataSample, `"id":"alpha","name"`, `"id":"root","name"`, 1),
		strings.Replace(metadataSample, `"pkg":"alpha"`, `"pkg":"absent"`, 1),
		strings.Replace(metadataSample, `"root":"root"`, `"root":"absent"`, 1),
	} {
		if _, err := collectMetadata("Cargo.toml", "app", []byte(input)); err == nil {
			t.Fatalf("invalid Cargo metadata accepted: %s", input)
		}
	}
}

func TestCollectMetadataOldDependencyDetailIsConditional(t *testing.T) {
	input := strings.Replace(metadataSample, `"deps":[{"name":"alpha","pkg":"alpha","dep_kinds":[{"kind":null,"target":null}]},{"name":"beta","pkg":"beta","dep_kinds":[{"kind":"dev","target":null}]}]`, `"deps":[]`, 1)
	doc, err := collectMetadata("Cargo.toml", "app", []byte(input))
	if err != nil {
		t.Fatal(err)
	}
	if doc.Coverage.GraphState != "partial" {
		t.Fatalf("missing dependency detail reported complete: %#v", doc.Coverage)
	}
	for _, edge := range doc.Edges {
		if edge.From == "root" && edge.Condition != "kind_or_target_unavailable" {
			t.Fatalf("old Cargo dependency detail became unconditional: %#v", edge)
		}
	}
}

func TestCargoPURLOnlyForKnownCratesIO(t *testing.T) {
	for _, tc := range []struct{ source, want string }{
		{"registry+https://github.com/rust-lang/crates.io-index", "pkg:cargo/alpha@1.2.3"},
		{"sparse+https://index.crates.io/", "pkg:cargo/alpha@1.2.3"},
		{"registry+https://private.example.test/index", ""},
		{"git+https://code.example.test/alpha#abcd1234", ""},
		{"", ""},
	} {
		if got := cargoPURL("alpha", "1.2.3", tc.source); got != tc.want {
			t.Errorf("cargoPURL(%q) = %q; want %q", tc.source, got, tc.want)
		}
	}
}
