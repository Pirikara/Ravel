package npm

import "testing"

func TestInstalledPackageKeepsRecordedTokenNamedArtifact(t *testing.T) {
	const location = "https://registry.example.test/api/npm/parse-tokens/-/parse-tokens-1.2.3.tgz"
	data := []byte(`{"name":"parse-tokens","version":"1.2.3","_resolved":"` + location + `"}`)
	doc, err := CollectInstalledPackage(data, "package.json", "test", "node_modules/parse-tokens/package.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Origins) != 1 || doc.Origins[0].SafeURL != location || doc.Origins[0].Status != "recorded_in_install_metadata" {
		t.Fatal("installed source lost", doc.Origins)
	}
	if doc.Components[0].PURLBasis != "source_qualified" {
		t.Fatal("recorded source missing from PURL", doc.Components)
	}
}
