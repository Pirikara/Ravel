package yarn

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestClassicDescriptorNameKeepsLocatorAtSigns(t *testing.T) {
	for value, want := range map[string]string{"name@link:./@scope/folder": "name", "@scope/name@file:../@group/archive.tgz": "@scope/name", "name@https://user@example.test/@npm:/archive.tgz": "name", "alias@npm:@scope/target@^1": "alias", "@scope/target": ""} {
		if got := descriptorName(value); got != want {
			t.Fatalf("%q name=%q want=%q", value, got, want)
		}
	}
}

func TestClassicLocalLocatorConflictRetained(t *testing.T) {
	entry := classicEntry{descriptors: []string{"tool@link:./first", "tool@link:./second", "tool@link:./first"}}
	origins := classicLocalLocators(entry)
	if len(origins) != 2 || origins[0].path != "./first" || origins[1].path != "./second" {
		t.Fatal(origins)
	}
}

func TestClassicResolvedArtifactOverridesLocalSelectors(t *testing.T) {
	dir := t.TempDir()
	lock := "# yarn lockfile v1\n\n\"tool@link:./local\":\n  version \"1.0.0\"\n  resolved \"https://registry.yarnpkg.com/tool/-/tool-1.0.0.tgz\"\n"
	for name, data := range map[string]string{"yarn.lock": lock, "package.json": `{"dependencies":{"tool":"link:./local"}}`} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	doc, err := Collect(filepath.Join(dir, "yarn.lock"), "test")
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Components) != 1 || doc.Components[0].Kind != "package" || !strings.HasPrefix(doc.Components[0].PURL, "pkg:npm/tool@1.0.0?download_url=") || doc.Components[0].PURLBasis != "source_qualified" {
		t.Fatal(doc.Components)
	}
	if len(doc.Origins) != 1 || doc.Origins[0].Kind != "download_url" {
		t.Fatal(doc.Origins)
	}
}

func TestClassicLocatorPathIsNotAnAliasProtocol(t *testing.T) {
	entry := classicEntry{descriptors: []string{"thing@https://example.test/@npm:/archive.tgz"}, version: "1.0.0"}
	name, alias, valid := classicEntryName(entry)
	if !valid || name != "thing" || alias != "" {
		t.Fatal(name, alias, valid)
	}
}
