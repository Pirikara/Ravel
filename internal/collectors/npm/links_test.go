package npm

import "testing"

func TestLockedLinksAndAncestorPlacements(t *testing.T) {
	actual := &item{location: "packages/actual"}
	parentTool := &item{location: "apps/desktop/node_modules/tool"}
	entries := map[string]*item{actual.location: actual, parentTool.location: parentTool}
	links := map[string]string{"node_modules/alias": "packages/actual", "node_modules/chain": "node_modules/alias", "node_modules/cycle-a": "node_modules/cycle-b", "node_modules/cycle-b": "node_modules/cycle-a", "node_modules/missing": "absent"}
	for _, sample := range []struct {
		name string
		want *item
	}{{"alias", actual}, {"chain", actual}, {"cycle-a", nil}, {"missing", nil}} {
		if got := resolve(entries, links, "", sample.name); got != sample.want {
			t.Fatal(sample.name, got)
		}
	}
	if got := resolve(entries, links, "apps/desktop/plugins/app", "tool"); got != parentTool {
		t.Fatal(got)
	}
	for _, location := range []string{"../outside", "/absolute", ".", "https://example.test/package"} {
		if localLockLocation(location) {
			t.Fatal(location)
		}
	}
}

func TestLockedWildcardAndLocalRequirement(t *testing.T) {
	pre := &item{data: lockPackage{Name: "peer", Version: "2.0.0-rc.1"}}
	if matched, verified := matchesNpmRequirement("*", pre); !matched || !verified {
		t.Fatal(matched, verified)
	}
	if matched, verified := matchesNpmRequirement("^1.0.0", pre); matched || !verified {
		t.Fatal(matched, verified)
	}
	local := &item{location: "apps/lib", data: lockPackage{Name: "lib", Version: "1.0.0"}}
	if matched, verified := matchesNpmRequirementAt("file:../lib", local, "apps/app"); !matched || !verified {
		t.Fatal(matched, verified)
	}
	if matched, verified := matchesNpmRequirementAt("file:../other", local, "apps/app"); matched || !verified {
		t.Fatal(matched, verified)
	}
}
