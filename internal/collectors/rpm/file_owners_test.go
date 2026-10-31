package rpm

import (
	"testing"

	rpmdb "github.com/anchore/go-rpmdb/pkg"
)

func TestRPMFileOwnersRejectMissingAndUnsafeRecords(t *testing.T) {
	wanted := map[string]bool{
		"/usr/bin/tool": true, "/usr/bin/ghost": true,
		"/usr/bin/optional": true, "/usr/bin/unsafe": true,
	}
	provider := installedPackage{
		name: "provider", ref: "provider-ref",
		header: &rpmdb.PackageInfo{
			BaseNames:  []string{"tool", "ghost", "optional"},
			DirNames:   []string{"/usr/bin/"},
			DirIndexes: []int32{0, 0, 0},
			FileFlags:  []int32{0, rpmdb.RPMFILE_GHOST, rpmdb.RPMFILE_MISSINGOK},
		},
	}
	owners, issues := indexFileOwners([]installedPackage{provider}, wanted)
	if len(owners["/usr/bin/tool"]) != 1 || owners["/usr/bin/tool"][0].ref != "provider-ref" {
		t.Fatalf("regular owned file was not found: %#v", owners)
	}
	if len(owners) != 1 || len(issues) != 0 {
		t.Fatalf("ghost or missing-ok owner accepted: owners=%#v issues=%#v", owners, issues)
	}
	broken := installedPackage{name: "broken", header: &rpmdb.PackageInfo{
		BaseNames: []string{"unsafe"}, DirIndexes: []int32{-1},
		DirNames: []string{"/usr/bin/"}, FileFlags: []int32{0},
	}}
	owners, issues = indexFileOwners([]installedPackage{provider, broken}, wanted)
	if len(owners) != 0 || len(issues) != 1 || issues[0].Code != "rpm_file_inventory_unavailable" {
		t.Fatalf("incomplete ownership inventory was treated as certain: owners=%#v issues=%#v", owners, issues)
	}
	for _, unsafe := range []string{"/usr/../bin/tool", "//usr/bin/tool", "/usr/bin/./tool"} {
		if validRPMFileRequirement(unsafe) {
			t.Fatalf("unsafe requirement path accepted: %q", unsafe)
		}
	}
	for _, unsafe := range []string{"//usr/bin/", "/usr/../bin/", "/usr/bin//"} {
		if validRPMFileDirectory(unsafe) {
			t.Fatalf("unsafe inventory directory accepted: %q", unsafe)
		}
	}
}
