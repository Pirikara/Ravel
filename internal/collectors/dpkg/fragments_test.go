package dpkg

import (
	"crypto/sha256"
	"fmt"
	"testing"
)

func TestStatusFragmentsKeepOriginalEvidenceAndCrossFileDependencies(t *testing.T) {
	fragments := map[string][]byte{
		"oci:layer!/var/lib/dpkg/status.d/alpha": []byte("Package: alpha\nVersion: 1.2.3\nArchitecture: arm64\nDepends: beta (>= 2.0)\n"),
		"oci:layer!/var/lib/dpkg/status.d/beta":  []byte("Package: beta\nVersion: 2.1\nArchitecture: arm64\n"),
	}
	doc, err := CollectFragments(fragments, "image", "example")
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Components) != 2 || len(doc.Edges) != 3 {
		t.Fatal("fragment packages or cross-file dependency lost", doc)
	}
	ids := map[string]string{}
	for _, c := range doc.Components {
		ids[c.Name] = c.ID
		if len(c.Evidence) != 1 || c.Evidence[0].Collector != "dpkg-status-fragment" || c.Evidence[0].Method != "installed-metadata" || c.Context != "metadata=dpkg-status-fragment" {
			t.Fatal("invented status or incorrect evidence", c)
		}
		e := c.Evidence[0]
		want := fmt.Sprintf("sha256:%x", sha256.Sum256(fragments[e.InputPath]))
		if e.InputDigest != want || e.Line != 1 {
			t.Fatal("fragment digest or line changed", e)
		}
	}
	found := false
	for _, e := range doc.Edges {
		if e.From == ids["alpha"] && e.To == ids["beta"] {
			found = true
			if e.Evidence.Line != 4 || e.Evidence.InputPath != "oci:layer!/var/lib/dpkg/status.d/alpha" {
				t.Fatal(e)
			}
		}
	}
	if !found {
		t.Fatal("cross-fragment dependency missing")
	}
	if _, err := CollectBytes(fragments["oci:layer!/var/lib/dpkg/status.d/alpha"], "status", "example"); err == nil {
		t.Fatal("active dpkg database accepted missing Status")
	}
}

func TestStatusFragmentsRejectConflictingPackageRecords(t *testing.T) {
	data := []byte("Package: alpha\nVersion: 1.2.3\nArchitecture: arm64\n")
	if _, err := CollectFragments(map[string][]byte{"one": data, "two": data}, "image", "example"); err == nil {
		t.Fatal("ambiguous duplicate package records accepted")
	}
	removed := []byte("Package: removed\nVersion: 1\nArchitecture: arm64\nStatus: deinstall ok config-files\n")
	doc, err := CollectFragments(map[string][]byte{"removed": removed}, "image", "example")
	if err != nil || len(doc.Components) != 0 {
		t.Fatal("removed package included", doc, err)
	}
}
