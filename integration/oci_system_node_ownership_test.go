package integration_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

const (
	ociNodeOwnerPath = "var/lib/dpkg/info/node-acorn.list"
	ociNodePath      = "usr/share/nodejs/acorn/package.json"
)

var (
	ociNodeOwnerStatus = []byte("Package: node-acorn\nStatus: install ok installed\nArchitecture: all\nVersion: 8.8.1\n\n")
	ociNodeOwnerList   = []byte("/.\n/usr\n/usr/share\n/usr/share/nodejs\n/usr/share/nodejs/acorn\n/usr/share/nodejs/acorn/package.json\n")
)

func TestOCISystemNodeDPKGFileOwnership(t *testing.T) {
	layout := ociTestLayout(t)
	image := ociTestImage(t, layout, "linux", "amd64", []ociTestLayer{{entries: []ociTestEntry{
		{name: "var/lib/dpkg/status", data: ociNodeOwnerStatus},
		{name: ociNodeOwnerPath, data: ociNodeOwnerList},
		{name: ociNodePath, data: []byte(`{"name":"acorn","version":"8.8.1"}`)},
	}}})
	ociTestIndex(t, layout, image)
	doc, output, code := ociTestScan(t, layout)
	if code != 0 || doc.Coverage.Packages != 2 || doc.Coverage.Edges != 2 {
		t.Fatalf("system Node ownership inventory incorrect: code=%d output=%s coverage=%#v", code, output, doc.Coverage)
	}
	ids := map[string]string{}
	hash := sha256.Sum256(ociNodeOwnerList)
	wantDigest := "sha256:" + hex.EncodeToString(hash[:])
	for _, component := range doc.Components {
		ids[component.Name] = component.ID
		if component.Name == "acorn" {
			if len(component.Evidence) != 2 || component.Evidence[1].Collector != "dpkg-file-list" || component.Evidence[1].InputDigest != wantDigest || component.Evidence[1].Line != 6 || !strings.HasSuffix(component.Evidence[1].InputPath, "!/"+ociNodeOwnerPath) {
				t.Fatalf("Node component lacks exact dpkg ownership evidence: %#v", component)
			}
		}
	}
	if ids["node-acorn"] == "" || ids["acorn"] == "" {
		t.Fatalf("system Node and Debian identities missing: %#v", doc.Components)
	}
	for _, edge := range doc.Edges {
		if edge.To == ids["acorn"] && (edge.From != ids["node-acorn"] || edge.Kind != "embedded" || edge.Evidence.Collector != "dpkg-file-list") {
			t.Fatalf("Node module was not linked to its Debian owner: %#v", edge)
		}
	}
}

func TestOCISystemNodeDPKGOwnershipOverlay(t *testing.T) {
	for _, test := range []struct {
		name          string
		upper         ociTestEntry
		wantOwnerLink bool
	}{
		{name: "whiteout", upper: ociTestEntry{name: "var/lib/dpkg/info/.wh.node-acorn.list"}},
		{name: "parent_whiteout", upper: ociTestEntry{name: "var/lib/dpkg/.wh.info"}},
		{name: "replacement_without_manifest", upper: ociTestEntry{name: ociNodeOwnerPath, data: []byte("/usr/share/nodejs/other/package.json\n")}},
		{name: "replacement_with_manifest", upper: ociTestEntry{name: ociNodeOwnerPath, data: []byte("/usr/share/nodejs/acorn/package.json\n")}, wantOwnerLink: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			layout := ociTestLayout(t)
			image := ociTestImage(t, layout, "linux", "amd64", []ociTestLayer{
				{entries: []ociTestEntry{
					{name: "var/lib/dpkg/status", data: ociNodeOwnerStatus},
					{name: ociNodeOwnerPath, data: ociNodeOwnerList},
					{name: ociNodePath, data: []byte(`{"name":"acorn","version":"8.8.1"}`)},
				}},
				{entries: []ociTestEntry{test.upper}},
			})
			ociTestIndex(t, layout, image)
			doc, output, code := ociTestScan(t, layout)
			if code != 0 || len(doc.Components) != 2 || len(doc.Edges) != 2 {
				t.Fatalf("system Node ownership overlay incorrect: code=%d output=%s doc=%#v", code, output, doc)
			}
			nodeID := ""
			for _, component := range doc.Components {
				if component.Name == "acorn" {
					nodeID = component.ID
				}
			}
			linked := false
			for _, edge := range doc.Edges {
				if edge.To == nodeID {
					linked = edge.From != "root" && edge.Kind == "embedded"
				}
			}
			if linked != test.wantOwnerLink {
				t.Fatalf("stale or missing Node ownership link: %#v", doc.Edges)
			}
			if !linked {
				found := false
				for _, issue := range doc.Coverage.Issues {
					found = found || issue.Code == "node_system_owner_unresolved"
				}
				if !found {
					t.Fatalf("missing system Node ownership coverage issue: %#v", doc.Coverage.Issues)
				}
			}
		})
	}
}

func TestOCISystemNodeDPKGOwnershipAmbiguous(t *testing.T) {
	layout := ociTestLayout(t)
	status := []byte("Package: node-acorn\nStatus: install ok installed\nArchitecture: all\nVersion: 8.8.1\n\nPackage: node-acorn-copy\nStatus: install ok installed\nArchitecture: all\nVersion: 8.8.1\n\n")
	image := ociTestImage(t, layout, "linux", "amd64", []ociTestLayer{{entries: []ociTestEntry{
		{name: "var/lib/dpkg/status", data: status},
		{name: ociNodeOwnerPath, data: ociNodeOwnerList},
		{name: "var/lib/dpkg/info/node-acorn-copy.list", data: ociNodeOwnerList},
		{name: ociNodePath, data: []byte(`{"name":"acorn","version":"8.8.1"}`)},
	}}})
	ociTestIndex(t, layout, image)
	doc, output, code := ociTestScan(t, layout)
	if code != 0 || len(doc.Components) != 3 || len(doc.Edges) != 3 {
		t.Fatalf("ambiguous ownership inventory incorrect: code=%d output=%s doc=%#v", code, output, doc)
	}
	nodeID := ""
	for _, component := range doc.Components {
		if component.Name == "acorn" {
			nodeID = component.ID
			if len(component.Evidence) != 1 {
				t.Fatalf("ambiguous ownership supplied false evidence: %#v", component)
			}
		}
	}
	for _, edge := range doc.Edges {
		if edge.To == nodeID && (edge.From != "root" || edge.Kind != "installed") {
			t.Fatalf("ambiguous ownership created a false owner link: %#v", edge)
		}
	}
	found := false
	for _, issue := range doc.Coverage.Issues {
		found = found || issue.Code == "node_system_owner_ambiguous"
	}
	if !found || doc.Coverage.GraphState != "partial" {
		t.Fatalf("ambiguous ownership not reported: %#v", doc.Coverage)
	}
}

func TestOCISystemNodeDPKGOwnershipQualifiedList(t *testing.T) {
	layout := ociTestLayout(t)
	status := []byte("Package: node-acorn\nStatus: install ok installed\nArchitecture: amd64\nVersion: 8.8.1\n\n")
	image := ociTestImage(t, layout, "linux", "amd64", []ociTestLayer{{entries: []ociTestEntry{
		{name: "var/lib/dpkg/status", data: status},
		{name: "var/lib/dpkg/info/node-acorn:amd64.list", data: ociNodeOwnerList},
		{name: ociNodePath, data: []byte(`{"name":"acorn","version":"8.8.1"}`)},
	}}})
	ociTestIndex(t, layout, image)
	doc, output, code := ociTestScan(t, layout)
	if code != 0 || len(doc.Components) != 2 || len(doc.Edges) != 2 {
		t.Fatalf("qualified ownership inventory incorrect: code=%d output=%s doc=%#v", code, output, doc)
	}
	linked := false
	for _, edge := range doc.Edges {
		linked = linked || edge.Kind == "embedded" && edge.Evidence.Collector == "dpkg-file-list"
	}
	if !linked {
		t.Fatalf("architecture-qualified dpkg file list was not linked: %#v", doc.Edges)
	}
}

func TestOCISystemNodeDPKGOwnershipScanLimit(t *testing.T) {
	layout := ociTestLayout(t)
	oversized := append(bytes.Repeat([]byte("x"), 1<<20), '\n')
	image := ociTestImage(t, layout, "linux", "amd64", []ociTestLayer{{entries: []ociTestEntry{
		{name: "var/lib/dpkg/status", data: ociNodeOwnerStatus},
		{name: ociNodeOwnerPath, data: oversized},
		{name: ociNodePath, data: []byte(`{"name":"acorn","version":"8.8.1"}`)},
	}}})
	ociTestIndex(t, layout, image)
	doc, output, code := ociTestScan(t, layout)
	if code != 0 || len(doc.Components) != 2 || len(doc.Edges) != 2 {
		t.Fatalf("limited ownership inventory incorrect: code=%d output=%s doc=%#v", code, output, doc)
	}
	issues := map[string]bool{}
	for _, issue := range doc.Coverage.Issues {
		issues[issue.Code] = true
	}
	if !issues["node_system_owner_unresolved"] || !issues["node_system_ownership_scan_limited"] {
		t.Fatalf("ownership scan limit not reported: %#v", doc.Coverage.Issues)
	}
}
