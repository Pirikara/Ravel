package integration_test

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

const (
	ociSetuptoolsSiteDir = "ak-root/.venv/lib/python3.14/site-packages"
	ociSetuptoolsPath    = ociSetuptoolsSiteDir + "/setuptools-83.0.0.dist-info/METADATA"
	ociVendoredPath      = ociSetuptoolsSiteDir + "/setuptools/_vendor/autocommand-2.2.2.dist-info/METADATA"
)

func TestOCISetuptoolsVendoredMetadata(t *testing.T) {
	vendor := []byte("Metadata-Version: 2.4\nName: autocommand\nVersion: 2.2.2\n")
	layout := ociTestLayout(t)
	image := ociTestImage(t, layout, "linux", "arm64", []ociTestLayer{{entries: []ociTestEntry{
		{name: ociSetuptoolsPath, data: []byte("Metadata-Version: 2.4\nName: setuptools\nVersion: 83.0.0\n")},
		{name: ociVendoredPath, data: vendor},
	}}})
	ociTestIndex(t, layout, image)
	doc, output, code := ociTestScan(t, layout)
	if code != 0 || doc.Coverage.Packages != 2 || doc.Coverage.Edges != 2 || doc.Coverage.GraphState != "partial" || doc.Coverage.OriginState != "partial" {
		t.Fatalf("setuptools vendor inventory incorrect: code=%d output=%s coverage=%#v", code, output, doc.Coverage)
	}
	setuptoolsID := ""
	vendorID := ""
	hash := sha256.Sum256(vendor)
	for _, component := range doc.Components {
		switch component.Name {
		case "setuptools":
			setuptoolsID = component.ID
		case "autocommand":
			vendorID = component.ID
			if component.Version != "2.2.2" || component.PURL != "" || !strings.Contains(component.Context, "vendor=setuptools;image=linux/arm64") || len(component.Evidence) != 1 || component.Evidence[0].Collector != "python-vendor-dist-info" || component.Evidence[0].InputDigest != "sha256:"+hex.EncodeToString(hash[:]) || !strings.HasSuffix(component.Evidence[0].InputPath, "!/"+ociVendoredPath) {
				t.Fatalf("setuptools vendored identity or evidence incorrect: %#v", component)
			}
		default:
			t.Fatalf("unexpected Python distribution: %#v", component)
		}
	}
	if setuptoolsID == "" || vendorID == "" {
		t.Fatalf("expected installed and vendored packages: %#v", doc.Components)
	}
	for _, edge := range doc.Edges {
		if edge.To == vendorID && (edge.From != setuptoolsID || edge.Kind != "embedded") {
			t.Fatalf("setuptools vendored relationship incorrect: %#v", edge)
		}
	}
}

func TestOCISetuptoolsVendorOverlay(t *testing.T) {
	for _, test := range []struct {
		name      string
		upper     ociTestEntry
		want      int
		wantIssue string
	}{
		{name: "whiteout", upper: ociTestEntry{name: ociSetuptoolsSiteDir + "/setuptools/_vendor/autocommand-2.2.2.dist-info/.wh.METADATA"}, want: 1},
		{name: "parent_whiteout", upper: ociTestEntry{name: ociSetuptoolsSiteDir + "/setuptools/.wh._vendor"}, want: 1},
		{name: "invalid_replacement", upper: ociTestEntry{name: ociVendoredPath, data: []byte("Metadata-Version: 2.4\nName: other\nVersion: 2.2.2\n")}, want: 1, wantIssue: "setuptools_vendor_metadata_invalid"},
		{name: "valid_replacement", upper: ociTestEntry{name: ociVendoredPath, data: []byte("Metadata-Version: 2.4\nName: autocommand\nVersion: 2.2.2\n")}, want: 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			layout := ociTestLayout(t)
			image := ociTestImage(t, layout, "linux", "arm64", []ociTestLayer{
				{entries: []ociTestEntry{
					{name: ociSetuptoolsPath, data: []byte("Metadata-Version: 2.4\nName: setuptools\nVersion: 83.0.0\n")},
					{name: ociVendoredPath, data: []byte("Metadata-Version: 2.4\nName: autocommand\nVersion: 2.2.2\n")},
				}},
				{entries: []ociTestEntry{test.upper}},
			})
			ociTestIndex(t, layout, image)
			doc, output, code := ociTestScan(t, layout)
			if code != 0 || len(doc.Components) != test.want {
				t.Fatalf("setuptools vendor overlay incorrect: code=%d output=%s components=%#v", code, output, doc.Components)
			}
			if test.wantIssue != "" {
				found := false
				for _, issue := range doc.Coverage.Issues {
					found = found || issue.Code == test.wantIssue
				}
				if !found {
					t.Fatalf("invalid setuptools vendor metadata not reported: %#v", doc.Coverage.Issues)
				}
			}
		})
	}
}
