package integration_test

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

const ociPipVendorPath = "usr/local/lib/python3.13/site-packages/pip/_vendor/vendor.txt"
const ociPipMetadataPath = "usr/local/lib/python3.13/site-packages/pip-25.3.dist-info/METADATA"

func TestOCIPipVendoredPackagesAndEvidence(t *testing.T) {
	vendor := []byte("CacheControl==0.14.4\nrequests==2.34.2\n    certifi==2026.10.19\n")
	layout := ociTestLayout(t)
	image := ociTestImage(t, layout, "linux", "amd64", []ociTestLayer{{entries: []ociTestEntry{
		{name: ociPipMetadataPath, data: []byte("Metadata-Version: 2.4\nName: pip\nVersion: 25.3\n")},
		{name: ociPipVendorPath, data: vendor},
	}}})
	ociTestIndex(t, layout, image)
	doc, output, code := ociTestScan(t, layout)
	if code != 0 || doc.Coverage.Packages != 4 || doc.Coverage.Edges != 4 || doc.Coverage.GraphState != "partial" || doc.Coverage.OriginState != "partial" {
		t.Fatalf("pip vendor inventory incorrect: code=%d output=%s coverage=%#v", code, output, doc.Coverage)
	}
	pipID := ""
	for _, component := range doc.Components {
		if component.Name == "pip" {
			pipID = component.ID
		}
	}
	if pipID == "" {
		t.Fatalf("pip package missing: %#v", doc.Components)
	}
	hash := sha256.Sum256(vendor)
	wantDigest := "sha256:" + hex.EncodeToString(hash[:])
	want := map[string]bool{"CacheControl@0.14.4": true, "requests@2.34.2": true, "certifi@2026.10.19": true}
	for _, component := range doc.Components {
		if component.Name == "pip" {
			continue
		}
		if !want[component.Name+"@"+component.Version] || component.Evidence[0].InputDigest != wantDigest || !strings.HasSuffix(component.Evidence[0].InputPath, "!/"+ociPipVendorPath) || !strings.Contains(component.Context, "vendor=pip;image=linux/amd64") {
			t.Fatalf("pip vendored package or evidence incorrect: %#v", component)
		}
	}
	linked := 0
	for _, edge := range doc.Edges {
		if edge.From == pipID && edge.Kind == "embedded" {
			linked++
		}
	}
	if linked != 3 {
		t.Fatalf("pip vendored edges missing: %#v", doc.Edges)
	}
}

func TestOCIPipVendorOverlayAndInvalidManifest(t *testing.T) {
	for _, test := range []struct {
		name      string
		upper     ociTestEntry
		want      int
		wantIssue string
	}{
		{name: "whiteout", upper: ociTestEntry{name: "usr/local/lib/python3.13/site-packages/pip/_vendor/.wh.vendor.txt"}, want: 1},
		{name: "invalid_replacement", upper: ociTestEntry{name: ociPipVendorPath, data: []byte("invalid requirement >=1\n")}, want: 1, wantIssue: "pip_vendor_manifest_invalid"},
		{name: "valid_replacement", upper: ociTestEntry{name: ociPipVendorPath, data: []byte("distlib==0.4.2\n")}, want: 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			layout := ociTestLayout(t)
			image := ociTestImage(t, layout, "linux", "amd64", []ociTestLayer{
				{entries: []ociTestEntry{
					{name: ociPipMetadataPath, data: []byte("Metadata-Version: 2.4\nName: pip\nVersion: 25.3\n")},
					{name: ociPipVendorPath, data: []byte("requests==2.34.2\n")},
				}},
				{entries: []ociTestEntry{test.upper}},
			})
			ociTestIndex(t, layout, image)
			doc, output, code := ociTestScan(t, layout)
			if code != 0 || len(doc.Components) != test.want {
				t.Fatalf("pip vendor overlay incorrect: code=%d output=%s components=%#v", code, output, doc.Components)
			}
			if test.wantIssue != "" {
				found := false
				for _, issue := range doc.Coverage.Issues {
					found = found || issue.Code == test.wantIssue
				}
				if !found {
					t.Fatalf("invalid pip vendor manifest not reported: %#v", doc.Coverage.Issues)
				}
			}
		})
	}
}
