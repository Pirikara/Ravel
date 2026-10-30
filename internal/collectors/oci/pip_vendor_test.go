package oci

import (
	"strings"
	"testing"
)

const testPipVendorPath = "usr/local/lib/python3.13/site-packages/pip/_vendor/vendor.txt"

func TestCollectPipVendorManifest(t *testing.T) {
	data := []byte("CacheControl==0.14.4\nrequests==2.34.2\n    certifi==2026.10.19\n")
	source := "oci:sha256:layer!/" + testPipVendorPath
	doc, err := collectPipVendor(data, source, "image", testPipVendorPath, "pip:installed")
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Components) != 3 || len(doc.Edges) != 3 || doc.Coverage.GraphState != "partial" || doc.Coverage.OriginState != "partial" {
		t.Fatalf("pip vendor manifest inventory incorrect: %#v", doc)
	}
	want := map[string]int{"CacheControl@0.14.4": 1, "requests@2.34.2": 2, "certifi@2026.10.19": 3}
	for _, component := range doc.Components {
		line := want[component.Name+"@"+component.Version]
		if line == 0 || component.PURL != "" || !strings.Contains(component.Context, "vendor=pip") || len(component.Evidence) != 1 || component.Evidence[0].Line != line || component.Evidence[0].InputPath != source {
			t.Fatalf("pip vendor identity or evidence incorrect: %#v", component)
		}
	}
	for _, edge := range doc.Edges {
		if edge.From != "pip:installed" || edge.Kind != "embedded" {
			t.Fatalf("pip vendored relationship incorrect: %#v", edge)
		}
	}
	fallback, err := collectPipVendor(data, source, "image", testPipVendorPath, "")
	if err != nil || fallback.Edges[0].From != "root" || fallback.Edges[0].Kind != "installed" {
		t.Fatalf("unmatched pip vendor parent was lost: err=%v doc=%#v", err, fallback)
	}
	if !isPipVendorPath(testPipVendorPath) || isPipVendorPath("other/vendor.txt") || isPipVendorPath("usr/local/lib/site-packages/other/_vendor/vendor.txt") || isPipVendorPath("../site-packages/pip/_vendor/vendor.txt") {
		t.Fatal("pip vendor path recognition incorrect")
	}
}

func TestCollectPipVendorRejectsInvalidEntries(t *testing.T) {
	for _, data := range []string{
		"requests>=2.0\n",
		"requests==2.0\nRequests==3.0\n",
		"../escape==1.0\n",
		"requests==1.0/../../other\n",
		"\n# no packages\n",
	} {
		if _, err := collectPipVendor([]byte(data), "oci:sha256:layer!/"+testPipVendorPath, "image", testPipVendorPath, "pip:installed"); err == nil {
			t.Fatalf("invalid pip vendor entry accepted: %q", data)
		}
	}
}
