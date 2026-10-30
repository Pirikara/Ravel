package integration_test

import (
	"strings"
	"testing"
)

func TestOCIYarnVersionedInstallation(t *testing.T) {
	for _, test := range []struct {
		name      string
		manifest  string
		want      int
		wantIssue string
	}{
		{name: "valid", manifest: `{"name":"yarn","version":"1.22.22"}`, want: 1},
		{name: "wrong_name", manifest: `{"name":"not-yarn","version":"1.22.22"}`, wantIssue: "node_installed_metadata_invalid"},
		{name: "wrong_version", manifest: `{"name":"yarn","version":"1.22.21"}`, wantIssue: "node_installed_metadata_invalid"},
	} {
		t.Run(test.name, func(t *testing.T) {
			layout := ociTestLayout(t)
			image := ociTestImage(t, layout, "linux", "amd64", []ociTestLayer{{entries: []ociTestEntry{{name: "opt/yarn-v1.22.22/package.json", data: []byte(test.manifest)}}}})
			ociTestIndex(t, layout, image)
			doc, output, code := ociTestScan(t, layout)
			if code != 0 || len(doc.Components) != test.want {
				t.Fatalf("versioned Yarn inventory incorrect: code=%d output=%s doc=%#v", code, output, doc)
			}
			if test.want == 1 && (doc.Components[0].Name != "yarn" || doc.Components[0].Version != "1.22.22" || !strings.HasSuffix(doc.Components[0].Evidence[0].InputPath, "!/opt/yarn-v1.22.22/package.json")) {
				t.Fatalf("Yarn identity or evidence incorrect: %#v", doc.Components[0])
			}
			if test.wantIssue != "" {
				found := false
				for _, issue := range doc.Coverage.Issues {
					found = found || issue.Code == test.wantIssue
				}
				if !found {
					t.Fatalf("invalid Yarn metadata not reported: %#v", doc.Coverage.Issues)
				}
			}
		})
	}
}
