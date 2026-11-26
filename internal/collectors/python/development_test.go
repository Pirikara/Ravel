package python

import (
	"strings"
	"testing"

	"github.com/Pirikara/Ravel/internal/collectors/common"
	"github.com/Pirikara/Ravel/internal/model"
)

func TestCoreMetadataDevelopment(t *testing.T) {
	for _, test := range []struct {
		headers     string
		count       int
		status, url string
	}{
		{"Project-URL: Source+Code, https://code.example.test/source\nHome-page: https://github.com/owner/other\n", 1, "declared", "https://code.example.test/source"},
		{"Project-URL: GitHub, https://github.com/owner/project\n", 1, "declared", "https://github.com/owner/project"},
		{"Project-URL: Documentation, https://docs.example.test\nProject-URL: Issues, https://github.com/owner/project/issues\n", 0, "", ""},
		{"Home-page: https://github.com/owner/project\n", 1, "inferred_from_homepage", "https://github.com/owner/project"},
		{"Home-page: https://project.example.test\n", 0, "", ""},
		{"Project-URL: Home page, https://github.com/owner/project\n", 1, "inferred_from_homepage", "https://github.com/owner/project"},
	} {
		headers, ok := parseWheelHeaders([]byte(test.headers))
		if !ok {
			t.Fatal(test.headers)
		}
		doc := common.NewDocument("METADATA", "sample", "python", nil)
		metadataDevelopment(&doc, "pkg", headers, model.Evidence{InputPath: "METADATA", InputDigest: "sha256:sample"})
		if len(doc.Development) != test.count {
			t.Fatalf("%s: %+v", test.headers, doc.Development)
		}
		if test.count > 0 && (doc.Development[0].Status != test.status || doc.Development[0].SafeURL != test.url || !strings.Contains(doc.Development[0].Evidence.Pointer, "/")) {
			t.Fatal(doc.Development)
		}
		if len(doc.Origins) != 0 {
			t.Fatal("source link became a distribution origin")
		}
	}
}
