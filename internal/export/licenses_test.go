package export

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Pirikara/Ravel/internal/model"
)

func TestDeclaredLicenseExports(t *testing.T) {
	declarations := []model.LicenseDeclaration{
		{Kind: "license", Value: "MIT", Evidence: []model.Evidence{{InputPath: "package.json", Pointer: "/license"}}},
		{Kind: "url", Value: "https://example.test/LICENSE"},
		{Kind: "file", Value: "LICENSE.txt"},
	}
	var c component
	applyCycloneDXLicenses(&c, declarations)
	if len(c.Licenses) != 1 || c.Licenses[0].License.ID != "MIT" || c.Licenses[0].License.Acknowledgement != "declared" || len(c.Properties) != 3 || len(c.ExternalReferences) != 1 {
		t.Fatalf("%+v", c)
	}
	var p spdxPackage
	applySPDXLicenses(&p, declarations)
	if p.LicenseDeclared != "MIT" || !strings.Contains(p.LicenseComments, "package.json") {
		t.Fatalf("%+v", p)
	}
	declarations = append(declarations, model.LicenseDeclaration{Kind: "license", Value: "Company terms\nCopyright notice"})
	applySPDXLicenses(&p, declarations)
	if p.LicenseDeclared != "NOASSERTION" {
		t.Fatal(p)
	}
	var named component
	applyCycloneDXLicenses(&named, declarations)
	found := false
	for _, l := range named.Licenses {
		if l.License != nil && l.License.Text != nil {
			found = true
		}
	}
	if !found {
		t.Fatal("long notice not retained", named.Licenses)
	}
	raw, _ := json.Marshal(named)
	if !strings.Contains(string(raw), "Company terms") {
		t.Fatal(string(raw))
	}
}
