package merge

import (
	"github.com/Pirikara/Ravel/internal/collectors/common"
	"github.com/Pirikara/Ravel/internal/model"
	"testing"
)

func TestMergedApplicationKeepsLicenseEvidence(t *testing.T) {
	doc := common.NewDocument("app/package-lock.json", "app", "npm", nil)
	doc.Root = &model.ProjectIdentity{Name: "app", Version: "1.0.0", Licenses: []model.LicenseDeclaration{{Kind: "license", Value: "MIT", Evidence: []model.Evidence{{InputPath: "app/package.json", Pointer: "/license"}}}}}
	other := common.NewDocument("other/requirements.txt", "other", "requirements", nil)
	combined, err := Documents("combined", []model.Document{doc, other})
	if err != nil {
		t.Fatal(err)
	}
	if len(combined.Components) != 1 || len(combined.Components[0].Licenses) != 1 || combined.Components[0].Licenses[0].Evidence[0].InputPath != "app/package.json" {
		t.Fatal(combined.Components)
	}
}
