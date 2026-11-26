package export

import (
	"encoding/json"
	"strings"

	"github.com/Pirikara/Ravel/internal/licensing"
	"github.com/Pirikara/Ravel/internal/model"
)

type licenseAttachment struct {
	ContentType string `json:"contentType"`
	Content     string `json:"content"`
}
type namedLicense struct {
	ID              string             `json:"id,omitempty"`
	Name            string             `json:"name,omitempty"`
	Acknowledgement string             `json:"acknowledgement"`
	Text            *licenseAttachment `json:"text,omitempty"`
}
type licenseChoice struct {
	License         *namedLicense `json:"license,omitempty"`
	Expression      string        `json:"expression,omitempty"`
	Acknowledgement string        `json:"acknowledgement,omitempty"`
}

func applyCycloneDXLicenses(c *component, declarations []model.LicenseDeclaration) {
	seen := map[string]bool{}
	for _, d := range licensing.Normalize(declarations) {
		encoded, _ := json.Marshal(d)
		c.Properties = append(c.Properties, property{Name: "ravel:licenseDeclaration", Value: string(encoded)})
		if d.Kind == "url" {
			c.ExternalReferences = append(c.ExternalReferences, reference{Type: "license", URL: d.Value, Comment: "Declared license location; contents not independently verified"})
			continue
		}
		if d.Kind == "file" || d.Kind == "classifier" {
			continue
		}
		choice := licenseChoice{}
		if d.Expression != "" {
			if id := licensing.Identifier(d.Expression); id != "" {
				choice.License = &namedLicense{ID: id, Acknowledgement: "declared"}
			} else {
				choice = licenseChoice{Expression: d.Expression, Acknowledgement: "declared"}
			}
		} else {
			l := &namedLicense{Name: d.Value, Acknowledgement: "declared"}
			if d.Kind == "notice" || d.Kind == "alternatives" || strings.ContainsAny(d.Value, "\r\n") || len(d.Value) > 256 {
				l.Name = "Unidentified declared license"
				l.Text = &licenseAttachment{ContentType: "text/plain", Content: d.Value}
			}
			choice.License = l
		}
		key, _ := json.Marshal(choice)
		if !seen[string(key)] {
			c.Licenses = append(c.Licenses, choice)
			seen[string(key)] = true
		}
	}
}

func applySPDXLicenses(p *spdxPackage, declarations []model.LicenseDeclaration) {
	declarations = licensing.Normalize(declarations)
	p.LicenseDeclared = licensing.DeclaredExpression(declarations)
	if len(declarations) > 0 {
		encoded, _ := json.Marshal(declarations)
		p.LicenseComments = "Declared package metadata; no file-content or license conclusion: " + string(encoded)
	}
}
