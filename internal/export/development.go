package export

import (
	"encoding/json"

	"github.com/Pirikara/Ravel/internal/model"
)

func applyCycloneDXDevelopment(item *component, sources []model.Development, seen map[string]bool) {
	if seen == nil {
		seen = map[string]bool{}
	}
	for _, source := range sources {
		if !seen[source.SafeURL] {
			item.ExternalReferences = append(item.ExternalReferences, reference{Type: "vcs", URL: source.SafeURL, Comment: "Development repository; status: " + source.Status})
			seen[source.SafeURL] = true
		}
		item.Properties = append(item.Properties, property{Name: "ravel:developmentRepository", Value: source.SafeURL})
		value, _ := json.Marshal(source)
		item.Properties = append(item.Properties, property{Name: "ravel:developmentRepositoryEvidence", Value: string(value)})
	}
}

func applySPDXDevelopment(item *spdxPackage, sources []model.Development) {
	for _, source := range sources {
		if item.Comment != "" {
			item.Comment += "; "
		}
		value, _ := json.Marshal(source)
		item.Comment += "Development repository metadata: " + string(value)
	}
}
