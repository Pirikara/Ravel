package python

import (
	"strconv"
	"strings"

	"github.com/Pirikara/Ravel/internal/licensing"
	"github.com/Pirikara/Ravel/internal/model"
)

func metadataLicenses(headers []wheelHeader, evidence model.Evidence) []model.LicenseDeclaration {
	var declarations []model.LicenseDeclaration
	counts := map[string]int{}
	for _, header := range headers {
		kind := ""
		switch header.name {
		case "license-expression":
			kind = "expression"
		case "license":
			kind = "license"
		case "license-file":
			kind = "file"
		case "classifier":
			if strings.HasPrefix(header.value, "License ::") {
				kind = "classifier"
			}
		}
		if kind == "" {
			continue
		}
		e := evidence
		e.Pointer += "/" + header.name + "/" + strconv.Itoa(counts[header.name])
		counts[header.name]++
		declarations = append(declarations, licensing.Declare(header.value, kind, e)...)
	}
	return licensing.Normalize(declarations)
}
