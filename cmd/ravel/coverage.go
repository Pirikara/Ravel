package main

import (
	"encoding/json"

	"ravel/internal/export"
	"ravel/internal/model"
)

func coverageReport(doc model.Document, format string) ([]byte, error) {
	report := struct {
		model.Coverage
		OutputFormat string        `json:"outputFormat"`
		OutputLosses []export.Loss `json:"outputLosses"`
	}{
		Coverage:     doc.Coverage,
		OutputFormat: format,
		OutputLosses: export.Losses(doc, format),
	}
	return json.MarshalIndent(report, "", "  ")
}
