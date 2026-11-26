package export

import (
	"strings"

	"github.com/Pirikara/Ravel/internal/model"
)

// Loss describes information retained in Ravel JSON but not represented in
// the selected interchange format. Counts refer to records, not packages.
type Loss struct {
	Code  string `json:"code"`
	Count int    `json:"count"`
}

func Losses(doc model.Document, format string) []Loss {
	losses := []Loss{}
	if format == "ravel-json" {
		return losses
	}
	add := func(code string, count int) {
		if count > 0 {
			losses = append(losses, Loss{Code: code, Count: count})
		}
	}
	conditional, edgeKinds, annotatedEdges := 0, 0, 0
	for _, edge := range doc.Edges {
		if isImageLockEdge(edge) {
			annotatedEdges++
		} else if edge.Condition != "" {
			conditional++
		} else if edge.Kind != "" {
			edgeKinds++
		}
	}
	add("conditional_edges_omitted", conditional)
	add("conditional_edges_annotated", annotatedEdges)
	add("edge_kinds_omitted", edgeKinds)
	evidence := 0
	for _, component := range doc.Components {
		for _, e := range component.Evidence {
			if e.Method != "image-lockfile-correlation" {
				evidence++
			}
		}
		for _, patch := range component.Patches {
			evidence += len(patch.Evidence)
		}
	}
	for _, edge := range doc.Edges {
		if edge.Evidence.Collector != "" && !isImageLockEdge(edge) {
			evidence++
		}
	}
	for _, origin := range doc.Origins {
		if origin.Evidence.Collector != "" && !isAnnotatedImageOrigin(origin) {
			evidence++
		}
	}
	for _, runtime := range doc.Runtimes {
		if runtime.Evidence.Collector != "" {
			evidence++
		}
	}
	add("evidence_records_omitted", evidence)
	sources := len(doc.Sources)
	if doc.Source != "" {
		sources++
	}
	add("source_paths_omitted", sources)
	add("coverage_issues_omitted", len(doc.Coverage.Issues))
	if format == "spdx-json" {
		add("origin_records_as_text", len(doc.Origins))
		platforms, hashes := 0, 0
		for _, component := range doc.Components {
			if component.Platform != "" {
				platforms++
			}
			for _, hash := range component.Hashes {
				algorithm := strings.ReplaceAll(strings.ToUpper(hash.Alg), "-", "")
				switch algorithm {
				case "SHA1", "SHA256", "SHA384", "SHA512", "MD5":
				default:
					hashes++
				}
			}
		}
		add("component_platforms_omitted", platforms)
		add("unsupported_hashes_omitted", hashes)
	} else {
		originStatus := 0
		for _, origin := range doc.Origins {
			_, hasReference := originReference(origin)
			if origin.Status != "" && !isAnnotatedImageOrigin(origin) && !hasReference {
				originStatus++
			}
		}
		add("origin_statuses_omitted", originStatus)
	}

	return losses
}
