package report

import (
	"errors"
	"fmt"
	"strings"

	"ravel/internal/model"
)

type Explanation struct {
	Component   model.Component     `json:"component"`
	Origins     []model.Origin      `json:"origins"`
	Development []model.Development `json:"development"`
	Incoming    []model.Edge        `json:"incoming"`
	Outgoing    []model.Edge        `json:"outgoing"`
	Coverage    model.Coverage      `json:"coverage"`
}

func Explain(doc model.Document, query string) (Explanation, error) {
	if query == "" {
		return Explanation{}, errors.New("empty package query")
	}
	var matches []model.Component
	for _, component := range doc.Components {
		if component.ID == query || component.PURL == query && component.PURL != "" || component.Name == query {
			matches = append(matches, component)
		}
	}
	if len(matches) == 0 {
		return Explanation{}, fmt.Errorf("package %q not found", query)
	}
	if len(matches) > 1 {
		return Explanation{}, fmt.Errorf("package %q is ambiguous (%d occurrences); use a component ID", query, len(matches))
	}
	component := matches[0]
	result := Explanation{Component: component, Origins: []model.Origin{}, Development: []model.Development{}, Incoming: []model.Edge{}, Outgoing: []model.Edge{}, Coverage: doc.Coverage}
	for _, origin := range doc.Origins {
		if origin.Occurrence == component.ID {
			result.Origins = append(result.Origins, origin)
		}
	}
	for _, source := range doc.Development {
		if source.Occurrence == component.ID {
			result.Development = append(result.Development, source)
		}
	}
	for _, edge := range doc.Edges {
		if edge.To == component.ID {
			result.Incoming = append(result.Incoming, edge)
		}
		if edge.From == component.ID {
			result.Outgoing = append(result.Outgoing, edge)
		}
	}
	return result, nil
}

func Text(doc model.Document, explanation Explanation) string {
	component := explanation.Component
	lines := []string{fmt.Sprintf("%s@%s [%s]", component.Name, component.Version, component.ID)}
	evidenceLine := func(evidence model.Evidence) string {
		return "  evidence: " + evidence.Collector + " " + evidence.InputPath + " " + evidence.Pointer
	}
	if component.PURL != "" {
		lines = append(lines, "purl: "+component.PURL)
	}
	for _, patch := range component.Patches {
		lines = append(lines, fmt.Sprintf("patch: %s [%s]", patch.Path, patch.Status))
		if patch.Hash != nil {
			lines = append(lines, "  patch hash: "+patch.Hash.Alg+":"+patch.Hash.Content)
		}
		for _, evidence := range patch.Evidence {
			lines = append(lines, evidenceLine(evidence))
		}
	}
	for _, origin := range explanation.Origins {
		location := origin.SafeURL
		if location == "" {
			location = origin.LocalPath
		}
		if location == "" {
			location = origin.Target
		}
		if location == "" {
			location = "(local)"
		}
		line := fmt.Sprintf("origin: %s %s [%s]", origin.Kind, location, origin.Status)
		if origin.Revision != "" {
			line += " revision=" + origin.Revision
		}
		if origin.Target != "" && location != origin.Target {
			line += " target=" + origin.Target
		}
		lines = append(lines, line)
		lines = append(lines, evidenceLine(origin.Evidence))
	}
	if len(explanation.Origins) == 0 {
		lines = append(lines, "origin: unknown")
	}
	for _, source := range explanation.Development {
		lines = append(lines, "development: "+source.SafeURL+" ["+source.Status+"]")
		lines = append(lines, evidenceLine(source.Evidence))
	}
	nameFor := func(ref string) string {
		if ref == "root" {
			return doc.Project
		}
		for _, c := range doc.Components {
			if c.ID == ref {
				return c.Name + "@" + c.Version
			}
		}
		return ref
	}
	for _, edge := range explanation.Incoming {
		line := "required by: " + nameFor(edge.From)
		if edge.Condition != "" {
			line += " if " + edge.Condition
		}
		lines = append(lines, line)
		lines = append(lines, evidenceLine(edge.Evidence))
	}
	for _, edge := range explanation.Outgoing {
		line := "depends on: " + nameFor(edge.To)
		if edge.Condition != "" {
			line += " if " + edge.Condition
		}
		lines = append(lines, line)
		lines = append(lines, evidenceLine(edge.Evidence))
	}
	for _, evidence := range component.Evidence {
		lines = append(lines, evidenceLine(evidence))
	}
	lines = append(lines, "coverage: graph="+doc.Coverage.GraphState+" origin="+doc.Coverage.OriginState)
	return strings.Join(lines, "\n") + "\n"
}
