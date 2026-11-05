package merge

import (
	"fmt"

	"github.com/Pirikara/Ravel/internal/collectors/common"
	"github.com/Pirikara/Ravel/internal/model"
	"github.com/Pirikara/Ravel/internal/safeurl"
)

// Documents combines explicit Ravel scans without asserting package identity
// across input scopes. Every input occurrence receives a distinct ID.
func Documents(project string, inputs []model.Document) (model.Document, error) {
	if project == "" || len(inputs) < 2 {
		return model.Document{}, fmt.Errorf("merge requires a project name and at least two inputs")
	}
	doc := common.NewDocument("merged", project, "multi", nil)
	doc.Sources = []string{}
	doc.Coverage.Inputs = []model.InputCoverage{}
	seenScopes := map[string]bool{}
	seenSources := map[string]bool{}
	allGraphComplete, allGraphUnknown, allOriginComplete := true, true, true
	for index, input := range inputs {
		if input.SchemaVersion != "0.1" {
			return model.Document{}, fmt.Errorf("input %d has unsupported Ravel JSON schema", index)
		}
		scopes := []model.InputCoverage{{
			Project: input.Project, Source: input.Source, Manager: input.Coverage.Manager,
			GraphState: input.Coverage.GraphState, OriginState: input.Coverage.OriginState,
			Packages: input.Coverage.Packages, Edges: input.Coverage.Edges, Issues: input.Coverage.Issues,
		}}
		if input.Coverage.Manager == "multi" && len(input.Coverage.Inputs) > 0 {
			scopes = input.Coverage.Inputs
		}
		hasGitHubActions := false
		for _, item := range scopes {
			hasGitHubActions = hasGitHubActions || item.Manager == "github-actions"
			scope := item.Manager + "\x00" + item.Project + "\x00" + item.Source
			if seenScopes[scope] {
				return model.Document{}, fmt.Errorf("duplicate input scope: %s (%s)", item.Project, item.Manager)
			}
			seenScopes[scope] = true
			if !seenSources[item.Source] {
				seenSources[item.Source] = true
				doc.Sources = append(doc.Sources, item.Source)
			}
			doc.Coverage.Inputs = append(doc.Coverage.Inputs, item)
		}
		for _, source := range input.Sources {
			if source != "" && !seenSources[source] {
				seenSources[source] = true
				doc.Sources = append(doc.Sources, source)
			}
		}
		if input.Coverage.GraphState != "complete_for_scope" {
			allGraphComplete = false
		}
		if input.Coverage.GraphState != "unknown" {
			allGraphUnknown = false
		}
		if input.Coverage.OriginState != "complete_for_scope" {
			allOriginComplete = false
		}
		for _, issue := range input.Coverage.Issues {
			if issue.Scope == "" {
				issue.Scope = input.Source
			}
			doc.Coverage.Issues = append(doc.Coverage.Issues, issue)
		}
		ids := map[string]string{"root": "root"}
		componentNames := map[string]string{}
		for _, component := range input.Components {
			if component.ID == "" || component.ID == "root" {
				return model.Document{}, fmt.Errorf("input %d has invalid component ID", index)
			}
			if _, exists := ids[component.ID]; exists {
				return model.Document{}, fmt.Errorf("input %d has duplicate component ID %q", index, component.ID)
			}
			id := "merge:" + common.ID(fmt.Sprintf("%d|%s|%s", index, input.Source, component.ID))
			ids[component.ID] = id
			componentNames[component.ID] = component.Name
			component.ID = id
			doc.Components = append(doc.Components, component)
		}
		for _, edge := range input.Edges {
			from, fromOK := ids[edge.From]
			to, toOK := ids[edge.To]
			if !fromOK || !toOK {
				return model.Document{}, fmt.Errorf("input %d has dangling dependency", index)
			}
			edge.From, edge.To = from, to
			doc.Edges = append(doc.Edges, edge)
		}
		for _, origin := range input.Origins {
			id, ok := ids[origin.Occurrence]
			if !ok || id == "root" {
				return model.Document{}, fmt.Errorf("input %d has dangling origin", index)
			}
			if origin.SafeURL != "" && safeurl.Clean(origin.SafeURL) != origin.SafeURL &&
				!(hasGitHubActions && safeurl.IsGitHubActionsRepository(origin.SafeURL, componentNames[origin.Occurrence])) {
				return model.Document{}, fmt.Errorf("input %d has unsafe origin URL", index)
			}
			origin.Occurrence = id
			doc.Origins = append(doc.Origins, origin)
		}
		for _, source := range input.Development {
			id, ok := ids[source.Occurrence]
			if !ok || id == "root" {
				return model.Document{}, fmt.Errorf("input %d has dangling development source", index)
			}
			if source.SafeURL == "" || safeurl.Clean(source.SafeURL) != source.SafeURL &&
				!(hasGitHubActions && safeurl.IsGitHubActionsRepository(source.SafeURL, componentNames[source.Occurrence])) {
				return model.Document{}, fmt.Errorf("input %d has unsafe development URL", index)
			}
			source.Occurrence = id
			doc.Development = append(doc.Development, source)
		}
		doc.Runtimes = append(doc.Runtimes, input.Runtimes...)
	}
	common.Finalize(&doc)
	if allGraphComplete {
		doc.Coverage.GraphState = "complete_for_scope"
	} else if allGraphUnknown {
		doc.Coverage.GraphState = "unknown"
	} else {
		doc.Coverage.GraphState = "partial"
	}
	if allOriginComplete {
		doc.Coverage.OriginState = "complete_for_scope"
	} else {
		doc.Coverage.OriginState = "partial"
	}
	return doc, nil
}
