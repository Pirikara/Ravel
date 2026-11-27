package renv

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"

	"github.com/Pirikara/Ravel/internal/collectors/common"
	"github.com/Pirikara/Ravel/internal/licensing"
	"github.com/Pirikara/Ravel/internal/model"
)

var dependencySpec = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9.]*)(?:\s*\(\s*(?:>=|<=|==|=|>|<)\s*[0-9]+(?:[.-][0-9]+)*\s*\))?$`)

func metadataList(raw json.RawMessage) ([]string, bool) {
	var values []string
	if json.Unmarshal(raw, &values) == nil {
		return values, true
	}
	var text string
	if json.Unmarshal(raw, &text) == nil {
		return strings.Split(text, ","), true
	}
	return nil, false
}

func addMetadata(doc *model.Document, c *model.Component, record packageRecord, evidence model.Evidence) {
	if len(record.License) != 0 {
		var value string
		if json.Unmarshal(record.License, &value) == nil {
			e := evidence
			e.Pointer += "/License"
			c.Licenses = licensing.Declare(value, "license", e)
		} else {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "renv_metadata_invalid", Name: c.Name, Scope: "License"})
		}
	}
	if len(record.URL) != 0 {
		values, ok := metadataList(record.URL)
		if !ok {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "renv_metadata_invalid", Name: c.Name, Scope: "URL"})
			return
		}
		for _, value := range values {
			fields := strings.Fields(value)
			if len(fields) == 0 {
				continue
			}
			if repo := common.RepositoryHomepage(fields[0]); repo != "" {
				e := evidence
				e.Pointer += "/URL"
				common.AddDevelopment(doc, c.ID, repo, "inferred_from_project_url", e)
			}
		}
	}
}

func addDependencies(doc *model.Document, parent packageEntry, entries map[string]packageEntry) {
	seen := map[string]bool{}
	hasMetadata := false
	for _, category := range []struct {
		name string
		raw  json.RawMessage
	}{{"Depends", parent.record.Depends}, {"Imports", parent.record.Imports}, {"LinkingTo", parent.record.LinkingTo}} {
		if len(category.raw) == 0 {
			continue
		}
		hasMetadata = true
		values, ok := metadataList(category.raw)
		if !ok {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "renv_requirements_invalid", Name: parent.name, Scope: category.name})
			continue
		}
		var array []string
		arrayValue := json.Unmarshal(category.raw, &array) == nil
		for index, spec := range values {
			spec = strings.TrimSpace(spec)
			if spec == "" {
				continue
			}
			match := dependencySpec.FindStringSubmatch(spec)
			if match == nil {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "renv_requirements_invalid", Name: parent.name, Scope: category.name})
				continue
			}
			name := match[1]
			seen[name] = true
			if name == "R" {
				continue
			}
			child, found := entries[name]
			if !found {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unresolved_dependency", Name: name, Scope: parent.name})
				continue
			}
			e := parent.evidence
			// A JSON string field is one value; array entries have their own index.
			e.Pointer += "/" + category.name
			if arrayValue {
				e.Pointer += "/" + strconv.Itoa(index)
			}
			condition := "category=" + category.name + "; requirement=" + spec + "; version constraint unverified"
			if category.name == "LinkingTo" {
				condition += "; kind=build"
			}
			doc.Edges = append(doc.Edges, model.Edge{From: parent.id, To: child.id, Kind: "requires", Condition: condition, Evidence: e})
		}
	}
	if len(parent.record.Requirements) == 0 {
		if !hasMetadata {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "renv_requirements_unavailable", Name: parent.name})
		}
		return
	}
	var requirements []any
	if json.Unmarshal(parent.record.Requirements, &requirements) != nil {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "renv_requirements_invalid", Name: parent.name})
		return
	}
	for index, raw := range requirements {
		name, ok := raw.(string)
		if !ok || !packageName.MatchString(name) {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "renv_requirements_invalid", Name: parent.name})
			continue
		}
		if name == "R" || seen[name] {
			continue
		}
		child, found := entries[name]
		if !found {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unresolved_dependency", Name: name, Scope: parent.name})
			continue
		}
		e := parent.evidence
		e.Pointer += "/Requirements/" + strconv.Itoa(index)
		doc.Edges = append(doc.Edges, model.Edge{From: parent.id, To: child.id, Kind: "requires", Condition: "dependency category unverified", Evidence: e})
	}
}
