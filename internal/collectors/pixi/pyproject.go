package pixi

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Pirikara/Ravel/internal/model"
)

type nativeDependencies struct {
	doc              *model.Document
	projectName      string
	optional, groups map[string]any
	defaultRequests  []directRequest
	cache            map[string][]directRequest
	resolving        map[string]bool
}

func newNativeDependencies(doc *model.Document, parsed map[string]any) *nativeDependencies {
	project := asTable(parsed["project"])
	native := &nativeDependencies{
		doc: doc, optional: asTable(project["optional-dependencies"]), groups: asTable(parsed["dependency-groups"]),
		cache: map[string][]directRequest{}, resolving: map[string]bool{},
	}
	native.projectName, _ = project["name"].(string)
	if raw, found := project["requires-python"]; found {
		if version, ok := raw.(string); ok && version != "" {
			native.defaultRequests = append(native.defaultRequests, directRequest{name: "python", manager: "conda", pointer: "/project/requires-python"})
		} else {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "pixi_manifest_requirement_invalid", Name: "requires-python"})
		}
	}
	if raw, found := project["dependencies"]; found {
		native.defaultRequests = append(native.defaultRequests, native.parseList(raw, "/project/dependencies", false)...)
	}
	return native
}

func (n *nativeDependencies) hasFeature(name string) bool {
	_, optional := n.optional[name]
	_, group := n.groups[name]
	return optional || group
}

func (n *nativeDependencies) featureRequests(name string) []directRequest {
	if cached, found := n.cache[name]; found {
		return cached
	}
	if len(n.resolving) >= 64 {
		n.doc.Coverage.Issues = append(n.doc.Coverage.Issues, model.Issue{Code: "pixi_manifest_group_unresolved", Name: name})
		return nil
	}
	if n.resolving[name] {
		n.doc.Coverage.Issues = append(n.doc.Coverage.Issues, model.Issue{Code: "pixi_manifest_group_unresolved", Name: name})
		return nil
	}
	if !n.hasFeature(name) {
		n.doc.Coverage.Issues = append(n.doc.Coverage.Issues, model.Issue{Code: "pixi_manifest_group_unresolved", Name: name})
		return nil
	}
	n.resolving[name] = true
	var requests []directRequest
	if raw, found := n.optional[name]; found {
		requests = append(requests, n.parseList(raw, "/project/optional-dependencies/"+name, false)...)
	}
	if raw, found := n.groups[name]; found {
		requests = append(requests, n.parseList(raw, "/dependency-groups/"+name, true)...)
	}
	delete(n.resolving, name)
	n.cache[name] = requests
	return requests
}

func (n *nativeDependencies) parseList(raw any, pointer string, group bool) []directRequest {
	list, ok := raw.([]any)
	if !ok {
		n.doc.Coverage.Issues = append(n.doc.Coverage.Issues, model.Issue{Code: "pixi_manifest_requirement_invalid", Name: pointer})
		return nil
	}
	var requests []directRequest
	for index, item := range list {
		itemPointer := fmt.Sprintf("%s/%d", pointer, index)
		if spec, ok := item.(string); ok {
			name := requirementName(spec)
			if name == "" {
				n.doc.Coverage.Issues = append(n.doc.Coverage.Issues, model.Issue{Code: "pixi_manifest_requirement_invalid", Name: itemPointer})
				continue
			}
			if n.projectName != "" && normalizePyPIName(name) == normalizePyPIName(n.projectName) {
				if extras := selfExtras(spec, name); len(extras) > 0 {
					marker := strings.Contains(spec, ";")
					if marker {
						n.doc.Coverage.Issues = append(n.doc.Coverage.Issues, model.Issue{Code: "pixi_manifest_marker_unverified", Name: name})
					}
					for _, extra := range extras {
						for _, included := range n.featureRequests(extra) {
							included.marker = included.marker || marker
							requests = append(requests, included)
						}
					}
					continue
				}
				n.doc.Coverage.Issues = append(n.doc.Coverage.Issues, model.Issue{Code: "pixi_manifest_self_reference_unresolved", Name: itemPointer})
				continue
			}
			marker := strings.Contains(spec, ";")
			if marker {
				n.doc.Coverage.Issues = append(n.doc.Coverage.Issues, model.Issue{Code: "pixi_manifest_marker_unverified", Name: name})
			}
			requests = append(requests, directRequest{name: name, manager: "pypi", pointer: itemPointer, marker: marker})
			continue
		}
		if group {
			if table := asTable(item); len(table) == 1 {
				if included, ok := table["include-group"].(string); ok && scopePattern.MatchString(included) {
					requests = append(requests, n.featureRequests(included)...)
					continue
				}
			}
		}
		n.doc.Coverage.Issues = append(n.doc.Coverage.Issues, model.Issue{Code: "pixi_manifest_requirement_invalid", Name: itemPointer})
	}
	return requests
}

func selfExtras(spec, name string) []string {
	rest := strings.TrimSpace(spec[len(name):])
	if !strings.HasPrefix(rest, "[") {
		return nil
	}
	end := strings.IndexByte(rest, ']')
	if end < 2 {
		return nil
	}
	var result []string
	for _, part := range strings.Split(rest[1:end], ",") {
		value := strings.TrimSpace(part)
		if !scopePattern.MatchString(value) {
			return nil
		}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func filterOverriddenPyPI(requests []directRequest) []directRequest {
	condaNames := map[string]bool{}
	for _, request := range requests {
		if request.manager == "conda" {
			condaNames[normalizePyPIName(request.name)] = true
		}
	}
	filtered := make([]directRequest, 0, len(requests))
	for _, request := range requests {
		if request.manager != "pypi" || !condaNames[normalizePyPIName(request.name)] {
			filtered = append(filtered, request)
		}
	}
	return filtered
}
