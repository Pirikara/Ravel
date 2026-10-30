package maven

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"ravel/internal/collectors/common"
	"ravel/internal/model"
)

type node struct {
	GroupID    string          `json:"groupId"`
	ArtifactID string          `json:"artifactId"`
	Version    string          `json:"version"`
	Type       string          `json:"type"`
	Classifier string          `json:"classifier"`
	Scope      string          `json:"scope"`
	Optional   json.RawMessage `json:"optional"`
	Children   []node          `json:"children"`
}

func CollectTree(file, project string) (model.Document, error) {
	data, root, err := readTree(file)
	if err != nil {
		return model.Document{}, err
	}
	return collectTree(file, project, data, root, nil)
}

func readTree(file string) ([]byte, node, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, node{}, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxTreeOutput+1))
	if err != nil {
		return nil, node{}, err
	}
	if len(data) > maxTreeOutput {
		return nil, node{}, fmt.Errorf("Maven dependency tree exceeded size limit")
	}
	var root node
	if err := json.Unmarshal(data, &root); err != nil {
		return nil, node{}, fmt.Errorf("invalid Maven dependency tree: %w", err)
	}
	if root.GroupID == "" || root.ArtifactID == "" || root.Version == "" {
		return nil, node{}, fmt.Errorf("Maven dependency tree root has no coordinates")
	}
	return data, root, nil
}

func collectTree(file, project string, data []byte, root node, stopAt func(node) bool) (model.Document, error) {
	doc := common.NewDocument(file, project, "maven", data)
	doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "manifest_freshness_unverified"})
	byKey := map[string]int{}
	contexts := map[string]map[string]bool{}
	seenEdges := map[string]bool{}
	count := 0
	var walk func(node, string, string, string, int) error
	walk = func(n node, parent, pointer, inheritedCondition string, depth int) error {
		if depth > 512 || count >= 100000 {
			return fmt.Errorf("Maven dependency tree exceeds size limit")
		}
		count++
		if n.GroupID == "" || n.ArtifactID == "" || n.Version == "" {
			return fmt.Errorf("Maven dependency tree node %s has no coordinates", pointer)
		}
		optional := false
		if len(n.Optional) > 0 {
			var raw string
			if err := json.Unmarshal(n.Optional, &raw); err == nil {
				if raw != "true" && raw != "false" {
					return fmt.Errorf("Maven node %s has invalid optional value", pointer)
				}
				optional = raw == "true"
			} else if err := json.Unmarshal(n.Optional, &optional); err != nil {
				return fmt.Errorf("Maven node %s has invalid optional value", pointer)
			}
		}
		key := strings.Join([]string{n.GroupID, n.ArtifactID, n.Version, n.Type, n.Classifier}, "\x00")
		ref := "maven:" + common.ID(key)
		ev := common.Evidence(file, "maven-tree", pointer, data)
		ev.Method = "resolver-output"
		if index, found := byKey[key]; found {
			doc.Components[index].Evidence = append(doc.Components[index].Evidence, ev)
		} else {
			byKey[key] = len(doc.Components)
			doc.Components = append(doc.Components, model.Component{ID: ref, Kind: "package", Name: n.GroupID + ":" + n.ArtifactID, Version: n.Version, Evidence: []model.Evidence{ev}})
			contexts[key] = map[string]bool{}
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "missing_source", Name: n.GroupID + ":" + n.ArtifactID})
		}
		if n.Scope != "" {
			contexts[key][n.Scope] = true
		}
		condition := ""
		if n.Scope != "" && n.Scope != "compile" && n.Scope != "runtime" {
			condition = "scope=" + n.Scope
		}
		if optional {
			if condition != "" {
				condition += " && "
			}
			condition += "optional=true"
		}
		if inheritedCondition != "" {
			if condition != "" {
				condition = inheritedCondition + " && " + condition
			} else {
				condition = inheritedCondition
			}
		}
		if condition != "" {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "conditional_graph", Name: n.ArtifactID})
		}
		edgeKey := parent + "\x00" + ref + "\x00" + condition
		if !seenEdges[edgeKey] {
			kind := "depends_on"
			if parent == "root" {
				kind = "direct"
			}
			doc.Edges = append(doc.Edges, model.Edge{From: parent, To: ref, Kind: kind, Condition: condition, Evidence: ev})
			seenEdges[edgeKey] = true
		}
		if stopAt != nil && stopAt(n) {
			return nil
		}
		for i, child := range n.Children {
			if err := walk(child, ref, fmt.Sprintf("%s/children/%d", pointer, i), condition, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	for i, child := range root.Children {
		if err := walk(child, "root", fmt.Sprintf("/children/%d", i), "", 1); err != nil {
			return model.Document{}, err
		}
	}
	for key, index := range byKey {
		scopes := []string{}
		for scope := range contexts[key] {
			scopes = append(scopes, scope)
		}
		sort.Strings(scopes)
		if len(scopes) > 0 {
			doc.Components[index].Context = "scopes=" + strings.Join(scopes, ",")
		}
	}
	common.Finalize(&doc)
	return doc, nil
}
