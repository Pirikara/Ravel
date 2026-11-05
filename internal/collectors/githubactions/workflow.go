package githubactions

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	packageurl "github.com/package-url/packageurl-go"
	"gopkg.in/yaml.v3"

	"github.com/Pirikara/Ravel/internal/collectors/common"
	"github.com/Pirikara/Ravel/internal/model"
)

var actionReference = regexp.MustCompile(`^([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)((?:/[A-Za-z0-9_.-]+)*)@([A-Za-z0-9_.-]+)$`)

// Collect reads declared GitHub Action uses from a workflow without executing it.
func Collect(file, project string) (model.Document, error) {
	info, err := os.Stat(file)
	if err != nil {
		return model.Document{}, err
	}
	if !info.Mode().IsRegular() || info.Size() > 2<<20 {
		return model.Document{}, fmt.Errorf("invalid or oversized workflow")
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return model.Document{}, err
	}
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return model.Document{}, fmt.Errorf("invalid workflow YAML: %w", err)
	}
	doc := common.NewDocument(file, project, "github-actions", data)
	if len(root.Content) != 1 || root.Content[0].Kind != yaml.MappingNode {
		return model.Document{}, fmt.Errorf("workflow root is not a mapping")
	}
	jobs := mappingValue(root.Content[0], "jobs")
	if jobs == nil || jobs.Kind != yaml.MappingNode {
		return doc, nil
	}
	seen := map[string]int{}
	add := func(node *yaml.Node, pointer string) {
		if node == nil || node.Kind != yaml.ScalarNode {
			return
		}
		raw := strings.TrimSpace(node.Value)
		match := actionReference.FindStringSubmatch(raw)
		if len(match) != 5 || match[1] == "." || match[1] == ".." || match[2] == "." || match[2] == ".." || match[4] == "." || match[4] == ".." || invalidActionSubpath(match[3]) {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unresolved_dependency", Name: "workflow uses", Line: node.Line})
			doc.Coverage.OriginState = "partial"
			return
		}
		name := match[1] + "/" + match[2] + match[3]
		ref := match[4]
		key := name + "@" + ref
		evidence := common.Evidence(file, "github-actions-workflow", pointer, data)
		evidence.Line = node.Line
		evidence.Method = "workflow-analysis"
		if index, exists := seen[key]; exists {
			doc.Components[index].Evidence = append(doc.Components[index].Evidence, evidence)
			return
		}
		id := "github-action:" + common.ID(file+"\x00"+key)
		purl := packageurl.NewPackageURL("github", match[1], match[2], ref, nil, strings.TrimPrefix(match[3], "/")).ToString()
		seen[key] = len(doc.Components)
		doc.Components = append(doc.Components, model.Component{ID: id, Kind: "package", Name: name, Version: ref, PURL: purl, Evidence: []model.Evidence{evidence}})
		doc.Edges = append(doc.Edges, model.Edge{From: "root", To: id, Kind: "direct", Evidence: evidence})
		doc.Origins = append(doc.Origins, model.Origin{Occurrence: id, Kind: "vcs", SafeURL: "https://github.com/" + match[1] + "/" + match[2], Status: "declared", Evidence: evidence})
	}
	for i := 0; i+1 < len(jobs.Content); i += 2 {
		jobName, job := jobs.Content[i].Value, jobs.Content[i+1]
		if job.Kind != yaml.MappingNode {
			continue
		}
		if uses := mappingValue(job, "uses"); uses != nil {
			add(uses, "/jobs/"+jobName+"/uses")
		}
		steps := mappingValue(job, "steps")
		if steps == nil || steps.Kind != yaml.SequenceNode {
			continue
		}
		for index, step := range steps.Content {
			if step.Kind != yaml.MappingNode {
				continue
			}
			if uses := mappingValue(step, "uses"); uses != nil {
				add(uses, fmt.Sprintf("/jobs/%s/steps/%d/uses", jobName, index))
			}
		}
	}
	common.Finalize(&doc)
	return doc, nil
}

func invalidActionSubpath(subpath string) bool {
	for _, part := range strings.Split(strings.TrimPrefix(subpath, "/"), "/") {
		if part == "." || part == ".." {
			return true
		}
	}
	return false
}

func mappingValue(node *yaml.Node, key string) *yaml.Node {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			return node.Content[i+1]
		}
	}
	return nil
}
