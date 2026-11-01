package maven

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Pirikara/Ravel/internal/collectors/common"
	"github.com/Pirikara/Ravel/internal/model"
)

const (
	maxMavenModules     = 128
	maxMavenModuleDepth = 16
)

// CollectPOM includes dependencies declared by the root POM and by modules
// named in its active <modules> lists. It does not resolve effective POMs or
// infer transitive dependencies.
func CollectPOM(file, project string) (model.Document, error) {
	doc, err := collectSinglePOM(file, project)
	if err != nil {
		return model.Document{}, err
	}
	rootPOM, rootData, err := readPOM(file)
	if err != nil {
		return model.Document{}, err
	}
	rootFile, err := filepath.Abs(file)
	if err != nil {
		return model.Document{}, err
	}
	rootDir := filepath.Dir(rootFile)
	visited := map[string]bool{rootFile: true}
	byID := map[string]int{}
	for i, component := range doc.Components {
		byID[component.ID] = i
	}
	moduleCount := 0
	unresolved := false
	moduleByPackageRef := map[string]string{}
	moduleNames := map[string]bool{}
	var walk func(pomDocument, []byte, string, string, int)
	walk = func(parent pomDocument, parentData []byte, parentFile, parentRef string, depth int) {
		for index, rawModule := range parent.Modules {
			module := strings.TrimSpace(rawModule)
			if module == "" || strings.ContainsAny(module, "\\\x00\r\n") || !filepath.IsLocal(filepath.FromSlash(module)) || moduleCount >= maxMavenModules || depth >= maxMavenModuleDepth {
				unresolved = true
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "maven_module_unresolved", Name: parentFile})
				continue
			}
			childFile := filepath.Join(filepath.Dir(parentFile), filepath.FromSlash(module), "pom.xml")
			childFile, err := filepath.Abs(childFile)
			if err != nil || !localMavenModule(rootDir, childFile) || visited[childFile] {
				unresolved = true
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "maven_module_unresolved", Name: module})
				continue
			}
			childPOM, childData, err := readPOM(childFile)
			if err != nil {
				unresolved = true
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "maven_module_unresolved", Name: module})
				continue
			}
			childDoc, err := collectSinglePOM(childFile, project)
			if err != nil {
				unresolved = true
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "maven_module_unresolved", Name: module})
				continue
			}
			visited[childFile] = true
			moduleCount++
			relFile, _ := filepath.Rel(rootDir, childFile)
			relDir := filepath.ToSlash(filepath.Dir(relFile))
			ref := "maven-module:" + common.ID(relFile)
			group, version := strings.TrimSpace(childPOM.GroupID), strings.TrimSpace(childPOM.Version)
			if group == "" {
				group = strings.TrimSpace(childPOM.Parent.GroupID)
			}
			if version == "" {
				version = strings.TrimSpace(childPOM.Parent.Version)
			}
			artifact := strings.TrimSpace(childPOM.ArtifactID)
			name := relDir
			if group != "" && artifact != "" && !strings.ContainsAny(group+artifact, "$<> ") {
				name = group + ":" + artifact
				moduleNames[name] = true
				if mavenExactVersion(version) {
					types := []string{strings.TrimSpace(childPOM.Packaging)}
					if types[0] == "" || types[0] == "jar" {
						types = []string{"", "jar"}
					}
					for _, typ := range types {
						key := strings.Join([]string{group, artifact, version, typ, ""}, "\x00")
						moduleByPackageRef["maven:"+common.ID(key)] = ref
					}
				}
			} else {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "maven_module_unresolved", Name: relDir})
			}
			if !mavenExactVersion(version) {
				version = ""
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "maven_module_unresolved", Name: relDir})
			}
			moduleEvidence := common.Evidence(childFile, "maven-pom", "/", childData)
			moduleEvidence.Method = "manifest-declaration"
			doc.Components = append(doc.Components, model.Component{ID: ref, Kind: "application", Name: name, Version: version, Context: "module=" + relDir, Evidence: []model.Evidence{moduleEvidence}})
			byID[ref] = len(doc.Components) - 1
			parentEvidence := common.Evidence(parentFile, "maven-pom", fmt.Sprintf("/modules/%d", index), parentData)
			parentEvidence.Method = "manifest-declaration"
			doc.Edges = append(doc.Edges, model.Edge{From: parentRef, To: ref, Kind: "module", Evidence: parentEvidence})
			doc.Origins = append(doc.Origins, model.Origin{Occurrence: ref, Kind: "local", LocalPath: relDir, Status: "declared", Evidence: moduleEvidence})
			doc.Sources = append(doc.Sources, childFile)
			for _, component := range childDoc.Components {
				if existing, found := byID[component.ID]; found {
					doc.Components[existing].Evidence = append(doc.Components[existing].Evidence, component.Evidence...)
				} else {
					byID[component.ID] = len(doc.Components)
					doc.Components = append(doc.Components, component)
				}
			}
			for _, edge := range childDoc.Edges {
				if edge.From == "root" {
					edge.From = ref
				}
				doc.Edges = append(doc.Edges, edge)
			}
			doc.Coverage.Issues = append(doc.Coverage.Issues, childDoc.Coverage.Issues...)
			walk(childPOM, childData, childFile, ref, depth+1)
		}
	}
	walk(rootPOM, rootData, rootFile, "root", 0)
	if len(moduleByPackageRef) != 0 {
		for i := range doc.Edges {
			if moduleRef := moduleByPackageRef[doc.Edges[i].To]; moduleRef != "" {
				doc.Edges[i].To = moduleRef
			}
		}
		components := doc.Components[:0]
		for _, component := range doc.Components {
			if moduleByPackageRef[component.ID] == "" {
				components = append(components, component)
			}
		}
		doc.Components = components
		externalNames := map[string]bool{}
		for _, component := range doc.Components {
			if component.Kind == "package" {
				externalNames[component.Name] = true
			}
		}
		issues := doc.Coverage.Issues[:0]
		for _, issue := range doc.Coverage.Issues {
			if issue.Code != "missing_source" || !moduleNames[issue.Name] || externalNames[issue.Name] {
				issues = append(issues, issue)
			}
		}
		doc.Coverage.Issues = issues
	}
	if !unresolved {
		issues := doc.Coverage.Issues[:0]
		for _, issue := range doc.Coverage.Issues {
			if issue.Code != "multi_module_scope_root" {
				issues = append(issues, issue)
			}
		}
		doc.Coverage.Issues = issues
	}
	doc.Coverage.GraphState = "complete_for_scope"
	doc.Coverage.OriginState = "complete_for_scope"
	common.Finalize(&doc)
	return doc, nil
}

func localMavenModule(rootDir, file string) bool {
	rel, err := filepath.Rel(rootDir, file)
	if err != nil || !filepath.IsLocal(rel) {
		return false
	}
	current := rootDir
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return false
		}
	}
	return true
}
