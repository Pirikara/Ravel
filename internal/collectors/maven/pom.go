package maven

import (
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"strings"

	"ravel/internal/collectors/common"
	"ravel/internal/model"
)

type pomDependency struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
	Type       string `xml:"type"`
	Classifier string `xml:"classifier"`
	Scope      string `xml:"scope"`
	Optional   string `xml:"optional"`
}

type pomDocument struct {
	XMLName      xml.Name        `xml:"project"`
	GroupID      string          `xml:"groupId"`
	ArtifactID   string          `xml:"artifactId"`
	Version      string          `xml:"version"`
	Packaging    string          `xml:"packaging"`
	Dependencies []pomDependency `xml:"dependencies>dependency"`
	Modules      []string        `xml:"modules>module"`
	Properties   pomProperties   `xml:"properties"`
	Parent       struct {
		GroupID string `xml:"groupId"`
		Version string `xml:"version"`
	} `xml:"parent"`
	Profiles []struct {
		ID string `xml:"id"`
	} `xml:"profiles>profile"`
}

type pomProperties map[string]string

func (p *pomProperties) UnmarshalXML(decoder *xml.Decoder, start xml.StartElement) error {
	values := pomProperties{}
	for {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		switch element := token.(type) {
		case xml.StartElement:
			var value string
			if err := decoder.DecodeElement(&value, &element); err != nil {
				return err
			}
			values[element.Name.Local] = strings.TrimSpace(value)
		case xml.EndElement:
			if element.Name == start.Name {
				*p = values
				return nil
			}
		}
	}
}

// collectSinglePOM records exact, directly declared coordinates. Maven's
// selected transitive graph requires the opt-in resolver and is not inferred.
func collectSinglePOM(file, project string) (model.Document, error) {
	pom, data, err := readPOM(file)
	if err != nil {
		return model.Document{}, err
	}
	doc := common.NewDocument(file, project, "maven", data)
	doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "transitive_graph_unavailable"})
	if len(pom.Modules) > 0 {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "multi_module_scope_root", Name: file})
	}
	if pom.Parent.GroupID != "" {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "maven_inherited_dependencies_unavailable"})
	}
	if len(pom.Profiles) > 0 {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "maven_profiles_unresolved"})
	}
	properties := pom.Properties
	if properties == nil {
		properties = pomProperties{}
	}
	if version := strings.TrimSpace(pom.Version); version != "" {
		properties["project.version"] = version
		properties["pom.version"] = version
	} else if version := strings.TrimSpace(pom.Parent.Version); version != "" {
		properties["project.version"] = version
		properties["pom.version"] = version
	}
	if group := strings.TrimSpace(pom.GroupID); group != "" {
		properties["project.groupId"] = group
		properties["pom.groupId"] = group
	} else if group := strings.TrimSpace(pom.Parent.GroupID); group != "" {
		properties["project.groupId"] = group
		properties["pom.groupId"] = group
	}
	coordinateCounts := map[string]int{}
	for _, dep := range pom.Dependencies {
		if strings.TrimSpace(dep.Scope) == "import" {
			continue
		}
		group, groupOK := expandPOMValue(strings.TrimSpace(dep.GroupID), properties)
		artifact, artifactOK := expandPOMValue(strings.TrimSpace(dep.ArtifactID), properties)
		if groupOK && artifactOK && group != "" && artifact != "" {
			coordinate := strings.Join([]string{group, artifact, strings.TrimSpace(dep.Type), strings.TrimSpace(dep.Classifier)}, "\x00")
			coordinateCounts[coordinate]++
		}
	}
	reportedDuplicates := map[string]bool{}
	for i, dep := range pom.Dependencies {
		group, groupOK := expandPOMValue(strings.TrimSpace(dep.GroupID), properties)
		artifact, artifactOK := expandPOMValue(strings.TrimSpace(dep.ArtifactID), properties)
		version, versionOK := expandPOMValue(strings.TrimSpace(dep.Version), properties)
		name := group + ":" + artifact
		if strings.TrimSpace(dep.Scope) == "import" {
			continue // imported BOM controls versions; it is not a runtime dependency
		}
		if !groupOK || !artifactOK || !versionOK || group == "" || artifact == "" || !mavenExactVersion(version) || strings.ContainsAny(group+artifact, "$<> ") {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unresolved_dependency", Name: name})
			continue
		}
		typ := strings.TrimSpace(dep.Type)
		classifier := strings.TrimSpace(dep.Classifier)
		if strings.ContainsAny(typ+classifier, "$<> ") {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unresolved_dependency", Name: name})
			continue
		}
		coordinate := strings.Join([]string{group, artifact, typ, classifier}, "\x00")
		if coordinateCounts[coordinate] > 1 {
			if !reportedDuplicates[coordinate] {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "duplicate_spec", Name: name})
				reportedDuplicates[coordinate] = true
			}
			continue
		}
		key := strings.Join([]string{group, artifact, version, typ, classifier}, "\x00")
		ref := "maven:" + common.ID(key)
		ev := common.Evidence(file, "maven-pom", fmt.Sprintf("/dependencies/%d", i), data)
		ev.Method = "manifest-declaration"
		condition := ""
		scope := strings.TrimSpace(dep.Scope)
		if scope != "" && scope != "compile" && scope != "runtime" {
			condition = "scope=" + scope
		}
		optional := strings.TrimSpace(dep.Optional)
		if optional != "" && optional != "true" && optional != "false" {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unresolved_dependency", Name: name})
			continue
		}
		if optional == "true" {
			if condition != "" {
				condition += " && "
			}
			condition += "optional=true"
		}
		if condition != "" {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "conditional_graph", Name: name})
		}
		doc.Components = append(doc.Components, model.Component{ID: ref, Kind: "package", Name: name, Version: version, Evidence: []model.Evidence{ev}})
		doc.Edges = append(doc.Edges, model.Edge{From: "root", To: ref, Kind: "direct", Condition: condition, Evidence: ev})
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "missing_source", Name: name})
	}
	common.Finalize(&doc)
	return doc, nil
}

func readPOM(file string) (pomDocument, []byte, error) {
	f, err := os.Open(file)
	if err != nil {
		return pomDocument{}, nil, err
	}
	defer f.Close()
	const maxPOM = 4 << 20
	data, err := io.ReadAll(io.LimitReader(f, maxPOM+1))
	if err != nil {
		return pomDocument{}, nil, err
	}
	if len(data) > maxPOM {
		return pomDocument{}, nil, fmt.Errorf("pom.xml exceeded size limit")
	}
	var pom pomDocument
	if err := xml.Unmarshal(data, &pom); err != nil {
		return pomDocument{}, nil, fmt.Errorf("invalid pom.xml: %w", err)
	}
	if pom.XMLName.Local != "project" {
		return pomDocument{}, nil, fmt.Errorf("invalid pom.xml: expected project root")
	}
	return pom, data, nil
}

func mavenExactVersion(version string) bool {
	if version == "" || strings.ContainsAny(version, "${}[](),+* ") {
		return false
	}
	return version != "LATEST" && version != "RELEASE"
}

func expandPOMValue(value string, properties pomProperties) (string, bool) {
	const maxValue = 4096
	if len(value) > maxValue {
		return value, false
	}
	for range 16 {
		start := strings.Index(value, "${")
		if start < 0 {
			return value, true
		}
		end := strings.IndexByte(value[start+2:], '}')
		if end < 0 {
			return value, false
		}
		end += start + 2
		replacement, found := properties[value[start+2:end]]
		if !found || replacement == "" || len(value)-(end+1-start)+len(replacement) > maxValue {
			return value, false
		}
		value = value[:start] + replacement + value[end+1:]
	}
	return value, false
}
