package pub

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	packageurl "github.com/package-url/packageurl-go"
	"gopkg.in/yaml.v3"

	"ravel/internal/collectors/common"
	"ravel/internal/model"
	"ravel/internal/safeurl"
)

type lockfile struct {
	Packages map[string]lockedPackage `yaml:"packages"`
}

type lockedPackage struct {
	Dependency  string    `yaml:"dependency"`
	Description yaml.Node `yaml:"description"`
	Source      string    `yaml:"source"`
	Version     string    `yaml:"version"`
}

type description struct {
	Name        string `yaml:"name"`
	URL         string `yaml:"url"`
	SHA256      string `yaml:"sha256"`
	Path        string `yaml:"path"`
	Ref         string `yaml:"ref"`
	ResolvedRef string `yaml:"resolved-ref"`
	Relative    bool   `yaml:"relative"`
}

var packageName = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
var gitRevision = regexp.MustCompile(`^[0-9a-fA-F]{7,64}$`)

func Collect(file, project string) (model.Document, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return model.Document{}, err
	}
	var lock lockfile
	if err := yaml.Unmarshal(data, &lock); err != nil {
		return model.Document{}, fmt.Errorf("invalid pubspec.lock: %w", err)
	}
	if lock.Packages == nil {
		return model.Document{}, fmt.Errorf("pubspec.lock has no packages map")
	}
	doc := common.NewDocument(file, project, "pub", data)
	doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "transitive_graph_unavailable"}, model.Issue{Code: "manifest_freshness_unverified"})
	for name, pkg := range lock.Packages {
		if !packageName.MatchString(name) || pkg.Version == "" {
			return model.Document{}, fmt.Errorf("Pub package %q has invalid identity", name)
		}
		if pkg.Dependency != "transitive" && pkg.Dependency != "direct main" && pkg.Dependency != "direct dev" && pkg.Dependency != "direct overridden" {
			return model.Document{}, fmt.Errorf("Pub package %q has unsupported dependency class %q", name, pkg.Dependency)
		}
		if pkg.Source != "hosted" && pkg.Source != "git" && pkg.Source != "path" && pkg.Source != "sdk" {
			return model.Document{}, fmt.Errorf("Pub package %q has unsupported source %q", name, pkg.Source)
		}
		var desc description
		if pkg.Description.Kind == yaml.MappingNode {
			if err := pkg.Description.Decode(&desc); err != nil {
				return model.Document{}, fmt.Errorf("Pub package %q has invalid description: %w", name, err)
			}
		} else if pkg.Description.Kind == yaml.ScalarNode {
			if pkg.Source == "sdk" {
				desc.Name = pkg.Description.Value
			} else if pkg.Source == "hosted" {
				desc.Name = pkg.Description.Value
			}
		} else {
			return model.Document{}, fmt.Errorf("Pub package %q has invalid description", name)
		}
		if pkg.Source == "hosted" && desc.Name != "" && desc.Name != name {
			return model.Document{}, fmt.Errorf("Pub package %q has conflicting hosted name %q", name, desc.Name)
		}
		ref := "pub:" + common.ID(name+"|"+pkg.Version+"|"+pkg.Source)
		ev := common.Evidence(file, "pub-lock", "/packages/"+name, data)
		purl := packageurl.NewPackageURL("pub", "", name, pkg.Version, nil, "")
		component := model.Component{ID: ref, Kind: "package", Name: name, Version: pkg.Version, PURL: purl.ToString(), Evidence: []model.Evidence{ev}}
		if pkg.Source == "hosted" {
			clean := safeurl.Clean(desc.URL)
			if clean == "" {
				component.PURL = ""
			} else if repository := strings.TrimSuffix(clean, "/"); repository != "https://pub.dev" && repository != "https://pub.dartlang.org" {
				purl.Qualifiers = packageurl.QualifiersFromMap(map[string]string{"repository_url": clean})
				component.PURL = purl.ToString()
			}
			component.Hashes = common.HexSHA256(desc.SHA256)
			if desc.SHA256 != "" && len(component.Hashes) == 0 {
				return model.Document{}, fmt.Errorf("Pub package %q has invalid SHA256", name)
			}
		}
		doc.Components = append(doc.Components, component)
		switch pkg.Source {
		case "hosted":
			if desc.URL == "" {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "missing_source", Name: name})
			} else if clean := safeurl.Clean(desc.URL); clean != "" {
				doc.Origins = append(doc.Origins, model.Origin{Occurrence: ref, Kind: "declared_registry", SafeURL: clean, Status: "declared", Evidence: ev})
			} else {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unsafe_or_invalid_source", Name: name})
			}
		case "git":
			if clean := safeurl.Clean(desc.URL); clean != "" {
				revision := desc.ResolvedRef
				if !gitRevision.MatchString(revision) {
					revision = ""
					doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "source_unresolved", Name: name})
				}
				doc.Origins = append(doc.Origins, model.Origin{Occurrence: ref, Kind: "vcs", SafeURL: clean, Revision: revision, Status: "declared", Evidence: ev})
			} else {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unsafe_or_invalid_source", Name: name})
			}
		case "path":
			if desc.Path == "" {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "missing_source", Name: name})
			} else {
				doc.Origins = append(doc.Origins, model.Origin{Occurrence: ref, Kind: "local", LocalPath: desc.Path, Status: "declared", Evidence: ev})
			}
		case "sdk":
			if strings.TrimSpace(desc.Name) == "" {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "missing_source", Name: name})
			} else {
				doc.Origins = append(doc.Origins, model.Origin{Occurrence: ref, Kind: "sdk", Target: desc.Name, Status: "declared", Evidence: ev})
			}
		}
		if pkg.Dependency != "transitive" {
			condition := ""
			if pkg.Dependency == "direct dev" {
				condition = "group=dev"
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "conditional_graph", Name: name})
			}
			doc.Edges = append(doc.Edges, model.Edge{From: "root", To: ref, Kind: "direct", Condition: condition, Evidence: ev})
		}
	}
	common.Finalize(&doc)
	return doc, nil
}
