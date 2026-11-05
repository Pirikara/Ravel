package composer

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	packageurl "github.com/package-url/packageurl-go"

	"github.com/Pirikara/Ravel/internal/collectors/common"
	"github.com/Pirikara/Ravel/internal/model"
	"github.com/Pirikara/Ravel/internal/safeurl"
)

type lockfile struct {
	Packages    []lockedPackage `json:"packages"`
	PackagesDev []lockedPackage `json:"packages-dev"`
	ContentHash string          `json:"content-hash"`
}

type lockedPackage struct {
	Name    string                                        `json:"name"`
	Version string                                        `json:"version"`
	Require map[string]string                             `json:"require"`
	Source  struct{ Type, URL, Reference string }         `json:"source"`
	Dist    struct{ Type, URL, Reference, Shasum string } `json:"dist"`
}

type manifest struct {
	Require    map[string]string `json:"require"`
	RequireDev map[string]string `json:"require-dev"`
}

type node struct {
	ref string
	pkg lockedPackage
	dev bool
}

var commit = regexp.MustCompile(`^[0-9a-fA-F]{7,64}$`)

func Collect(file, project string) (model.Document, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return model.Document{}, err
	}
	var lock lockfile
	if err := json.Unmarshal(data, &lock); err != nil {
		return model.Document{}, fmt.Errorf("invalid composer.lock: %w", err)
	}
	if lock.Packages == nil && lock.PackagesDev == nil {
		return model.Document{}, fmt.Errorf("composer.lock has no package arrays")
	}
	doc := common.NewDocument(file, project, "composer", data)
	nodes := []node{}
	byName := map[string][]node{}
	for group, packages := range [][]lockedPackage{lock.Packages, lock.PackagesDev} {
		for i, pkg := range packages {
			parts := strings.Split(pkg.Name, "/")
			if len(parts) != 2 || parts[0] == "" || parts[1] == "" || pkg.Version == "" {
				return model.Document{}, fmt.Errorf("Composer package %d missing identity", i)
			}
			ref := "composer:" + common.ID(fmt.Sprintf("%d|%d|%s|%s", group, i, pkg.Name, pkg.Version))
			dev := group == 1
			n := node{ref: ref, pkg: pkg, dev: dev}
			nodes = append(nodes, n)
			byName[strings.ToLower(pkg.Name)] = append(byName[strings.ToLower(pkg.Name)], n)
			ev := common.Evidence(file, "composer-lock", fmt.Sprintf("/packages/%d/%d", group, i), data)
			component := model.Component{ID: ref, Kind: "package", Name: pkg.Name, Version: pkg.Version, Evidence: []model.Evidence{ev}}
			if pkg.Source.Type != "path" && pkg.Dist.Type != "path" {
				component.PURL = packageurl.NewPackageURL("composer", strings.ToLower(parts[0]), strings.ToLower(parts[1]), pkg.Version, nil, "").ToString()
				component.PURLBasis = "ecosystem_inferred"
			}
			doc.Components = append(doc.Components, component)
			originCount := 0
			if pkg.Source.URL != "" {
				kind := "vcs"
				if pkg.Source.Type == "path" {
					kind = "local"
				}
				if kind == "local" {
					doc.Origins = append(doc.Origins, model.Origin{Occurrence: ref, Kind: "local", Status: "declared", Evidence: ev})
					originCount++
				} else if clean := safeurl.Clean(pkg.Source.URL); clean != "" {
					revision := pkg.Source.Reference
					if !commit.MatchString(revision) {
						revision = ""
					}
					doc.Origins = append(doc.Origins, model.Origin{Occurrence: ref, Kind: "vcs", SafeURL: clean, Revision: revision, Status: "declared", Evidence: ev})
					originCount++
				} else {
					doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unsafe_or_invalid_source", Name: pkg.Name})
				}
			}
			if pkg.Dist.URL != "" {
				if pkg.Dist.Type == "path" {
					doc.Origins = append(doc.Origins, model.Origin{Occurrence: ref, Kind: "local", Status: "declared", Evidence: ev})
					originCount++
				} else if clean := safeurl.Clean(pkg.Dist.URL); clean != "" {
					doc.Origins = append(doc.Origins, model.Origin{Occurrence: ref, Kind: "download_url", SafeURL: clean, Status: "declared", Evidence: ev})
					originCount++
				} else {
					doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unsafe_or_invalid_source", Name: pkg.Name})
				}
			}
			if originCount == 0 {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "missing_source", Name: pkg.Name})
			}
			if dev {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "conditional_graph", Name: pkg.Name})
			}
		}
	}
	resolve := func(name string) node {
		candidates := byName[strings.ToLower(name)]
		if len(candidates) == 1 {
			return candidates[0]
		}
		code := "unresolved_dependency"
		if len(candidates) > 1 {
			code = "ambiguous_dependency"
		}
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: code, Name: name})
		return node{}
	}
	for _, n := range nodes {
		for name := range n.pkg.Require {
			if isPlatform(name) {
				continue
			}
			to := resolve(name)
			if to.ref == "" {
				continue
			}
			condition := ""
			if n.dev || to.dev {
				condition = "group=dev"
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "conditional_graph", Name: name})
			}
			doc.Edges = append(doc.Edges, model.Edge{From: n.ref, To: to.ref, Kind: "depends_on", Condition: condition, Evidence: common.Evidence(file, "composer-lock", "/require/"+common.ID(name), data)})
		}
	}
	manifestData, err := os.ReadFile(filepath.Join(filepath.Dir(file), "composer.json"))
	if err != nil {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "missing_direct_dependencies"})
	} else {
		doc.Sources = append(doc.Sources, filepath.Join(filepath.Dir(file), "composer.json"))
		var m manifest
		if err := json.Unmarshal(manifestData, &m); err != nil {
			return model.Document{}, fmt.Errorf("invalid composer.json: %w", err)
		}
		for group, requires := range []map[string]string{m.Require, m.RequireDev} {
			for name := range requires {
				if isPlatform(name) {
					continue
				}
				to := resolve(name)
				if to.ref == "" {
					continue
				}
				condition := ""
				if group == 1 || to.dev {
					condition = "group=dev"
					doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "conditional_graph", Name: name})
				}
				doc.Edges = append(doc.Edges, model.Edge{From: "root", To: to.ref, Kind: "direct", Condition: condition, Evidence: common.Evidence(filepath.Join(filepath.Dir(file), "composer.json"), "composer-manifest", "/require/"+common.ID(name), manifestData)})
			}
		}
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "manifest_freshness_unverified"})
	}
	common.Finalize(&doc)
	return doc, nil
}

func isPlatform(name string) bool {
	if strings.Contains(name, "/") {
		return false
	}
	return name == "php" || strings.HasPrefix(name, "php-") || strings.HasPrefix(name, "ext-") || strings.HasPrefix(name, "lib-") || name == "composer" || name == "composer-plugin-api" || name == "composer-runtime-api"
}
