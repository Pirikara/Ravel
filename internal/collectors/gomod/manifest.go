package gomod

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"

	"github.com/Pirikara/Ravel/internal/collectors/common"
	"github.com/Pirikara/Ravel/internal/model"
)

// CollectManifest inventories the modules declared in go.mod without running Go.
// The manifest does not establish the selected build list or transitive graph.
func CollectManifest(file, project string) (model.Document, error) {
	if filepath.Base(file) != "go.mod" {
		return model.Document{}, fmt.Errorf("Go manifest input must be go.mod")
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return model.Document{}, err
	}
	manifest, err := modfile.Parse(file, data, nil)
	if err != nil {
		return model.Document{}, fmt.Errorf("invalid go.mod: %w", err)
	}
	doc := common.NewDocument(file, project, "go", data)
	if len(manifest.Require) > 0 {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "transitive_graph_unavailable"})
	}
	if work := filepath.Join(filepath.Dir(file), "go.work"); fileExists(work) {
		doc.Sources = append(doc.Sources, work)
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "workspace_unresolved"})
	}
	seen := map[string]bool{}
	for _, req := range manifest.Require {
		path, version := req.Mod.Path, req.Mod.Version
		if module.CheckPath(path) != nil || !semver.IsValid(version) {
			return model.Document{}, fmt.Errorf("invalid Go module requirement")
		}
		if seen[path] {
			return model.Document{}, fmt.Errorf("duplicate Go module requirement: %s", path)
		}
		seen[path] = true
		item := listedModule{Path: path, Version: version}
		if replacement := manifestReplacement(manifest, path, version); replacement != nil {
			item.Replace = &listedModule{Path: replacement.New.Path, Version: replacement.New.Version}
		}
		ref := "go:" + common.ID(path+"|"+version+"|"+replacementKey(item.Replace))
		ev := common.Evidence(file, "go-manifest", "/require/"+common.ID(path), data)
		ev.Method = "manifest-analysis"
		identity := ""
		if item.Replace == nil {
			identity = common.GoModulePURL(path, version)
		}
		doc.Components = append(doc.Components, model.Component{ID: ref, Kind: "package", Name: path, Version: version, PURL: identity, Evidence: []model.Evidence{ev}})
		addResolvedOrigin(&doc, ref, item, ev)
		if !req.Indirect {
			doc.Edges = append(doc.Edges, model.Edge{From: "root", To: ref, Kind: "direct", Evidence: ev})
		}
	}
	common.Finalize(&doc)
	return doc, nil
}

func manifestReplacement(manifest *modfile.File, path, version string) *modfile.Replace {
	var selected *modfile.Replace
	for _, replacement := range manifest.Replace {
		if replacement.Old.Path != path {
			continue
		}
		if replacement.Old.Version == version {
			return replacement
		}
		if replacement.Old.Version == "" {
			selected = replacement
		}
	}
	return selected
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
