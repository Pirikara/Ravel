package gomod

import (
	"fmt"

	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"

	"github.com/Pirikara/Ravel/internal/collectors/common"
	"github.com/Pirikara/Ravel/internal/model"
)

// addMainModule records the module named by go.mod as a project component.
// A source checkout has no module version unless one is supplied separately.
func addMainModule(doc *model.Document, manifest *modfile.File, file string, data []byte) (string, error) {
	if manifest.Module == nil || module.CheckImportPath(manifest.Module.Mod.Path) != nil {
		return "", fmt.Errorf("go.mod has no valid module directive")
	}
	path := manifest.Module.Mod.Path
	ref := "go-main:" + common.ID(path)
	evidence := common.Evidence(file, "go-manifest", "/module", data)
	evidence.Method = "manifest-analysis"
	doc.Components = append(doc.Components, model.Component{
		ID: ref, Kind: "application", Name: path,
		PURL: common.GoMainModulePURL(path), Evidence: []model.Evidence{evidence},
	})
	doc.Edges = append(doc.Edges, model.Edge{From: "root", To: ref, Kind: "project", Evidence: evidence})
	return ref, nil
}
