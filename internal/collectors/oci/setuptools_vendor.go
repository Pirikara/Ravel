package oci

import (
	"errors"
	"path"
	"strings"

	"ravel/internal/collectors/common"
	"ravel/internal/collectors/python"
	"ravel/internal/model"
)

// setuptools keeps some distribution metadata inside its private _vendor
// directory. Those distributions are embedded code, not independently
// installed packages in the interpreter's site-packages directory.
func isSetuptoolsVendorMetadataPath(name string) bool {
	if path.Clean(name) != name || strings.HasPrefix(name, "/") {
		return false
	}
	parts := strings.Split(name, "/")
	for _, part := range parts {
		if part == ".." || part == "." || part == "" {
			return false
		}
	}
	n := len(parts)
	if n < 5 || parts[n-1] != "METADATA" || parts[n-3] != "_vendor" || parts[n-4] != "setuptools" || parts[n-5] != "site-packages" && parts[n-5] != "dist-packages" {
		return false
	}
	return python.IsInstalledMetadataPath(path.Join(strings.Join(parts[:n-4], "/"), parts[n-2], "METADATA"))
}

func collectSetuptoolsVendor(data []byte, source, project, filename, setuptoolsID string) (model.Document, error) {
	if !isSetuptoolsVendorMetadataPath(filename) {
		return model.Document{}, errors.New("invalid setuptools vendor metadata path")
	}
	vendorDir := path.Dir(path.Dir(filename))
	siteDir := path.Dir(path.Dir(vendorDir))
	synthetic := path.Join(siteDir, path.Base(path.Dir(filename)), "METADATA")
	installed, err := python.CollectInstalledMetadata(data, source, project, synthetic)
	if err != nil {
		return model.Document{}, err
	}
	component := installed.Components[0]
	component.ID = "python-vendor:" + common.ID(filename+"\x00"+component.Name+"\x00"+component.Version)
	component.Context = "location=/" + vendorDir + ";vendor=setuptools"
	component.Evidence[0].Collector = "python-vendor-dist-info"
	component.Evidence[0].Method = "vendored-metadata"
	doc := common.NewDocument(source, project, "setuptools-vendor", nil)
	doc.Components = append(doc.Components, component)
	from, kind := setuptoolsID, "embedded"
	if from == "" {
		from, kind = "root", "installed"
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "setuptools_vendor_parent_unresolved", Name: filename})
	}
	doc.Edges = append(doc.Edges, model.Edge{From: from, To: component.ID, Kind: kind, Evidence: component.Evidence[0]})
	doc.Coverage.Issues = append(doc.Coverage.Issues,
		model.Issue{Code: "setuptools_vendor_graph_unavailable", Name: filename},
		model.Issue{Code: "setuptools_vendor_origin_unavailable", Name: filename},
	)
	common.Finalize(&doc)
	return doc, nil
}
