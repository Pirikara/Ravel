package oci

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path"
	"regexp"
	"strings"

	"github.com/Pirikara/Ravel/internal/collectors/common"
	"github.com/Pirikara/Ravel/internal/model"
)

const (
	maxPipVendorBytes = 64 << 10
	maxPipVendorFiles = 100
	maxPipVendorItems = 200
)

var pipVendorName = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$`)
var pipVendorSeparator = regexp.MustCompile(`[-_.]+`)

func isPipVendorPath(name string) bool {
	if path.Clean(name) != name || strings.HasPrefix(name, "/") {
		return false
	}
	parts := strings.Split(name, "/")
	if len(parts) < 4 {
		return false
	}
	for _, part := range parts {
		if part == ".." {
			return false
		}
	}
	n := len(parts)
	return (parts[n-4] == "site-packages" || parts[n-4] == "dist-packages") && parts[n-3] == "pip" && parts[n-2] == "_vendor" && parts[n-1] == "vendor.txt"
}

// collectPipVendor records the versions explicitly listed by pip's installed
// vendor manifest. The manifest does not establish a package index, artifact
// digest, or the dependency graph among the vendored distributions.
func collectPipVendor(data []byte, source, project, filename, pipID string) (model.Document, error) {
	if len(data) == 0 || len(data) > maxPipVendorBytes || !isPipVendorPath(filename) {
		return model.Document{}, errors.New("invalid pip vendor manifest path or size")
	}
	digest := sha256.Sum256(data)
	evidence := model.Evidence{Collector: "pip-vendor", InputPath: source, InputDigest: "sha256:" + hex.EncodeToString(digest[:]), Method: "installed-vendor-manifest"}
	doc := common.NewDocument(source, project, "pip-vendor", data)
	vendorDir := path.Dir(filename)
	seen := map[string]bool{}
	for lineNumber, line := range strings.Split(string(data), "\n") {
		entry := strings.TrimSpace(line)
		if entry == "" || strings.HasPrefix(entry, "#") {
			continue
		}
		name, version, found := strings.Cut(entry, "==")
		if !found || !pipVendorName.MatchString(name) || version == "" || len(version) > 128 || strings.ContainsAny(version, " \t\x00/\\\r\n") || strings.Contains(version, "==") {
			return model.Document{}, errors.New("invalid pip vendor package entry")
		}
		canonical := pipVendorSeparator.ReplaceAllString(strings.ToLower(name), "-")
		if seen[canonical] {
			return model.Document{}, errors.New("duplicate pip vendor package entry")
		}
		seen[canonical] = true
		if len(seen) > maxPipVendorItems {
			return model.Document{}, errors.New("pip vendor manifest has too many packages")
		}
		id := "python-vendor:" + common.ID(source+"\x00"+canonical+"\x00"+version)
		itemEvidence := evidence
		itemEvidence.Line = lineNumber + 1
		doc.Components = append(doc.Components, model.Component{ID: id, Kind: "package", Name: name, Version: version, Context: "location=/" + vendorDir + ";vendor=pip", Evidence: []model.Evidence{itemEvidence}})
		from, kind := pipID, "embedded"
		if from == "" {
			from, kind = "root", "installed"
		}
		doc.Edges = append(doc.Edges, model.Edge{From: from, To: id, Kind: kind, Evidence: itemEvidence})
	}
	if len(doc.Components) == 0 {
		return model.Document{}, errors.New("empty pip vendor manifest")
	}
	doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "pip_vendor_graph_unavailable", Name: filename}, model.Issue{Code: "pip_vendor_origin_unavailable", Name: filename})
	if pipID == "" {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "pip_vendor_parent_unresolved", Name: filename})
	}
	common.Finalize(&doc)
	return doc, nil
}
