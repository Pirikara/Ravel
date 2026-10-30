package python

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path"
	"regexp"
	"strings"

	"ravel/internal/collectors/common"
	"ravel/internal/model"
)

const MaxInstalledMetadataBytes = 2 << 20

var installedDistributionName = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$`)

// CollectInstalledMetadata records one installed Python distribution from
// its dist-info/METADATA file. The file establishes its installed identity,
// but not the index or artifact from which it was obtained.
func CollectInstalledMetadata(data []byte, source, project, metadataPath string) (model.Document, error) {
	if len(data) > MaxInstalledMetadataBytes || !IsInstalledMetadataPath(metadataPath) {
		return model.Document{}, errors.New("invalid installed Python metadata path or size")
	}
	headers, ok := parseWheelHeaders(data)
	name := singleWheelHeader(headers, "name")
	version := singleWheelHeader(headers, "version")
	metadataVersion := singleWheelHeader(headers, "metadata-version")
	if !ok || !installedDistributionName.MatchString(name) || version == "" || metadataVersion == "" || strings.ContainsAny(version, " \t\x00/\\\r\n") {
		return model.Document{}, errors.New("invalid installed Python core metadata")
	}
	folder := path.Base(path.Dir(metadataPath))
	stem := strings.TrimSuffix(folder, ".dist-info")
	separator := strings.LastIndexByte(stem, '-')
	if separator <= 0 || separator == len(stem)-1 || wheelNameToken(stem[:separator]) != wheelNameToken(name) || wheelVersionToken(stem[separator+1:]) != wheelVersionToken(version) {
		return model.Document{}, errors.New("installed Python metadata does not match its dist-info directory")
	}
	hash := sha256.Sum256(data)
	digest := "sha256:" + hex.EncodeToString(hash[:])
	evidence := model.Evidence{Collector: "python-dist-info", InputPath: source, InputDigest: digest, Method: "installed-metadata"}
	id := "python-installed:" + common.ID(metadataPath+"\x00"+name+"\x00"+version)
	doc := common.NewDocument(source, project, "python-installed", nil)
	doc.Components = append(doc.Components, model.Component{ID: id, Kind: "package", Name: name, Version: version, Context: "location=" + path.Dir(path.Dir(metadataPath)), Evidence: []model.Evidence{evidence}})
	doc.Edges = append(doc.Edges, model.Edge{From: "root", To: id, Kind: "installed", Evidence: evidence})
	doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "distribution_source_unavailable", Name: name})
	for _, header := range headers {
		if header.name == "requires-dist" {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "declared_dependencies_unresolved", Name: name})
			break
		}
	}
	common.Finalize(&doc)
	return doc, nil
}

// IsInstalledMetadataPath accepts an installed dist-info record immediately
// below a Python package directory, including virtual environments.
func IsInstalledMetadataPath(name string) bool {
	if path.Clean(name) != name || !strings.HasSuffix(name, ".dist-info/METADATA") {
		return false
	}
	parts := strings.Split(name, "/")
	if len(parts) < 3 {
		return false
	}
	parent := parts[len(parts)-3]
	folder := parts[len(parts)-2]
	return (parent == "site-packages" || parent == "dist-packages") && strings.Contains(strings.TrimSuffix(folder, ".dist-info"), "-")
}
