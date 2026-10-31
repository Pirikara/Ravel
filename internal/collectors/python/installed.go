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
// its dist-info/METADATA, egg-info/PKG-INFO, or legacy egg-info file. The
// metadata establishes its installed identity, but not its index or artifact.
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
	eggInfo := strings.HasSuffix(metadataPath, ".egg-info/PKG-INFO") || strings.HasSuffix(metadataPath, ".egg-info")
	if !eggInfo {
		folder := path.Base(path.Dir(metadataPath))
		stem := strings.TrimSuffix(folder, ".dist-info")
		separator := strings.LastIndexByte(stem, '-')
		if separator <= 0 || separator == len(stem)-1 || wheelNameToken(stem[:separator]) != wheelNameToken(name) || wheelVersionToken(stem[separator+1:]) != wheelVersionToken(version) {
			return model.Document{}, errors.New("installed Python metadata does not match its dist-info directory")
		}
	}
	hash := sha256.Sum256(data)
	digest := "sha256:" + hex.EncodeToString(hash[:])
	collector := "python-dist-info"
	if eggInfo {
		collector = "python-egg-info"
	}
	evidence := model.Evidence{Collector: collector, InputPath: source, InputDigest: digest, Method: "installed-metadata"}
	id := "python-installed:" + common.ID(metadataPath+"\x00"+name+"\x00"+version)
	doc := common.NewDocument(source, project, "python-installed", nil)
	doc.Components = append(doc.Components, model.Component{ID: id, Kind: "package", Name: name, Version: version, Context: "location=" + installedMetadataEnvironment(metadataPath), Evidence: []model.Evidence{evidence}})
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

// IsInstalledMetadataPath accepts installed dist-info, egg-info directories,
// and legacy egg-info files directly inside a Python package directory.
func IsInstalledMetadataPath(name string) bool {
	if path.Clean(name) != name {
		return false
	}
	parts := strings.Split(name, "/")
	if len(parts) >= 2 && (parts[len(parts)-2] == "site-packages" || parts[len(parts)-2] == "dist-packages") {
		folder := parts[len(parts)-1]
		return strings.HasSuffix(folder, ".egg-info") && len(folder) > len(".egg-info") && !strings.HasPrefix(folder, ".")
	}
	if len(parts) < 3 {
		return false
	}
	parent := parts[len(parts)-3]
	folder := parts[len(parts)-2]
	if parent != "site-packages" && parent != "dist-packages" {
		return false
	}
	if strings.HasSuffix(name, ".dist-info/METADATA") {
		return strings.Contains(strings.TrimSuffix(folder, ".dist-info"), "-")
	}
	return strings.HasSuffix(name, ".egg-info/PKG-INFO") && len(folder) > len(".egg-info") && !strings.HasPrefix(folder, ".")
}

// IsInstalledEggRequirementsPath identifies a legacy egg-info dependency
// sidecar. Its presence must be checked against the final OCI layer state.
func IsInstalledEggRequirementsPath(name string) bool {
	if !strings.HasSuffix(name, ".egg-info/requires.txt") {
		return false
	}
	return IsInstalledMetadataPath(strings.TrimSuffix(name, "requires.txt") + "PKG-INFO")
}

func installedMetadataEnvironment(metadataPath string) string {
	if strings.HasSuffix(metadataPath, ".egg-info") {
		return path.Dir(metadataPath)
	}
	return path.Dir(path.Dir(metadataPath))
}
