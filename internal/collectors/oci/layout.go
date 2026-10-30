package oci

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"ravel/internal/collectors/apk"
	"ravel/internal/collectors/common"
	"ravel/internal/collectors/dpkg"
	"ravel/internal/collectors/javaarchive"
	"ravel/internal/collectors/npm"
	"ravel/internal/collectors/python"
	"ravel/internal/collectors/rpm"
	"ravel/internal/model"
)

const (
	maxMetadataBytes       = 8 << 20
	maxDatabaseBytes       = 128 << 20
	maxLayerBytes          = 2 << 30
	maxExpandedLayer       = 4 << 30
	maxLayerEntries        = 1000000
	maxImageLayers         = 128
	maxPythonMetadataFiles = 2000
	maxPythonMetadataTotal = 128 << 20
	maxNodeMetadataFiles   = 20000
	maxNodeMetadataTotal   = 128 << 20
	maxJavaArchiveFiles    = 1000
	maxJavaArchiveTotal    = 256 << 20
	manifestMediaType      = "application/vnd.oci.image.manifest.v1+json"
	indexMediaType         = "application/vnd.oci.image.index.v1+json"
	configMediaType        = "application/vnd.oci.image.config.v1+json"
	dockerManifestType     = "application/vnd.docker.distribution.manifest.v2+json"
	dockerIndexType        = "application/vnd.docker.distribution.manifest.list.v2+json"
	dockerConfigType       = "application/vnd.docker.container.image.v1+json"
	dockerPlainLayerType   = "application/vnd.docker.image.rootfs.diff.tar"
	dockerGzipLayerType    = "application/vnd.docker.image.rootfs.diff.tar.gzip"
	dockerForeignLayerType = "application/vnd.docker.image.rootfs.foreign.diff.tar.gzip"
	plainLayerType         = "application/vnd.oci.image.layer.v1.tar"
	gzipLayerType          = "application/vnd.oci.image.layer.v1.tar+gzip"
	plainNonDistType       = "application/vnd.oci.image.layer.nondistributable.v1.tar"
	gzipNonDistType        = "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip"
	statusPath             = "var/lib/dpkg/status"
	apkInstalledPath       = "lib/apk/db/installed"
)

var databasePaths = append([]string{statusPath, apkInstalledPath}, rpm.DatabasePaths...)
var rpmWALPaths = []string{
	"usr/lib/sysimage/rpm/rpmdb.sqlite-wal", "var/lib/rpm/rpmdb.sqlite-wal", "usr/share/rpm/rpmdb.sqlite-wal",
}
var trackedDatabasePaths = append(append([]string{}, databasePaths...), rpmWALPaths...)

var (
	sha256Digest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	platformName = regexp.MustCompile(`^[a-z0-9]+/[a-z0-9]+(?:/[a-z0-9._-]+)?$`)
)

type descriptor struct {
	MediaType   string            `json:"mediaType"`
	Digest      string            `json:"digest"`
	Size        int64             `json:"size"`
	Annotations map[string]string `json:"annotations,omitempty"`
	Platform    *struct {
		OS           string `json:"os"`
		Architecture string `json:"architecture"`
		Variant      string `json:"variant"`
	} `json:"platform,omitempty"`
}

type imageIndex struct {
	SchemaVersion int          `json:"schemaVersion"`
	Manifests     []descriptor `json:"manifests"`
}

type imageManifest struct {
	SchemaVersion int          `json:"schemaVersion"`
	Config        descriptor   `json:"config"`
	Layers        []descriptor `json:"layers"`
}

type imageConfig struct {
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
	Variant      string `json:"variant"`
	RootFS       struct {
		Type    string   `json:"type"`
		DiffIDs []string `json:"diff_ids"`
	} `json:"rootfs"`
}

type imageChoice struct {
	config imageConfig
	layers []descriptor
}

type javaArchiveState struct {
	data   []byte
	layer  string
	status string
}

// Collect reads an OCI image layout directory. It reconstructs the final
// installed package databases across layers without extracting image files.
func Collect(layout, project, requestedPlatform string) (model.Document, error) {
	if requestedPlatform != "" && !platformName.MatchString(requestedPlatform) {
		return model.Document{}, errors.New("invalid OCI platform; use os/architecture[/variant]")
	}
	layoutPath := filepath.Join(layout, "oci-layout")
	indexPath := filepath.Join(layout, "index.json")
	layoutData, err := readLocalMetadata(layoutPath)
	if err != nil {
		return model.Document{}, err
	}
	var header struct {
		ImageLayoutVersion string `json:"imageLayoutVersion"`
	}
	if err := json.Unmarshal(layoutData, &header); err != nil || header.ImageLayoutVersion != "1.0.0" && header.ImageLayoutVersion != "1.1.0" {
		return model.Document{}, errors.New("unsupported OCI image layout version")
	}
	indexData, err := readLocalMetadata(indexPath)
	if err != nil {
		return model.Document{}, err
	}
	var index imageIndex
	if err := json.Unmarshal(indexData, &index); err != nil || index.SchemaVersion != 2 {
		return model.Document{}, errors.New("invalid OCI image index")
	}
	var manifests []descriptor
	sources := []string{layoutPath, indexPath}
	seen := map[string]bool{}
	for _, item := range index.Manifests {
		if err := collectManifests(layout, item, requestedPlatform, 0, seen, &manifests, &sources); err != nil {
			return model.Document{}, err
		}
	}
	if len(manifests) == 0 {
		if requestedPlatform != "" {
			return model.Document{}, fmt.Errorf("OCI image has no manifest for platform %s", requestedPlatform)
		}
		return model.Document{}, errors.New("OCI layout has no image manifest")
	}
	if requestedPlatform == "" && len(manifests) > 1 {
		return model.Document{}, errors.New("OCI layout has multiple images; select --platform os/architecture[/variant]")
	}
	var choices []imageChoice
	for _, item := range manifests {
		manifestData, manifestPath, err := readBlob(layout, item, maxMetadataBytes)
		if err != nil {
			return model.Document{}, err
		}
		sources = append(sources, manifestPath)
		var manifest imageManifest
		if err := json.Unmarshal(manifestData, &manifest); err != nil || manifest.SchemaVersion != 2 || manifest.Config.MediaType != configMediaType && manifest.Config.MediaType != dockerConfigType || len(manifest.Layers) > maxImageLayers {
			return model.Document{}, errors.New("invalid OCI image manifest")
		}
		configData, configPath, err := readBlob(layout, manifest.Config, maxMetadataBytes)
		if err != nil {
			return model.Document{}, err
		}
		sources = append(sources, configPath)
		var config imageConfig
		if err := json.Unmarshal(configData, &config); err != nil || config.OS == "" || config.Architecture == "" || config.RootFS.Type != "layers" || len(config.RootFS.DiffIDs) != len(manifest.Layers) {
			return model.Document{}, errors.New("invalid OCI image config")
		}
		platform := config.OS + "/" + config.Architecture
		if config.Variant != "" {
			platform += "/" + config.Variant
		}
		if requestedPlatform == "" || matchesPlatform(requestedPlatform, platform) {
			choices = append(choices, imageChoice{config: config, layers: manifest.Layers})
		}
	}
	if len(choices) != 1 {
		if len(choices) == 0 {
			return model.Document{}, fmt.Errorf("OCI image has no manifest for platform %s", requestedPlatform)
		}
		return model.Document{}, errors.New("OCI platform selects multiple images; choose a single-image layout")
	}
	choice := choices[0]
	type databaseState struct {
		data  []byte
		layer string
	}
	databases := map[string]databaseState{}
	pythonMetadata := map[string]databaseState{}
	pipVendor := map[string]databaseState{}
	nodeMetadata := map[string]databaseState{}
	rubySpecs := map[string]databaseState{}
	javaArchives := map[string]javaArchiveState{}
	goBinaries := map[string]goBinaryState{}
	goScanLimited := false
	pythonRuntimes := map[string]pythonRuntimeState{}
	pythonRuntimeLimited := false
	var nodeRuntimeBinary *nodeRuntimeBinaryState
	var nodeRuntimeHeader *nodeRuntimeHeaderState
	for i, layer := range choice.layers {
		relevantPaths := map[string]bool{}
		for _, name := range []string{nodeRuntimeBinaryPath, nodeRuntimeHeaderPath} {
			for current := name; ; current = path.Dir(current) {
				relevantPaths[current] = true
				if current == "." {
					break
				}
			}
		}
		for _, metadata := range []map[string]databaseState{pythonMetadata, pipVendor, nodeMetadata, rubySpecs} {
			for name := range metadata {
				for current := name; ; current = path.Dir(current) {
					relevantPaths[current] = true
					if current == "." {
						break
					}
				}
			}
		}
		for name := range javaArchives {
			for current := name; ; current = path.Dir(current) {
				relevantPaths[current] = true
				if current == "." {
					break
				}
			}
		}
		for name := range goBinaries {
			for current := name; ; current = path.Dir(current) {
				relevantPaths[current] = true
				if current == "." {
					break
				}
			}
		}
		for name := range pythonRuntimes {
			for current := name; ; current = path.Dir(current) {
				relevantPaths[current] = true
				if current == "." {
					break
				}
			}
		}
		change, blobPath, err := scanLayer(layout, layer, choice.config.RootFS.DiffIDs[i], relevantPaths, project)
		if err != nil {
			return model.Document{}, fmt.Errorf("OCI layer %d: %w", i, err)
		}
		sources = append(sources, blobPath)
		for name, update := range change.files {
			if update.deleted {
				delete(databases, name)
			}
			if update.present {
				databases[name] = databaseState{data: update.data, layer: layer.Digest}
			}
		}
		for _, removed := range change.whiteouts {
			if removed == "." || removed == nodeRuntimeBinaryPath || strings.HasPrefix(nodeRuntimeBinaryPath, removed+"/") {
				nodeRuntimeBinary = nil
			}
			if removed == "." || removed == nodeRuntimeHeaderPath || strings.HasPrefix(nodeRuntimeHeaderPath, removed+"/") {
				nodeRuntimeHeader = nil
			}
			for _, metadata := range []map[string]databaseState{pythonMetadata, pipVendor, nodeMetadata, rubySpecs} {
				for name := range metadata {
					if name == removed || strings.HasPrefix(name, removed+"/") || removed == "." {
						delete(metadata, name)
					}
				}
			}
			for name := range javaArchives {
				if name == removed || strings.HasPrefix(name, removed+"/") || removed == "." {
					delete(javaArchives, name)
				}
			}
			for name := range goBinaries {
				if name == removed || strings.HasPrefix(name, removed+"/") || removed == "." {
					delete(goBinaries, name)
				}
			}
			for name := range pythonRuntimes {
				if name == removed || strings.HasPrefix(name, removed+"/") || removed == "." {
					delete(pythonRuntimes, name)
				}
			}
		}
		for name, data := range change.python {
			pythonMetadata[name] = databaseState{data: data, layer: layer.Digest}
		}
		for name, data := range change.pipVendor {
			pipVendor[name] = databaseState{data: data, layer: layer.Digest}
		}
		for name, data := range change.node {
			nodeMetadata[name] = databaseState{data: data, layer: layer.Digest}
		}
		for name, data := range change.rubySpecs {
			rubySpecs[name] = databaseState{data: data, layer: layer.Digest}
		}
		for name, state := range change.java {
			state.layer = layer.Digest
			javaArchives[name] = state
		}
		for name, state := range change.goBinaries {
			goBinaries[name] = state
		}
		goScanLimited = goScanLimited || change.goLimited
		for name, state := range change.pythonRuntimes {
			pythonRuntimes[name] = state
		}
		pythonRuntimeLimited = pythonRuntimeLimited || change.pythonRuntimeLimited
		if change.nodeRuntimeBinary != nil {
			nodeRuntimeBinary = change.nodeRuntimeBinary
		}
		if change.nodeRuntimeHeader != nil {
			nodeRuntimeHeader = change.nodeRuntimeHeader
		}
		if len(pythonMetadata) > maxPythonMetadataFiles {
			return model.Document{}, errors.New("OCI image has too many installed Python metadata files")
		}
		metadataBytes := 0
		for _, state := range pythonMetadata {
			metadataBytes += len(state.data)
		}
		if metadataBytes > maxPythonMetadataTotal {
			return model.Document{}, errors.New("OCI image installed Python metadata exceeded size limit")
		}
		if len(pipVendor) > maxPipVendorFiles {
			return model.Document{}, errors.New("OCI image has too many pip vendor manifests")
		}
		if len(nodeMetadata) > maxNodeMetadataFiles {
			return model.Document{}, errors.New("OCI image has too many installed Node package manifests")
		}
		nodeBytes := 0
		for _, state := range nodeMetadata {
			nodeBytes += len(state.data)
		}
		if nodeBytes > maxNodeMetadataTotal {
			return model.Document{}, errors.New("OCI image installed Node package metadata exceeded size limit")
		}
		if len(rubySpecs) > maxRubySpecFiles {
			return model.Document{}, errors.New("OCI image has too many installed Ruby gemspecs")
		}
		rubyBytes := 0
		for _, state := range rubySpecs {
			rubyBytes += len(state.data)
		}
		if rubyBytes > maxRubySpecTotal {
			return model.Document{}, errors.New("OCI image installed Ruby gemspecs exceeded size limit")
		}
		if len(javaArchives) > maxJavaArchiveFiles {
			return model.Document{}, errors.New("OCI image has too many Java archives")
		}
		javaBytes := 0
		for _, state := range javaArchives {
			javaBytes += len(state.data)
		}
		if javaBytes > maxJavaArchiveTotal {
			return model.Document{}, errors.New("OCI image Java archives exceeded size limit")
		}
		if len(goBinaries) > maxGoBinaryImageFiles {
			return model.Document{}, errors.New("OCI image has too many Go binary records")
		}
		if len(pythonRuntimes) > maxPythonRuntimeFiles {
			return model.Document{}, errors.New("OCI image has too many Python runtime library records")
		}
		goModules := 0
		for _, state := range goBinaries {
			goModules += len(state.document.Components)
		}
		if goModules > 50000 {
			return model.Document{}, errors.New("OCI image has too many Go module records")
		}
	}
	platform := choice.config.OS + "/" + choice.config.Architecture
	if choice.config.Variant != "" {
		platform += "/" + choice.config.Variant
	}
	for _, name := range rpmWALPaths {
		if state, found := databases[name]; found && len(state.data) != 0 {
			return model.Document{}, fmt.Errorf("RPM SQLite database has an uncheckpointed WAL: %s", name)
		}
	}
	installedDatabases := 0
	for _, name := range databasePaths {
		if _, found := databases[name]; found {
			installedDatabases++
		}
	}
	if installedDatabases == 0 && len(pythonMetadata) == 0 && len(pipVendor) == 0 && len(nodeMetadata) == 0 && len(rubySpecs) == 0 && len(javaArchives) == 0 && len(goBinaries) == 0 && len(pythonRuntimes) == 0 && nodeRuntimeBinary == nil && nodeRuntimeHeader == nil {
		doc := common.NewDocument(layout, project, "oci", nil)
		doc.Sources = sources
		doc.Coverage.Platforms = []string{platform}
		doc.Coverage.GraphState = "unknown"
		doc.Coverage.OriginState = "unknown"
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "os_package_database_not_found", Name: "dpkg,apk,rpm"}, model.Issue{Code: "image_language_packages_unscanned"})
		if goScanLimited {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "go_binary_scan_limited"})
		}
		if pythonRuntimeLimited {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "python_runtime_scan_limited"})
		}
		common.Finalize(&doc)
		doc.Coverage.GraphState = "unknown"
		return doc, nil
	}
	doc := common.NewDocument(layout, project, "oci", nil)
	doc.Sources = sources
	doc.Coverage.Platforms = []string{platform}
	if goScanLimited {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "go_binary_scan_limited"})
	}
	if pythonRuntimeLimited {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "python_runtime_scan_limited"})
	}
	if installedDatabases == 0 {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "os_package_database_not_found", Name: "dpkg,apk,rpm"})
	}
	rpmDatabases := 0
	for _, name := range rpm.DatabasePaths {
		if _, found := databases[name]; found {
			rpmDatabases++
		}
	}
	if rpmDatabases > 1 {
		return model.Document{}, errors.New("OCI image has multiple RPM databases; active database is ambiguous")
	}
	for _, name := range databasePaths {
		state, found := databases[name]
		if !found {
			continue
		}
		evidencePath := "oci:" + state.layer + "!/" + name
		var database model.Document
		if name == statusPath {
			database, err = dpkg.CollectBytes(state.data, evidencePath, project)
		} else if name == apkInstalledPath {
			database, err = apk.CollectBytes(state.data, evidencePath, project)
		} else {
			database, err = rpm.CollectBytes(state.data, evidencePath, project)
		}
		if err != nil {
			return model.Document{}, fmt.Errorf("invalid %s database in OCI image: %w", name, err)
		}
		doc.Components = append(doc.Components, database.Components...)
		doc.Edges = append(doc.Edges, database.Edges...)
		doc.Origins = append(doc.Origins, database.Origins...)
		doc.Development = append(doc.Development, database.Development...)
		doc.Coverage.Issues = append(doc.Coverage.Issues, database.Coverage.Issues...)
	}
	pythonNames := make([]string, 0, len(pythonMetadata))
	for name := range pythonMetadata {
		pythonNames = append(pythonNames, name)
	}
	sort.Strings(pythonNames)
	var installedRecords []python.InstalledRecord
	for _, name := range pythonNames {
		state := pythonMetadata[name]
		evidencePath := "oci:" + state.layer + "!/" + name
		installed, err := python.CollectInstalledMetadata(state.data, evidencePath, project, name)
		if err != nil {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "python_installed_metadata_invalid", Name: name})
			continue
		}
		installedRecords = append(installedRecords, python.InstalledRecord{Component: installed.Components[0], Metadata: state.data, MetadataPath: name})
		doc.Components = append(doc.Components, installed.Components...)
		doc.Edges = append(doc.Edges, installed.Edges...)
		doc.Origins = append(doc.Origins, installed.Origins...)
		doc.Development = append(doc.Development, installed.Development...)
		for _, issue := range installed.Coverage.Issues {
			if issue.Code != "declared_dependencies_unresolved" {
				doc.Coverage.Issues = append(doc.Coverage.Issues, issue)
			}
		}
	}
	python.LinkInstalledRequirements(&doc, installedRecords)
	vendorNames := make([]string, 0, len(pipVendor))
	for name := range pipVendor {
		vendorNames = append(vendorNames, name)
	}
	sort.Strings(vendorNames)
	for _, name := range vendorNames {
		state := pipVendor[name]
		pipID := ""
		matches := 0
		sitePackages := path.Dir(path.Dir(path.Dir(name)))
		for _, record := range installedRecords {
			if strings.EqualFold(record.Component.Name, "pip") && record.Component.Context == "location="+sitePackages {
				pipID = record.Component.ID
				matches++
			}
		}
		if matches != 1 {
			pipID = ""
		}
		evidencePath := "oci:" + state.layer + "!/" + name
		vendorDoc, err := collectPipVendor(state.data, evidencePath, project, name, pipID)
		if err != nil {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "pip_vendor_manifest_invalid", Name: name})
			continue
		}
		doc.Components = append(doc.Components, vendorDoc.Components...)
		doc.Edges = append(doc.Edges, vendorDoc.Edges...)
		doc.Coverage.Issues = append(doc.Coverage.Issues, vendorDoc.Coverage.Issues...)
	}
	nodeNames := make([]string, 0, len(nodeMetadata))
	for name := range nodeMetadata {
		nodeNames = append(nodeNames, name)
	}
	sort.Strings(nodeNames)
	var installedNodeRecords []npm.InstalledRecord
	for _, name := range nodeNames {
		state := nodeMetadata[name]
		evidencePath := "oci:" + state.layer + "!/" + name
		installed, err := npm.CollectInstalledPackage(state.data, evidencePath, project, name)
		if err != nil {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "node_installed_metadata_invalid", Name: name})
			continue
		}
		installedNodeRecords = append(installedNodeRecords, npm.InstalledRecord{Component: installed.Components[0], Metadata: state.data, MetadataPath: name})
		doc.Components = append(doc.Components, installed.Components...)
		doc.Edges = append(doc.Edges, installed.Edges...)
		doc.Origins = append(doc.Origins, installed.Origins...)
		doc.Development = append(doc.Development, installed.Development...)
		for _, issue := range installed.Coverage.Issues {
			if issue.Code != "declared_dependencies_unresolved" {
				doc.Coverage.Issues = append(doc.Coverage.Issues, issue)
			}
		}
	}
	npm.LinkInstalledDependencies(&doc, installedNodeRecords)
	rubyNames := make([]string, 0, len(rubySpecs))
	for name := range rubySpecs {
		rubyNames = append(rubyNames, name)
	}
	sort.Strings(rubyNames)
	rubyInstalled := false
	for _, name := range rubyNames {
		state := rubySpecs[name]
		evidencePath := "oci:" + state.layer + "!/" + name
		installed, err := inspectInstalledRubySpec(state.data, evidencePath, project, name)
		if err != nil {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "ruby_installed_spec_invalid", Name: name})
			continue
		}
		rubyInstalled = true
		doc.Components = append(doc.Components, installed.Components...)
		doc.Edges = append(doc.Edges, installed.Edges...)
	}
	if rubyInstalled {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "ruby_installed_graph_unavailable"}, model.Issue{Code: "ruby_installed_origin_unavailable"})
	}
	javaNames := make([]string, 0, len(javaArchives))
	for name := range javaArchives {
		javaNames = append(javaNames, name)
	}
	sort.Strings(javaNames)
	for _, name := range javaNames {
		state := javaArchives[name]
		if state.status != "" {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "java_installed_archive_" + state.status, Name: name})
			continue
		}
		evidencePath := "oci:" + state.layer + "!/" + name
		installed, err := javaarchive.CollectBytes(state.data, evidencePath, project)
		if err != nil {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "java_installed_archive_invalid", Name: name})
			continue
		}
		for i := range installed.Components {
			installed.Components[i].Context = "location=/" + name
		}
		doc.Components = append(doc.Components, installed.Components...)
		doc.Edges = append(doc.Edges, installed.Edges...)
		doc.Origins = append(doc.Origins, installed.Origins...)
		doc.Development = append(doc.Development, installed.Development...)
		doc.Coverage.Issues = append(doc.Coverage.Issues, installed.Coverage.Issues...)
	}
	goNames := make([]string, 0, len(goBinaries))
	for name := range goBinaries {
		goNames = append(goNames, name)
	}
	sort.Strings(goNames)
	for _, name := range goNames {
		state := goBinaries[name]
		if state.status != "" {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "go_binary_" + state.status, Name: name})
			continue
		}
		installed := state.document
		doc.Components = append(doc.Components, installed.Components...)
		doc.Edges = append(doc.Edges, installed.Edges...)
		doc.Origins = append(doc.Origins, installed.Origins...)
		doc.Development = append(doc.Development, installed.Development...)
		doc.Coverage.Issues = append(doc.Coverage.Issues, installed.Coverage.Issues...)
	}
	pythonRuntimeNames := make([]string, 0, len(pythonRuntimes))
	for name := range pythonRuntimes {
		pythonRuntimeNames = append(pythonRuntimeNames, name)
	}
	sort.Strings(pythonRuntimeNames)
	for _, name := range pythonRuntimeNames {
		state := pythonRuntimes[name]
		if state.status != "" {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "python_runtime_" + state.status, Name: name})
			continue
		}
		installed := state.document
		doc.Components = append(doc.Components, installed.Components...)
		doc.Edges = append(doc.Edges, installed.Edges...)
		doc.Coverage.Issues = append(doc.Coverage.Issues, installed.Coverage.Issues...)
	}
	if nodeRuntimeBinary != nil {
		if nodeRuntimeBinary.status != "" {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "node_runtime_" + nodeRuntimeBinary.status, Name: nodeRuntimeBinaryPath})
		} else {
			installed, err := nodeRuntimeDocument(*nodeRuntimeBinary, nodeRuntimeHeader, project)
			if err != nil {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "node_runtime_version_mismatch", Name: nodeRuntimeBinaryPath})
			} else {
				doc.Components = append(doc.Components, installed.Components...)
				doc.Edges = append(doc.Edges, installed.Edges...)
				doc.Coverage.Issues = append(doc.Coverage.Issues, installed.Coverage.Issues...)
			}
		}
	}
	if nodeRuntimeHeader != nil && nodeRuntimeHeader.status != "" {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "node_runtime_" + nodeRuntimeHeader.status, Name: nodeRuntimeHeaderPath})
	}
	doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "image_language_packages_unscanned"})
	for i := range doc.Components {
		doc.Components[i].Context += ";image=" + platform
	}
	common.Finalize(&doc)
	return doc, nil
}

func readLocalMetadata(file string) ([]byte, error) {
	info, err := os.Lstat(file)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxMetadataBytes {
		return nil, fmt.Errorf("invalid OCI metadata file: %s", file)
	}
	return os.ReadFile(file)
}

func collectManifests(layout string, item descriptor, requestedPlatform string, depth int, seen map[string]bool, out *[]descriptor, sources *[]string) error {
	if depth > 8 || len(*out) > 128 {
		return errors.New("OCI image index exceeds traversal limit")
	}
	if item.Annotations["vnd.docker.reference.type"] == "attestation-manifest" && item.Platform != nil && item.Platform.OS == "unknown" && item.Platform.Architecture == "unknown" {
		return nil // Docker attaches attestations as non-runnable manifests.
	}
	if requestedPlatform != "" && item.Platform != nil && !descriptorMatchesPlatform(item, requestedPlatform) {
		return nil // Unselected platform blobs may be absent from sparse archives.
	}
	if item.MediaType != manifestMediaType && item.MediaType != dockerManifestType && item.MediaType != indexMediaType && item.MediaType != dockerIndexType {
		return nil // indexes may contain artifact descriptors
	}
	if seen[item.Digest] {
		return nil
	}
	seen[item.Digest] = true
	if item.MediaType == manifestMediaType || item.MediaType == dockerManifestType {
		*out = append(*out, item)
		return nil
	}
	data, source, err := readBlob(layout, item, maxMetadataBytes)
	if err != nil {
		return err
	}
	*sources = append(*sources, source)
	var nested imageIndex
	if err := json.Unmarshal(data, &nested); err != nil || nested.SchemaVersion != 2 {
		return errors.New("invalid nested OCI image index")
	}
	for _, child := range nested.Manifests {
		if err := collectManifests(layout, child, requestedPlatform, depth+1, seen, out, sources); err != nil {
			return err
		}
	}
	return nil
}

func descriptorMatchesPlatform(item descriptor, requested string) bool {
	parts := strings.Split(requested, "/")
	if item.Platform.OS != parts[0] || item.Platform.Architecture != parts[1] {
		return false
	}
	return len(parts) == 2 || item.Platform.Variant == "" || item.Platform.Variant == parts[2]
}

func matchesPlatform(requested, actual string) bool {
	return requested == actual || strings.Count(requested, "/") == 1 && strings.HasPrefix(actual, requested+"/")
}

func blobPath(layout string, item descriptor) (string, error) {
	if !sha256Digest.MatchString(item.Digest) || item.Size < 0 {
		return "", errors.New("unsupported or invalid OCI blob descriptor")
	}
	file := filepath.Join(layout, "blobs", "sha256", strings.TrimPrefix(item.Digest, "sha256:"))
	for _, part := range []string{filepath.Join(layout, "blobs"), filepath.Join(layout, "blobs", "sha256"), file} {
		info, err := os.Lstat(part)
		if err != nil {
			return "", err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return "", errors.New("OCI blob path contains a symlink")
		}
	}
	info, err := os.Stat(file)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Size() != item.Size {
		return "", errors.New("OCI blob size does not match descriptor")
	}
	return file, nil
}

func readBlob(layout string, item descriptor, limit int64) ([]byte, string, error) {
	file, err := blobPath(layout, item)
	if err != nil {
		return nil, "", err
	}
	if item.Size > limit {
		return nil, "", errors.New("OCI metadata blob exceeded size limit")
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, "", err
	}
	hash := sha256.Sum256(data)
	if "sha256:"+hex.EncodeToString(hash[:]) != item.Digest {
		return nil, "", errors.New("OCI blob digest mismatch")
	}
	return data, file, nil
}

type databaseChange struct {
	deleted bool
	present bool
	data    []byte
}

type layerChange struct {
	files                map[string]databaseChange
	python               map[string][]byte
	pipVendor            map[string][]byte
	node                 map[string][]byte
	rubySpecs            map[string][]byte
	java                 map[string]javaArchiveState
	goBinaries           map[string]goBinaryState
	goLimited            bool
	pythonRuntimes       map[string]pythonRuntimeState
	pythonRuntimeLimited bool
	nodeRuntimeBinary    *nodeRuntimeBinaryState
	nodeRuntimeHeader    *nodeRuntimeHeaderState
	whiteouts            []string
}

func scanLayer(layout string, item descriptor, diffID string, relevantLanguagePaths map[string]bool, project string) (layerChange, string, error) {
	if item.MediaType != plainLayerType && item.MediaType != gzipLayerType && item.MediaType != plainNonDistType && item.MediaType != gzipNonDistType && item.MediaType != dockerPlainLayerType && item.MediaType != dockerGzipLayerType && item.MediaType != dockerForeignLayerType {
		return layerChange{}, "", fmt.Errorf("unsupported OCI layer media type %s", item.MediaType)
	}
	if !sha256Digest.MatchString(diffID) || item.Size > maxLayerBytes {
		return layerChange{}, "", errors.New("invalid OCI layer size or diff ID")
	}
	file, err := blobPath(layout, item)
	if err != nil {
		return layerChange{}, "", err
	}
	f, err := os.Open(file)
	if err != nil {
		return layerChange{}, "", err
	}
	defer f.Close()
	compressedHash := sha256.New()
	compressed := io.TeeReader(f, compressedHash)
	var uncompressed io.Reader = compressed
	if item.MediaType == gzipLayerType || item.MediaType == gzipNonDistType || item.MediaType == dockerGzipLayerType || item.MediaType == dockerForeignLayerType {
		gz, err := gzip.NewReader(compressed)
		if err != nil {
			return layerChange{}, "", err
		}
		defer gz.Close()
		uncompressed = gz
	}
	diffHash := sha256.New()
	limited := &io.LimitedReader{R: uncompressed, N: maxExpandedLayer + 1}
	stream := io.TeeReader(limited, diffHash)
	reader := tar.NewReader(stream)
	change := layerChange{files: map[string]databaseChange{}, python: map[string][]byte{}, pipVendor: map[string][]byte{}, node: map[string][]byte{}, rubySpecs: map[string][]byte{}, java: map[string]javaArchiveState{}, goBinaries: map[string]goBinaryState{}, pythonRuntimes: map[string]pythonRuntimeState{}}
	seenDatabase := map[string]bool{}
	parentReplaced := map[string]bool{}
	nonDirectoryPaths := map[string]bool{}
	entries := 0
	pythonBytes := 0
	pipVendorBytes := 0
	nodeBytes := 0
	rubyBytes := 0
	javaBytes := 0
	goBytes := 0
	goFiles := 0
	pythonRuntimeBytes := 0
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return layerChange{}, "", err
		}
		entries++
		if entries > maxLayerEntries {
			return layerChange{}, "", errors.New("OCI layer has too many entries")
		}
		name, err := cleanTarPath(header.Name)
		if err != nil {
			return layerChange{}, "", err
		}
		if name == "." {
			continue
		}
		if header.Typeflag != tar.TypeDir {
			nonDirectoryPaths[name] = true
		}
		base := path.Base(name)
		if strings.HasPrefix(base, ".wh.") {
			if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA || header.Size != 0 {
				return layerChange{}, "", errors.New("invalid OCI whiteout entry")
			}
			if base == ".wh." {
				return layerChange{}, "", errors.New("invalid OCI whiteout")
			}
			deletedPath := path.Join(path.Dir(name), strings.TrimPrefix(base, ".wh."))
			if base == ".wh..wh..opq" {
				deletedPath = path.Dir(name)
			}
			if relevantLanguagePaths[deletedPath] {
				change.whiteouts = append(change.whiteouts, deletedPath)
			}
			for _, target := range trackedDatabasePaths {
				if ancestorOfTarget(deletedPath, target) {
					update := change.files[target]
					update.deleted = true
					change.files[target] = update
				}
			}
			continue
		}
		if isPipVendorPath(name) {
			if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA || header.Size > maxPipVendorBytes {
				return layerChange{}, "", fmt.Errorf("unsupported OCI pip vendor manifest entry: %s", name)
			}
			if _, duplicate := change.pipVendor[name]; duplicate {
				return layerChange{}, "", fmt.Errorf("duplicate OCI pip vendor manifest entry: %s", name)
			}
			data, err := io.ReadAll(io.LimitReader(reader, maxPipVendorBytes+1))
			if err != nil || len(data) > maxPipVendorBytes {
				return layerChange{}, "", errors.New("OCI pip vendor manifest exceeded size limit")
			}
			change.pipVendor[name] = data
			pipVendorBytes += len(data)
			if len(change.pipVendor) > maxPipVendorFiles || pipVendorBytes > maxPipVendorFiles*maxPipVendorBytes {
				return layerChange{}, "", errors.New("OCI layer has too much pip vendor metadata")
			}
			continue
		}
		if python.IsInstalledMetadataPath(name) {
			if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA || header.Size > python.MaxInstalledMetadataBytes {
				return layerChange{}, "", fmt.Errorf("unsupported OCI installed Python metadata entry: %s", name)
			}
			if _, duplicate := change.python[name]; duplicate {
				return layerChange{}, "", fmt.Errorf("duplicate OCI installed Python metadata entry: %s", name)
			}
			data, err := io.ReadAll(io.LimitReader(reader, python.MaxInstalledMetadataBytes+1))
			if err != nil || len(data) > python.MaxInstalledMetadataBytes {
				return layerChange{}, "", errors.New("OCI installed Python metadata exceeded size limit")
			}
			change.python[name] = data
			pythonBytes += len(data)
			if len(change.python) > maxPythonMetadataFiles || pythonBytes > maxPythonMetadataTotal {
				return layerChange{}, "", errors.New("OCI layer has too much installed Python metadata")
			}
			continue
		}
		if npm.IsInstalledPackagePath(name) {
			if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA || header.Size > npm.MaxInstalledPackageJSONBytes {
				return layerChange{}, "", fmt.Errorf("unsupported OCI installed Node package manifest entry: %s", name)
			}
			if _, duplicate := change.node[name]; duplicate {
				return layerChange{}, "", fmt.Errorf("duplicate OCI installed Node package manifest entry: %s", name)
			}
			data, err := io.ReadAll(io.LimitReader(reader, npm.MaxInstalledPackageJSONBytes+1))
			if err != nil || len(data) > npm.MaxInstalledPackageJSONBytes {
				return layerChange{}, "", errors.New("OCI installed Node package manifest exceeded size limit")
			}
			change.node[name] = data
			nodeBytes += len(data)
			if len(change.node) > maxNodeMetadataFiles || nodeBytes > maxNodeMetadataTotal {
				return layerChange{}, "", errors.New("OCI layer has too much installed Node package metadata")
			}
			continue
		}
		if isInstalledRubySpecPath(name) {
			if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA || header.Size > maxRubySpecBytes {
				return layerChange{}, "", fmt.Errorf("unsupported OCI installed Ruby gemspec entry: %s", name)
			}
			if _, duplicate := change.rubySpecs[name]; duplicate {
				return layerChange{}, "", fmt.Errorf("duplicate OCI installed Ruby gemspec entry: %s", name)
			}
			data, err := io.ReadAll(io.LimitReader(reader, maxRubySpecBytes+1))
			if err != nil || len(data) != int(header.Size) {
				return layerChange{}, "", errors.New("invalid OCI installed Ruby gemspec entry")
			}
			change.rubySpecs[name] = data
			rubyBytes += len(data)
			if len(change.rubySpecs) > maxRubySpecFiles || rubyBytes > maxRubySpecTotal {
				return layerChange{}, "", errors.New("OCI layer has too much installed Ruby gemspec metadata")
			}
			continue
		}
		if isJavaArchivePath(name) {
			if _, duplicate := change.java[name]; duplicate {
				return layerChange{}, "", fmt.Errorf("duplicate OCI Java archive entry: %s", name)
			}
			if header.Typeflag == tar.TypeSymlink || header.Typeflag == tar.TypeLink {
				change.java[name] = javaArchiveState{status: "link_unresolved"}
			} else if header.Typeflag == tar.TypeReg || header.Typeflag == tar.TypeRegA {
				if header.Size > javaarchive.MaxInstalledArchiveBytes {
					change.java[name] = javaArchiveState{status: "oversized"}
				} else {
					data, err := io.ReadAll(io.LimitReader(reader, javaarchive.MaxInstalledArchiveBytes+1))
					if err != nil || len(data) > javaarchive.MaxInstalledArchiveBytes {
						return layerChange{}, "", errors.New("OCI Java archive exceeded size limit")
					}
					change.java[name] = javaArchiveState{data: data}
					javaBytes += len(data)
					if javaBytes > maxJavaArchiveTotal {
						return layerChange{}, "", errors.New("OCI layer Java archives exceeded size limit")
					}
				}
			}
			if len(change.java) > maxJavaArchiveFiles {
				return layerChange{}, "", errors.New("OCI layer has too many Java archives")
			}
			if header.Typeflag == tar.TypeReg || header.Typeflag == tar.TypeRegA {
				continue
			}
		}
		for _, target := range trackedDatabasePaths {
			if name == target {
				if seenDatabase[target] || header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA || header.Size > maxDatabaseBytes {
					return layerChange{}, "", fmt.Errorf("unsupported or duplicate OCI database entry: %s", target)
				}
				seenDatabase[target] = true
				update := change.files[target]
				update.present = true
				update.data, err = io.ReadAll(io.LimitReader(reader, maxDatabaseBytes+1))
				if err != nil || len(update.data) > maxDatabaseBytes {
					return layerChange{}, "", errors.New("OCI package database exceeded size limit")
				}
				change.files[target] = update
			} else if ancestorOfTarget(name, target) && header.Typeflag != tar.TypeDir {
				if header.Typeflag == tar.TypeSymlink || header.Typeflag == tar.TypeLink {
					if header.Typeflag != tar.TypeSymlink || !allowedDatabaseParentLink(name, header.Linkname) {
						return layerChange{}, "", fmt.Errorf("OCI package database path has an unsupported link: %s", name)
					}
				}
				update := change.files[target]
				update.deleted = true
				change.files[target] = update
				parentReplaced[target] = true
			}
		}
		if isPythonRuntimeLibraryPath(name) && (header.Typeflag == tar.TypeReg || header.Typeflag == tar.TypeRegA) {
			switch {
			case header.Size > maxPythonRuntimeBytes:
				change.pythonRuntimes[name] = pythonRuntimeState{status: "oversized"}
			case int64(pythonRuntimeBytes)+header.Size > maxPythonRuntimeLayerBytes:
				change.pythonRuntimeLimited = true
			default:
				data, err := io.ReadAll(io.LimitReader(reader, maxPythonRuntimeBytes+1))
				if err != nil || len(data) != int(header.Size) {
					return layerChange{}, "", errors.New("invalid OCI Python runtime library entry")
				}
				pythonRuntimeBytes += len(data)
				input := "oci:" + item.Digest + "!/" + name
				runtimeDoc, recognized, err := inspectPythonRuntimeLibrary(data, input, project, name)
				if err != nil {
					change.pythonRuntimes[name] = pythonRuntimeState{status: "invalid"}
				} else if recognized {
					change.pythonRuntimes[name] = pythonRuntimeState{document: runtimeDoc}
				}
			}
			if relevantLanguagePaths[name] {
				change.whiteouts = append(change.whiteouts, name)
			}
			continue
		}
		if name == nodeRuntimeBinaryPath && (header.Typeflag == tar.TypeReg || header.Typeflag == tar.TypeRegA) {
			if change.nodeRuntimeBinary != nil {
				return layerChange{}, "", errors.New("duplicate OCI Node runtime executable entry")
			}
			if header.Size > maxNodeRuntimeBytes {
				change.nodeRuntimeBinary = &nodeRuntimeBinaryState{status: "oversized"}
			} else {
				source := "oci:" + item.Digest + "!/" + name
				state, err := inspectNodeRuntimeBinary(reader, header.Size, source)
				if err != nil {
					return layerChange{}, "", err
				}
				change.nodeRuntimeBinary = &state
			}
			change.whiteouts = append(change.whiteouts, name)
			continue
		}
		if name == nodeRuntimeHeaderPath && (header.Typeflag == tar.TypeReg || header.Typeflag == tar.TypeRegA) {
			if change.nodeRuntimeHeader != nil {
				return layerChange{}, "", errors.New("duplicate OCI Node runtime version header entry")
			}
			if header.Size > maxNodeHeaderBytes {
				change.nodeRuntimeHeader = &nodeRuntimeHeaderState{status: "header_invalid"}
			} else {
				data, err := io.ReadAll(io.LimitReader(reader, maxNodeHeaderBytes+1))
				if err != nil || len(data) != int(header.Size) {
					return layerChange{}, "", errors.New("invalid OCI Node runtime version header entry")
				}
				source := "oci:" + item.Digest + "!/" + name
				state := inspectNodeRuntimeHeader(data, source)
				change.nodeRuntimeHeader = &state
			}
			change.whiteouts = append(change.whiteouts, name)
			continue
		}
		if (header.Typeflag == tar.TypeReg || header.Typeflag == tar.TypeRegA) && header.Size >= 4 && !seenDatabase[name] {
			var magic [4]byte
			if _, err := io.ReadFull(reader, magic[:]); err != nil {
				return layerChange{}, "", err
			}
			if isELFMagic(magic[:]) {
				goFiles++
				switch {
				case header.Size > maxGoBinaryBytes:
					hasMagic, err := hasGoBuildInfoMagic(reader, header.Size-4)
					if err != nil {
						return layerChange{}, "", err
					}
					if hasMagic {
						change.goBinaries[name] = goBinaryState{status: "oversized"}
					}
				case goFiles > maxGoBinaryFiles || int64(goBytes)+header.Size > maxGoBinaryLayerBytes:
					change.goLimited = true
				default:
					remaining, err := io.ReadAll(io.LimitReader(reader, maxGoBinaryBytes+1))
					if err != nil || len(remaining)+4 != int(header.Size) {
						return layerChange{}, "", errors.New("invalid OCI executable entry")
					}
					data := append(magic[:], remaining...)
					goBytes += len(data)
					input := "oci:" + item.Digest + "!/" + name
					binaryDoc, recognized, err := inspectGoBinary(data, input, project, name)
					if err != nil {
						status := "invalid"
						if errors.Is(err, errGoBinaryModuleLimit) {
							status = "scan_limited"
						}
						change.goBinaries[name] = goBinaryState{status: status}
					} else if recognized {
						change.goBinaries[name] = goBinaryState{document: binaryDoc}
					}
				}
			}
		}
		if relevantLanguagePaths[name] && header.Typeflag != tar.TypeDir {
			change.whiteouts = append(change.whiteouts, name)
		}
	}
	for target := range parentReplaced {
		if seenDatabase[target] {
			return layerChange{}, "", fmt.Errorf("OCI layer replaces database parent directory and %s together", target)
		}
	}
	for _, metadata := range []map[string][]byte{change.python, change.pipVendor, change.node, change.rubySpecs} {
		for name := range metadata {
			for ancestor := path.Dir(name); ancestor != "."; ancestor = path.Dir(ancestor) {
				if nonDirectoryPaths[ancestor] {
					return layerChange{}, "", fmt.Errorf("OCI layer contains installed metadata beneath a non-directory entry: %s", ancestor)
				}
			}
		}
	}
	for name := range change.java {
		for ancestor := path.Dir(name); ancestor != "."; ancestor = path.Dir(ancestor) {
			if nonDirectoryPaths[ancestor] {
				return layerChange{}, "", fmt.Errorf("OCI layer contains Java archive beneath a non-directory entry: %s", ancestor)
			}
		}
	}
	for name := range change.goBinaries {
		for ancestor := path.Dir(name); ancestor != "."; ancestor = path.Dir(ancestor) {
			if nonDirectoryPaths[ancestor] {
				return layerChange{}, "", fmt.Errorf("OCI layer contains Go binary beneath a non-directory entry: %s", ancestor)
			}
		}
	}
	for name := range change.pythonRuntimes {
		for ancestor := path.Dir(name); ancestor != "."; ancestor = path.Dir(ancestor) {
			if nonDirectoryPaths[ancestor] {
				return layerChange{}, "", fmt.Errorf("OCI layer contains Python runtime library beneath a non-directory entry: %s", ancestor)
			}
		}
	}
	if change.nodeRuntimeBinary != nil || change.nodeRuntimeHeader != nil {
		for _, name := range []string{nodeRuntimeBinaryPath, nodeRuntimeHeaderPath} {
			if name == nodeRuntimeBinaryPath && change.nodeRuntimeBinary == nil || name == nodeRuntimeHeaderPath && change.nodeRuntimeHeader == nil {
				continue
			}
			for ancestor := path.Dir(name); ancestor != "."; ancestor = path.Dir(ancestor) {
				if nonDirectoryPaths[ancestor] {
					return layerChange{}, "", fmt.Errorf("OCI layer contains Node runtime file beneath a non-directory entry: %s", ancestor)
				}
			}
		}
	}
	if _, err := io.Copy(io.Discard, stream); err != nil {
		return layerChange{}, "", err
	}
	if maxExpandedLayer+1-limited.N > maxExpandedLayer {
		return layerChange{}, "", errors.New("OCI layer decompressed size exceeded limit")
	}
	if _, err := io.Copy(io.Discard, compressed); err != nil {
		return layerChange{}, "", err
	}
	if "sha256:"+hex.EncodeToString(compressedHash.Sum(nil)) != item.Digest {
		return layerChange{}, "", errors.New("OCI layer blob digest mismatch")
	}
	if "sha256:"+hex.EncodeToString(diffHash.Sum(nil)) != diffID {
		return layerChange{}, "", errors.New("OCI layer diff ID mismatch")
	}
	return change, file, nil
}

func cleanTarPath(raw string) (string, error) {
	if raw == "" || len(raw) > 4096 || strings.HasPrefix(raw, "/") || strings.ContainsAny(raw, "\\\x00") {
		return "", errors.New("unsafe OCI layer path")
	}
	for _, segment := range strings.Split(raw, "/") {
		if segment == ".." {
			return "", errors.New("unsafe OCI layer path")
		}
	}
	return path.Clean(raw), nil
}

func ancestorOfTarget(candidate, target string) bool {
	return candidate == "." || candidate == target || strings.HasPrefix(target, candidate+"/")
}

func isJavaArchivePath(name string) bool {
	base := strings.ToLower(path.Base(name))
	return len(base) > 4 && (strings.HasSuffix(base, ".jar") || strings.HasSuffix(base, ".war"))
}

func allowedDatabaseParentLink(name, target string) bool {
	if len(target) == 0 || len(target) > 4096 || strings.ContainsAny(target, "\\\x00") {
		return false
	}
	parents := map[string]bool{}
	for _, database := range rpm.DatabasePaths {
		parents[path.Dir(database)] = true
	}
	resolved := strings.TrimPrefix(target, "/")
	if !strings.HasPrefix(target, "/") {
		resolved = path.Join(path.Dir(name), target)
	}
	resolved = path.Clean(resolved)
	if name == "lib" && resolved == "usr/lib" {
		return true
	}
	if !parents[name] {
		return false
	}
	return resolved != name && parents[resolved] && resolved != ".." && !strings.HasPrefix(resolved, "../")
}
