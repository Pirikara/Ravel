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
	"ravel/internal/collectors/composer"
	"ravel/internal/collectors/dpkg"
	"ravel/internal/collectors/javaarchive"
	"ravel/internal/collectors/npm"
	"ravel/internal/collectors/nuget"
	"ravel/internal/collectors/python"
	"ravel/internal/collectors/rpm"
	"ravel/internal/model"
)

const (
	maxMetadataBytes                   = 8 << 20
	maxDatabaseBytes                   = 128 << 20
	maxLayerBytes                      = 2 << 30
	maxExpandedLayer                   = 4 << 30
	maxLayerEntries                    = 1000000
	maxImageLayers                     = 128
	maxPythonMetadataFiles             = 2000
	maxPythonMetadataTotal             = 128 << 20
	maxPythonEggRequirementsTotal      = 8 << 20
	maxPythonEggRequirementsLinesTotal = 100000
	maxComposerInstalledFiles          = 100
	maxComposerInstalledTotal          = 64 << 20
	maxDotnetDepsFiles                 = 500
	maxDotnetDepsTotal                 = 64 << 20
	maxNodeMetadataFiles               = 20000
	maxNodeMetadataTotal               = 128 << 20
	maxNodePackageLinks                = 20000
	maxJavaArchiveFiles                = 1000
	maxJavaArchiveTotal                = 256 << 20
	manifestMediaType                  = "application/vnd.oci.image.manifest.v1+json"
	indexMediaType                     = "application/vnd.oci.image.index.v1+json"
	configMediaType                    = "application/vnd.oci.image.config.v1+json"
	dockerManifestType                 = "application/vnd.docker.distribution.manifest.v2+json"
	dockerIndexType                    = "application/vnd.docker.distribution.manifest.list.v2+json"
	dockerConfigType                   = "application/vnd.docker.container.image.v1+json"
	dockerPlainLayerType               = "application/vnd.docker.image.rootfs.diff.tar"
	dockerGzipLayerType                = "application/vnd.docker.image.rootfs.diff.tar.gzip"
	dockerForeignLayerType             = "application/vnd.docker.image.rootfs.foreign.diff.tar.gzip"
	plainLayerType                     = "application/vnd.oci.image.layer.v1.tar"
	gzipLayerType                      = "application/vnd.oci.image.layer.v1.tar+gzip"
	plainNonDistType                   = "application/vnd.oci.image.layer.nondistributable.v1.tar"
	gzipNonDistType                    = "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip"
	statusPath                         = "var/lib/dpkg/status"
	apkInstalledPath                   = "lib/apk/db/installed"
	apkInstalledADBPath                = "lib/apk/db/installed.adb"
)

var databasePaths = append([]string{statusPath, apkInstalledPath, apkInstalledADBPath}, rpm.DatabasePaths...)
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

type pythonEggRequirementsState struct {
	data   []byte
	layer  string
	status string
	lines  int
}

type composerInstalledState struct {
	data   []byte
	layer  string
	status string
}

type dotnetDepsState struct {
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
	pythonEggRequirements := map[string]pythonEggRequirementsState{}
	pythonEggRequirementsBytes := 0
	pythonEggRequirementsLines := 0
	composerInstalled := map[string]composerInstalledState{}
	composerPackageManifests := map[string]composerPackageManifestState{}
	composerPackageLimited := false
	dotnetDeps := map[string]dotnetDepsState{}
	dotnetAssemblies := map[string]dotnetAssemblyState{}
	dotnetAssemblyLimited := false
	pipVendor := map[string]databaseState{}
	nodeMetadata := map[string]databaseState{}
	nodePackageLinks := map[string]string{}
	rubySpecs := map[string]databaseState{}
	javaArchives := map[string]javaArchiveState{}
	goBinaries := map[string]goBinaryState{}
	goScanLimited := false
	var bunBinary *bunBinaryState
	var denoBinary *denoBinaryState
	var httpdBinary *httpdBinaryState
	var haproxyBinary *haproxyBinaryState
	var memcachedBinary *memcachedBinaryState
	var postgresBinary *postgresBinaryState
	var redisBinary *redisBinaryState
	pythonRuntimes := map[string]pythonRuntimeState{}
	pythonRuntimeLimited := false
	rubyRuntimes := map[string]rubyRuntimeState{}
	rubyRuntimeLimited := false
	var nodeRuntimeBinary *nodeRuntimeBinaryState
	var nodeRuntimeHeader *nodeRuntimeHeaderState
	for i, layer := range choice.layers {
		relevantPaths := map[string]bool{}
		for _, name := range []string{nodeRuntimeBinaryPath, nodeRuntimeHeaderPath, bunBinaryPath, denoBinaryPath, httpdBinaryPath, haproxyBinaryPath, memcachedBinaryPath, postgresBinaryPath, redisBinaryPath} {
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
		for name := range pythonEggRequirements {
			for current := name; ; current = path.Dir(current) {
				relevantPaths[current] = true
				if current == "." {
					break
				}
			}
		}
		for name := range composerInstalled {
			for current := name; ; current = path.Dir(current) {
				relevantPaths[current] = true
				if current == "." {
					break
				}
			}
		}
		for name := range composerPackageManifests {
			for current := name; ; current = path.Dir(current) {
				relevantPaths[current] = true
				if current == "." {
					break
				}
			}
		}
		for name := range dotnetDeps {
			for current := name; ; current = path.Dir(current) {
				relevantPaths[current] = true
				if current == "." {
					break
				}
			}
		}
		for name := range dotnetAssemblies {
			for current := name; ; current = path.Dir(current) {
				relevantPaths[current] = true
				if current == "." {
					break
				}
			}
		}
		for name := range nodePackageLinks {
			for current := name; ; current = path.Dir(current) {
				relevantPaths[current] = true
				if current == "." {
					break
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
		for name := range rubyRuntimes {
			for current := name; ; current = path.Dir(current) {
				relevantPaths[current] = true
				if current == "." {
					break
				}
			}
		}
		change, blobPath, err := scanLayer(layout, layer, choice.config.RootFS.DiffIDs[i], relevantPaths, nodePackageLinks, project, choice.config.Architecture)
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
			for name := range nodePackageLinks {
				if name == removed || strings.HasPrefix(name, removed+"/") || removed == "." {
					delete(nodePackageLinks, name)
				}
			}
			if removed == "." || removed == nodeRuntimeBinaryPath || strings.HasPrefix(nodeRuntimeBinaryPath, removed+"/") {
				nodeRuntimeBinary = nil
			}
			if removed == "." || removed == nodeRuntimeHeaderPath || strings.HasPrefix(nodeRuntimeHeaderPath, removed+"/") {
				nodeRuntimeHeader = nil
			}
			if removed == "." || removed == bunBinaryPath || strings.HasPrefix(bunBinaryPath, removed+"/") {
				bunBinary = nil
			}
			if removed == "." || removed == denoBinaryPath || strings.HasPrefix(denoBinaryPath, removed+"/") {
				denoBinary = nil
			}
			if removed == "." || removed == httpdBinaryPath || strings.HasPrefix(httpdBinaryPath, removed+"/") {
				httpdBinary = nil
			}
			if removed == "." || removed == haproxyBinaryPath || strings.HasPrefix(haproxyBinaryPath, removed+"/") {
				haproxyBinary = nil
			}
			if removed == "." || removed == memcachedBinaryPath || strings.HasPrefix(memcachedBinaryPath, removed+"/") {
				memcachedBinary = nil
			}
			if removed == "." || removed == postgresBinaryPath || strings.HasPrefix(postgresBinaryPath, removed+"/") {
				postgresBinary = nil
			}
			if removed == "." || removed == redisBinaryPath || strings.HasPrefix(redisBinaryPath, removed+"/") {
				redisBinary = nil
			}
			for _, metadata := range []map[string]databaseState{pythonMetadata, pipVendor, nodeMetadata, rubySpecs} {
				for name := range metadata {
					if name == removed || strings.HasPrefix(name, removed+"/") || removed == "." {
						delete(metadata, name)
					}
				}
			}
			for name := range pythonEggRequirements {
				if name == removed || strings.HasPrefix(name, removed+"/") || removed == "." {
					pythonEggRequirementsBytes -= len(pythonEggRequirements[name].data)
					pythonEggRequirementsLines -= pythonEggRequirements[name].lines
					delete(pythonEggRequirements, name)
				}
			}
			for name := range composerInstalled {
				if name == removed || strings.HasPrefix(name, removed+"/") || removed == "." {
					delete(composerInstalled, name)
				}
			}
			for name := range composerPackageManifests {
				if name == removed || strings.HasPrefix(name, removed+"/") || removed == "." {
					delete(composerPackageManifests, name)
				}
			}
			for name := range dotnetDeps {
				if name == removed || strings.HasPrefix(name, removed+"/") || removed == "." {
					delete(dotnetDeps, name)
				}
			}
			for name := range dotnetAssemblies {
				if name == removed || strings.HasPrefix(name, removed+"/") || removed == "." {
					delete(dotnetAssemblies, name)
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
			for name := range rubyRuntimes {
				if name == removed || strings.HasPrefix(name, removed+"/") || removed == "." {
					delete(rubyRuntimes, name)
				}
			}
		}
		for name, target := range change.nodeLinks {
			if target == "" {
				delete(nodePackageLinks, name)
			} else {
				nodePackageLinks[name] = target
			}
		}
		for name, data := range change.python {
			pythonMetadata[name] = databaseState{data: data, layer: layer.Digest}
		}
		eggRequirementNames := make([]string, 0, len(change.pythonEggRequirements))
		for name := range change.pythonEggRequirements {
			eggRequirementNames = append(eggRequirementNames, name)
		}
		sort.Strings(eggRequirementNames)
		for _, name := range eggRequirementNames {
			state := change.pythonEggRequirements[name]
			pythonEggRequirementsBytes -= len(pythonEggRequirements[name].data)
			pythonEggRequirementsLines -= pythonEggRequirements[name].lines
			if pythonEggRequirementsBytes+len(state.data) > maxPythonEggRequirementsTotal || pythonEggRequirementsLines+state.lines > maxPythonEggRequirementsLinesTotal {
				state.data = nil
				state.status = "limited"
				state.lines = 0
			} else {
				pythonEggRequirementsBytes += len(state.data)
				pythonEggRequirementsLines += state.lines
			}
			state.layer = layer.Digest
			pythonEggRequirements[name] = state
		}
		for name, data := range change.pipVendor {
			pipVendor[name] = databaseState{data: data, layer: layer.Digest}
		}
		for name, state := range change.composerInstalled {
			state.layer = layer.Digest
			composerInstalled[name] = state
		}
		composerPackageNames := make([]string, 0, len(change.composerPackageManifests))
		for name := range change.composerPackageManifests {
			composerPackageNames = append(composerPackageNames, name)
		}
		sort.Strings(composerPackageNames)
		for _, name := range composerPackageNames {
			state := change.composerPackageManifests[name]
			if _, found := composerPackageManifests[name]; !found && len(composerPackageManifests) >= maxComposerPackageFiles {
				composerPackageLimited = true
				continue
			}
			state.layer = layer.Digest
			composerPackageManifests[name] = state
		}
		composerPackageLimited = composerPackageLimited || change.composerPackageLimited
		for name, state := range change.dotnetDeps {
			state.layer = layer.Digest
			dotnetDeps[name] = state
		}
		dotnetAssemblyNames := make([]string, 0, len(change.dotnetAssemblies))
		for name := range change.dotnetAssemblies {
			dotnetAssemblyNames = append(dotnetAssemblyNames, name)
		}
		sort.Strings(dotnetAssemblyNames)
		for _, name := range dotnetAssemblyNames {
			if _, found := dotnetAssemblies[name]; !found && len(dotnetAssemblies) >= maxDotnetAssemblyFiles {
				dotnetAssemblyLimited = true
				continue
			}
			state := change.dotnetAssemblies[name]
			state.layer = layer.Digest
			dotnetAssemblies[name] = state
		}
		dotnetAssemblyLimited = dotnetAssemblyLimited || change.dotnetAssemblyLimited
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
		for name, state := range change.rubyRuntimes {
			rubyRuntimes[name] = state
		}
		rubyRuntimeLimited = rubyRuntimeLimited || change.rubyRuntimeLimited
		if change.nodeRuntimeBinary != nil {
			nodeRuntimeBinary = change.nodeRuntimeBinary
		}
		if change.nodeRuntimeHeader != nil {
			nodeRuntimeHeader = change.nodeRuntimeHeader
		}
		if change.bunBinary != nil {
			bunBinary = change.bunBinary
		}
		if change.denoBinary != nil {
			denoBinary = change.denoBinary
		}
		if change.httpdBinary != nil {
			httpdBinary = change.httpdBinary
		}
		if change.haproxyBinary != nil {
			haproxyBinary = change.haproxyBinary
		}
		if change.memcachedBinary != nil {
			memcachedBinary = change.memcachedBinary
		}
		if change.postgresBinary != nil {
			postgresBinary = change.postgresBinary
		}
		if change.redisBinary != nil {
			redisBinary = change.redisBinary
		}
		if len(pythonMetadata) > maxPythonMetadataFiles {
			return model.Document{}, errors.New("OCI image has too many installed Python metadata files")
		}
		if len(pythonEggRequirements) > maxPythonMetadataFiles {
			return model.Document{}, errors.New("OCI image has too many installed Python egg-info requirements files")
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
		if len(composerInstalled) > maxComposerInstalledFiles {
			return model.Document{}, errors.New("OCI image has too many Composer installed manifests")
		}
		if len(dotnetDeps) > maxDotnetDepsFiles {
			return model.Document{}, errors.New("OCI image has too many .NET deps manifests")
		}
		dotnetBytes := 0
		for _, state := range dotnetDeps {
			dotnetBytes += len(state.data)
		}
		if dotnetBytes > maxDotnetDepsTotal {
			return model.Document{}, errors.New("OCI image .NET deps manifests exceeded size limit")
		}
		composerBytes := 0
		for _, state := range composerInstalled {
			composerBytes += len(state.data)
		}
		if composerBytes > maxComposerInstalledTotal {
			return model.Document{}, errors.New("OCI image Composer installed manifests exceeded size limit")
		}
		if len(nodeMetadata) > maxNodeMetadataFiles {
			return model.Document{}, errors.New("OCI image has too many installed Node package manifests")
		}
		if len(nodePackageLinks) > maxNodePackageLinks {
			return model.Document{}, errors.New("OCI image has too many Node package links")
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
		if len(rubyRuntimes) > maxRubyRuntimeFiles {
			return model.Document{}, errors.New("OCI image has too many Ruby runtime library records")
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
	nodeMetadataPaths := map[string]bool{}
	for name := range nodeMetadata {
		nodeMetadataPaths[name] = true
	}
	nodeAliases, nodeLinkIssues := resolveNodePackageLinks(nodePackageLinks, nodeMetadataPaths)
	if installedDatabases == 0 && len(pythonMetadata) == 0 && len(pipVendor) == 0 && len(composerInstalled) == 0 && len(dotnetDeps) == 0 && len(nodeMetadata) == 0 && len(rubySpecs) == 0 && len(javaArchives) == 0 && len(goBinaries) == 0 && len(pythonRuntimes) == 0 && len(rubyRuntimes) == 0 && nodeRuntimeBinary == nil && nodeRuntimeHeader == nil && bunBinary == nil && denoBinary == nil && httpdBinary == nil && haproxyBinary == nil && memcachedBinary == nil && postgresBinary == nil && redisBinary == nil {
		doc := common.NewDocument(layout, project, "oci", nil)
		doc.Sources = sources
		doc.Coverage.Platforms = []string{platform}
		doc.Coverage.GraphState = "unknown"
		doc.Coverage.OriginState = "unknown"
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "os_package_database_not_found", Name: "dpkg,apk,rpm"}, model.Issue{Code: "image_language_packages_unscanned"})
		doc.Coverage.Issues = append(doc.Coverage.Issues, nodeLinkIssues...)
		if goScanLimited {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "go_binary_scan_limited"})
		}
		if pythonRuntimeLimited {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "python_runtime_scan_limited"})
		}
		if rubyRuntimeLimited {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "ruby_runtime_scan_limited"})
		}
		common.Finalize(&doc)
		doc.Coverage.GraphState = "unknown"
		return doc, nil
	}
	doc := common.NewDocument(layout, project, "oci", nil)
	doc.Sources = sources
	doc.Coverage.Platforms = []string{platform}
	doc.Coverage.Issues = append(doc.Coverage.Issues, nodeLinkIssues...)
	if goScanLimited {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "go_binary_scan_limited"})
	}
	if pythonRuntimeLimited {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "python_runtime_scan_limited"})
	}
	if rubyRuntimeLimited {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "ruby_runtime_scan_limited"})
	}
	if composerPackageLimited {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "composer_package_manifest_scan_limited"})
	}
	if installedDatabases == 0 {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "os_package_database_not_found", Name: "dpkg,apk,rpm"})
	}
	if _, textFound := databases[apkInstalledPath]; textFound {
		if _, binaryFound := databases[apkInstalledADBPath]; binaryFound {
			return model.Document{}, errors.New("OCI image has multiple APK databases; active database is ambiguous")
		}
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
		} else if name == apkInstalledPath || name == apkInstalledADBPath {
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
		record := python.InstalledRecord{Component: installed.Components[0], Metadata: state.data, MetadataPath: name}
		doc.Components = append(doc.Components, installed.Components...)
		doc.Edges = append(doc.Edges, installed.Edges...)
		doc.Origins = append(doc.Origins, installed.Origins...)
		doc.Development = append(doc.Development, installed.Development...)
		for _, issue := range installed.Coverage.Issues {
			if issue.Code != "declared_dependencies_unresolved" {
				doc.Coverage.Issues = append(doc.Coverage.Issues, issue)
			}
		}
		if strings.HasSuffix(name, ".egg-info/PKG-INFO") {
			requirementsPath := path.Join(path.Dir(name), "requires.txt")
			if requirements, found := pythonEggRequirements[requirementsPath]; found {
				if requirements.status != "" {
					doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "python_egg_requirements_unscanned", Name: installed.Components[0].Name})
				} else {
					hash := sha256.Sum256(requirements.data)
					record.EggRequirements = requirements.data
					record.EggRequirementsEvidence = model.Evidence{Collector: "python-egg-info", InputPath: "oci:" + requirements.layer + "!/" + requirementsPath, InputDigest: "sha256:" + hex.EncodeToString(hash[:]), Method: "installed-requirements"}
				}
			}
		}
		installedRecords = append(installedRecords, record)
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
	composerNames := make([]string, 0, len(composerInstalled))
	for name := range composerInstalled {
		composerNames = append(composerNames, name)
	}
	sort.Strings(composerNames)
	for _, name := range composerNames {
		state := composerInstalled[name]
		if state.status != "" {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "composer_installed_metadata_" + state.status, Name: name})
			continue
		}
		evidencePath := "oci:" + state.layer + "!/" + name
		installed, err := composer.CollectInstalled(state.data, evidencePath, project, name)
		if err != nil {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "composer_installed_metadata_invalid", Name: name})
			continue
		}
		verifyComposerPackageManifests(&installed, name, state.data, composerPackageManifests)
		doc.Components = append(doc.Components, installed.Components...)
		doc.Edges = append(doc.Edges, installed.Edges...)
		doc.Coverage.Issues = append(doc.Coverage.Issues, installed.Coverage.Issues...)
	}
	dotnetNames := make([]string, 0, len(dotnetDeps))
	for name := range dotnetDeps {
		dotnetNames = append(dotnetNames, name)
	}
	sort.Strings(dotnetNames)
	assemblyUsers := map[string]map[string]bool{}
	installedDotnet := map[string]model.Document{}
	for _, manifestPath := range dotnetNames {
		state := dotnetDeps[manifestPath]
		if state.status != "" {
			continue
		}
		installed, err := nuget.CollectInstalledDeps(state.data, "oci:"+state.layer+"!/"+manifestPath, project, manifestPath)
		if err != nil {
			continue
		}
		installedDotnet[manifestPath] = installed
		candidatesByIdentity := nuget.RuntimeAssemblyCandidates(state.data, manifestPath)
		for _, component := range installed.Components {
			identity := strings.ToLower(component.Name + "/" + component.Version)
			candidates := candidatesByIdentity[identity]
			for _, candidate := range candidates {
				if assemblyUsers[candidate.Path] == nil {
					assemblyUsers[candidate.Path] = map[string]bool{}
				}
				assemblyUsers[candidate.Path][manifestPath+"\x00"+identity] = true
			}
		}
	}
	for _, name := range dotnetNames {
		state := dotnetDeps[name]
		if state.status != "" {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "dotnet_deps_metadata_" + state.status, Name: name})
			continue
		}
		installed, found := installedDotnet[name]
		if !found {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "dotnet_deps_metadata_invalid", Name: name})
			continue
		}
		verifyDotnetRuntimeAssemblies(&installed, state.data, name, dotnetAssemblies, assemblyUsers)
		doc.Components = append(doc.Components, installed.Components...)
		doc.Edges = append(doc.Edges, installed.Edges...)
		doc.Coverage.Issues = append(doc.Coverage.Issues, installed.Coverage.Issues...)
	}
	if dotnetAssemblyLimited && len(dotnetDeps) > 0 {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "dotnet_runtime_assembly_scan_limited"})
	}
	nodeNames := make([]string, 0, len(nodeMetadata))
	for name := range nodeMetadata {
		nodeNames = append(nodeNames, name)
	}
	sort.Strings(nodeNames)
	var installedNodeRecords []npm.InstalledRecord
	reachableStore := map[string]bool{}
	for _, physical := range nodeAliases {
		reachableStore[physical] = true
	}
	for _, name := range nodeNames {
		if npm.IsPnpmStorePackagePath(name) && !reachableStore[name] {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "node_pnpm_store_unlinked", Name: name})
			continue
		}
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
	npm.LinkInstalledDependencies(&doc, installedNodeRecords, nodeAliases)
	rubyNames := make([]string, 0, len(rubySpecs))
	for name := range rubySpecs {
		rubyNames = append(rubyNames, name)
	}
	sort.Strings(rubyNames)
	rubyInstalled := false
	rubyRecords := make([]rubyInstalledRecord, 0, len(rubyNames))
	for _, name := range rubyNames {
		state := rubySpecs[name]
		evidencePath := "oci:" + state.layer + "!/" + name
		installed, err := inspectInstalledRubySpec(state.data, evidencePath, project, name)
		if err != nil {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "ruby_installed_spec_invalid", Name: name})
			continue
		}
		rubyInstalled = true
		rubyRecords = append(rubyRecords, rubyInstalledRecord{component: installed.Components[0], metadata: state.data, metadataPath: name})
		doc.Components = append(doc.Components, installed.Components...)
		doc.Edges = append(doc.Edges, installed.Edges...)
	}
	if rubyInstalled {
		linkInstalledRubyDependencies(&doc, rubyRecords)
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "ruby_installed_activation_unresolved"}, model.Issue{Code: "ruby_installed_origin_unavailable"})
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
	rubyRuntimeNames := make([]string, 0, len(rubyRuntimes))
	for name := range rubyRuntimes {
		rubyRuntimeNames = append(rubyRuntimeNames, name)
	}
	sort.Strings(rubyRuntimeNames)
	for _, name := range rubyRuntimeNames {
		state := rubyRuntimes[name]
		if state.status != "" {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "ruby_runtime_" + state.status, Name: name})
			continue
		}
		installed := state.document
		doc.Components = append(doc.Components, installed.Components...)
		doc.Edges = append(doc.Edges, installed.Edges...)
		doc.Coverage.Issues = append(doc.Coverage.Issues, installed.Coverage.Issues...)
	}
	if postgresBinary != nil {
		if postgresBinary.status != "" {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "postgres_runtime_" + postgresBinary.status, Name: postgresBinaryPath})
		} else {
			installed := postgresBinary.document
			doc.Components = append(doc.Components, installed.Components...)
			doc.Edges = append(doc.Edges, installed.Edges...)
			doc.Coverage.Issues = append(doc.Coverage.Issues, installed.Coverage.Issues...)
		}
	}
	if redisBinary != nil {
		if redisBinary.status != "" {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "redis_runtime_" + redisBinary.status, Name: redisBinaryPath})
		} else {
			installed := redisBinary.document
			doc.Components = append(doc.Components, installed.Components...)
			doc.Edges = append(doc.Edges, installed.Edges...)
			doc.Coverage.Issues = append(doc.Coverage.Issues, installed.Coverage.Issues...)
		}
	}
	if bunBinary != nil {
		if bunBinary.status != "" {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "bun_runtime_" + bunBinary.status, Name: bunBinaryPath})
		} else {
			installed := bunBinary.document
			doc.Components = append(doc.Components, installed.Components...)
			doc.Edges = append(doc.Edges, installed.Edges...)
			doc.Coverage.Issues = append(doc.Coverage.Issues, installed.Coverage.Issues...)
		}
	}
	if denoBinary != nil {
		if denoBinary.status != "" {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "deno_runtime_" + denoBinary.status, Name: denoBinaryPath})
		} else {
			installed := denoBinary.document
			doc.Components = append(doc.Components, installed.Components...)
			doc.Edges = append(doc.Edges, installed.Edges...)
			doc.Coverage.Issues = append(doc.Coverage.Issues, installed.Coverage.Issues...)
		}
	}
	if httpdBinary != nil {
		if httpdBinary.status != "" {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "httpd_server_" + httpdBinary.status, Name: httpdBinaryPath})
		} else {
			installed := httpdBinary.document
			doc.Components = append(doc.Components, installed.Components...)
			doc.Edges = append(doc.Edges, installed.Edges...)
			doc.Coverage.Issues = append(doc.Coverage.Issues, installed.Coverage.Issues...)
		}
	}
	if haproxyBinary != nil {
		if haproxyBinary.status != "" {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "haproxy_server_" + haproxyBinary.status, Name: haproxyBinaryPath})
		} else {
			installed := haproxyBinary.document
			doc.Components = append(doc.Components, installed.Components...)
			doc.Edges = append(doc.Edges, installed.Edges...)
			doc.Coverage.Issues = append(doc.Coverage.Issues, installed.Coverage.Issues...)
		}
	}
	if memcachedBinary != nil {
		if memcachedBinary.status != "" {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "memcached_server_" + memcachedBinary.status, Name: memcachedBinaryPath})
		} else {
			installed := memcachedBinary.document
			doc.Components = append(doc.Components, installed.Components...)
			doc.Edges = append(doc.Edges, installed.Edges...)
			doc.Coverage.Issues = append(doc.Coverage.Issues, installed.Coverage.Issues...)
		}
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
	files                    map[string]databaseChange
	python                   map[string][]byte
	pythonEggRequirements    map[string]pythonEggRequirementsState
	pipVendor                map[string][]byte
	composerInstalled        map[string]composerInstalledState
	composerPackageManifests map[string]composerPackageManifestState
	composerPackageLimited   bool
	dotnetDeps               map[string]dotnetDepsState
	dotnetAssemblies         map[string]dotnetAssemblyState
	dotnetAssemblyLimited    bool
	node                     map[string][]byte
	nodeLinks                map[string]string
	rubySpecs                map[string][]byte
	java                     map[string]javaArchiveState
	goBinaries               map[string]goBinaryState
	goLimited                bool
	bunBinary                *bunBinaryState
	denoBinary               *denoBinaryState
	httpdBinary              *httpdBinaryState
	haproxyBinary            *haproxyBinaryState
	memcachedBinary          *memcachedBinaryState
	postgresBinary           *postgresBinaryState
	redisBinary              *redisBinaryState
	pythonRuntimes           map[string]pythonRuntimeState
	pythonRuntimeLimited     bool
	rubyRuntimes             map[string]rubyRuntimeState
	rubyRuntimeLimited       bool
	nodeRuntimeBinary        *nodeRuntimeBinaryState
	nodeRuntimeHeader        *nodeRuntimeHeaderState
	whiteouts                []string
}

func scanLayer(layout string, item descriptor, diffID string, relevantLanguagePaths map[string]bool, existingNodeLinks map[string]string, project, architecture string) (layerChange, string, error) {
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
	change := layerChange{files: map[string]databaseChange{}, python: map[string][]byte{}, pythonEggRequirements: map[string]pythonEggRequirementsState{}, pipVendor: map[string][]byte{}, composerInstalled: map[string]composerInstalledState{}, composerPackageManifests: map[string]composerPackageManifestState{}, dotnetDeps: map[string]dotnetDepsState{}, dotnetAssemblies: map[string]dotnetAssemblyState{}, node: map[string][]byte{}, nodeLinks: map[string]string{}, rubySpecs: map[string][]byte{}, java: map[string]javaArchiveState{}, goBinaries: map[string]goBinaryState{}, pythonRuntimes: map[string]pythonRuntimeState{}, rubyRuntimes: map[string]rubyRuntimeState{}}
	seenDatabase := map[string]bool{}
	parentReplaced := map[string]bool{}
	nonDirectoryPaths := map[string]bool{}
	entries := 0
	pythonBytes := 0
	pythonEggBytes := 0
	pythonEggLines := 0
	pipVendorBytes := 0
	composerInstalledBytes := 0
	composerPackageBytes := 0
	dotnetDepsBytes := 0
	dotnetAssemblyBytes := 0
	nodeBytes := 0
	rubyBytes := 0
	javaBytes := 0
	goBytes := 0
	goFiles := 0
	pythonRuntimeBytes := 0
	rubyRuntimeBytes := 0
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
		if _, found := existingNodeLinks[name]; found {
			change.nodeLinks[name] = ""
		}
		if _, found := change.nodeLinks[name]; found {
			change.nodeLinks[name] = ""
		}
		if header.Typeflag == tar.TypeSymlink && npm.IsInstalledPackageLinkPath(name) {
			change.nodeLinks[name] = header.Linkname
			if header.Linkname == "" {
				change.nodeLinks[name] = "\x00" // Retain the invalid link for coverage reporting.
			}
			if len(change.nodeLinks) > maxNodePackageLinks {
				return layerChange{}, "", errors.New("OCI layer has too many Node package links")
			}
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
		if header.Typeflag != tar.TypeDir && python.IsInstalledEggRequirementsPath(name) {
			if _, duplicate := change.pythonEggRequirements[name]; duplicate {
				return layerChange{}, "", fmt.Errorf("duplicate OCI installed Python egg-info requirements entry: %s", name)
			}
			state := pythonEggRequirementsState{}
			if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA {
				state.status = "unsupported"
			} else if header.Size > python.MaxEggRequirementsBytes {
				state.status = "oversized"
			} else {
				data, err := io.ReadAll(io.LimitReader(reader, python.MaxEggRequirementsBytes+1))
				if err != nil || len(data) != int(header.Size) {
					return layerChange{}, "", errors.New("invalid OCI installed Python egg-info requirements entry")
				}
				lines := strings.Count(string(data), "\n")
				if len(data) == 0 || data[len(data)-1] != '\n' {
					lines++
				}
				if lines > python.MaxEggRequirementsLines || pythonEggBytes+len(data) > maxPythonEggRequirementsTotal || pythonEggLines+lines > maxPythonEggRequirementsLinesTotal {
					state.status = "limited"
				} else {
					state.data = data
					state.lines = lines
					pythonEggBytes += len(data)
					pythonEggLines += lines
				}
			}
			change.pythonEggRequirements[name] = state
			if len(change.pythonEggRequirements) > maxPythonMetadataFiles {
				return layerChange{}, "", errors.New("OCI layer has too many installed Python egg-info requirements files")
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
		if composer.IsInstalledManifestPath(name) {
			if _, duplicate := change.composerInstalled[name]; duplicate {
				return layerChange{}, "", fmt.Errorf("duplicate OCI Composer installed manifest entry: %s", name)
			}
			state := composerInstalledState{}
			switch {
			case header.Typeflag == tar.TypeSymlink || header.Typeflag == tar.TypeLink:
				state.status = "link_unresolved"
			case header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA:
				state.status = "unsupported"
			case header.Size > composer.MaxInstalledJSONBytes:
				state.status = "oversized"
			default:
				data, err := io.ReadAll(io.LimitReader(reader, composer.MaxInstalledJSONBytes+1))
				if err != nil || len(data) != int(header.Size) {
					return layerChange{}, "", errors.New("invalid OCI Composer installed manifest entry")
				}
				state.data = data
				composerInstalledBytes += len(data)
			}
			change.composerInstalled[name] = state
			if len(change.composerInstalled) > maxComposerInstalledFiles || composerInstalledBytes > maxComposerInstalledTotal {
				return layerChange{}, "", errors.New("OCI layer has too much Composer installed metadata")
			}
			continue
		}
		if path.Base(name) == "composer.json" {
			if _, duplicate := change.composerPackageManifests[name]; duplicate {
				return layerChange{}, "", fmt.Errorf("duplicate OCI Composer package manifest entry: %s", name)
			}
			state := composerPackageManifestState{}
			switch {
			case header.Typeflag == tar.TypeSymlink || header.Typeflag == tar.TypeLink:
				state.status = "link_unresolved"
			case header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA:
				state.status = "unsupported"
			case header.Size > maxComposerPackageJSONBytes:
				state.status = "oversized"
			case int64(composerPackageBytes)+header.Size > maxComposerPackageLayerBytes:
				state.status = "scan_limited"
				change.composerPackageLimited = true
			default:
				data, err := io.ReadAll(io.LimitReader(reader, maxComposerPackageJSONBytes+1))
				if err != nil || len(data) != int(header.Size) {
					return layerChange{}, "", errors.New("invalid OCI Composer package manifest entry")
				}
				composerPackageBytes += len(data)
				state = inspectComposerPackageManifest(data)
			}
			if len(change.composerPackageManifests) < maxComposerPackageFiles {
				change.composerPackageManifests[name] = state
			} else {
				change.composerPackageLimited = true
			}
			continue
		}
		if nuget.IsDepsManifestPath(name) {
			if _, duplicate := change.dotnetDeps[name]; duplicate {
				return layerChange{}, "", fmt.Errorf("duplicate OCI .NET deps manifest entry: %s", name)
			}
			state := dotnetDepsState{}
			switch {
			case header.Typeflag == tar.TypeSymlink || header.Typeflag == tar.TypeLink:
				state.status = "link_unresolved"
			case header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA:
				state.status = "unsupported"
			case header.Size > nuget.MaxDepsJSONBytes:
				state.status = "oversized"
			default:
				data, err := io.ReadAll(io.LimitReader(reader, nuget.MaxDepsJSONBytes+1))
				if err != nil || len(data) != int(header.Size) {
					return layerChange{}, "", errors.New("invalid OCI .NET deps manifest entry")
				}
				state.data = data
				dotnetDepsBytes += len(data)
			}
			change.dotnetDeps[name] = state
			if len(change.dotnetDeps) > maxDotnetDepsFiles || dotnetDepsBytes > maxDotnetDepsTotal {
				return layerChange{}, "", errors.New("OCI layer has too much .NET deps metadata")
			}
			continue
		}
		if strings.HasSuffix(strings.ToLower(path.Base(name)), ".dll") {
			if _, found := change.dotnetAssemblies[name]; !found && len(change.dotnetAssemblies) >= maxDotnetAssemblyFiles {
				change.dotnetAssemblyLimited = true
			} else {
				state := dotnetAssemblyState{}
				switch {
				case header.Typeflag == tar.TypeSymlink || header.Typeflag == tar.TypeLink:
					state.status = "link_unresolved"
				case header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA:
					state.status = "unsupported"
				case header.Size > maxDotnetAssemblyBytes:
					state.status = "oversized"
				case int64(dotnetAssemblyBytes)+header.Size > maxDotnetAssemblyLayerBytes:
					state.status = "scan_limited"
					change.dotnetAssemblyLimited = true
				default:
					data, err := io.ReadAll(io.LimitReader(reader, maxDotnetAssemblyBytes+1))
					if err != nil || len(data) != int(header.Size) {
						return layerChange{}, "", errors.New("invalid OCI .NET assembly entry")
					}
					dotnetAssemblyBytes += len(data)
					state = inspectDotnetAssembly(data)
				}
				change.dotnetAssemblies[name] = state
			}
			if relevantLanguagePaths[name] && header.Typeflag != tar.TypeDir {
				change.whiteouts = append(change.whiteouts, name)
			}
			continue
		}
		if header.Typeflag != tar.TypeDir && python.IsInstalledMetadataPath(name) {
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
		if isRubyRuntimeLibraryPath(name) && (header.Typeflag == tar.TypeReg || header.Typeflag == tar.TypeRegA) {
			switch {
			case header.Size > maxRubyRuntimeBytes:
				change.rubyRuntimes[name] = rubyRuntimeState{status: "oversized"}
			case int64(rubyRuntimeBytes)+header.Size > maxRubyRuntimeLayerBytes:
				change.rubyRuntimeLimited = true
			default:
				data, err := io.ReadAll(io.LimitReader(reader, maxRubyRuntimeBytes+1))
				if err != nil || len(data) != int(header.Size) {
					return layerChange{}, "", errors.New("invalid OCI Ruby runtime library entry")
				}
				rubyRuntimeBytes += len(data)
				input := "oci:" + item.Digest + "!/" + name
				runtimeDoc, err := inspectRubyRuntimeLibrary(data, input, project, name)
				if err != nil {
					change.rubyRuntimes[name] = rubyRuntimeState{status: "invalid"}
				} else {
					change.rubyRuntimes[name] = rubyRuntimeState{document: runtimeDoc}
				}
			}
			if relevantLanguagePaths[name] {
				change.whiteouts = append(change.whiteouts, name)
			}
			continue
		}
		if name == postgresBinaryPath && (header.Typeflag == tar.TypeReg || header.Typeflag == tar.TypeRegA) {
			if change.postgresBinary != nil {
				return layerChange{}, "", errors.New("duplicate OCI PostgreSQL executable entry")
			}
			if header.Size > maxPostgresBinaryBytes {
				change.postgresBinary = &postgresBinaryState{status: "oversized"}
			} else {
				data, err := io.ReadAll(io.LimitReader(reader, maxPostgresBinaryBytes+1))
				if err != nil || len(data) != int(header.Size) {
					return layerChange{}, "", errors.New("invalid OCI PostgreSQL executable entry")
				}
				input := "oci:" + item.Digest + "!/" + name
				binaryDoc, err := inspectPostgresBinary(data, input, project, name)
				if err != nil {
					change.postgresBinary = &postgresBinaryState{status: "invalid"}
				} else {
					change.postgresBinary = &postgresBinaryState{document: binaryDoc}
				}
			}
			change.whiteouts = append(change.whiteouts, name)
			continue
		}
		if name == redisBinaryPath && (header.Typeflag == tar.TypeReg || header.Typeflag == tar.TypeRegA) {
			if change.redisBinary != nil {
				return layerChange{}, "", errors.New("duplicate OCI Redis executable entry")
			}
			if header.Size > maxRedisBinaryBytes {
				change.redisBinary = &redisBinaryState{status: "oversized"}
			} else {
				data, err := io.ReadAll(io.LimitReader(reader, maxRedisBinaryBytes+1))
				if err != nil || len(data) != int(header.Size) {
					return layerChange{}, "", errors.New("invalid OCI Redis executable entry")
				}
				input := "oci:" + item.Digest + "!/" + name
				binaryDoc, err := inspectRedisBinary(data, input, project, name)
				if err != nil {
					change.redisBinary = &redisBinaryState{status: "invalid"}
				} else {
					change.redisBinary = &redisBinaryState{document: binaryDoc}
				}
			}
			change.whiteouts = append(change.whiteouts, name)
			continue
		}
		if name == bunBinaryPath && (header.Typeflag == tar.TypeReg || header.Typeflag == tar.TypeRegA) {
			if change.bunBinary != nil {
				return layerChange{}, "", errors.New("duplicate OCI Bun executable entry")
			}
			if header.Size > maxBunBinaryBytes {
				change.bunBinary = &bunBinaryState{status: "oversized"}
			} else {
				input := "oci:" + item.Digest + "!/" + name
				binaryDoc, err := inspectBunBinary(reader, header.Size, input, project)
				if errors.Is(err, errBunBinaryIO) {
					return layerChange{}, "", err
				}
				if err != nil {
					change.bunBinary = &bunBinaryState{status: "invalid"}
				} else {
					change.bunBinary = &bunBinaryState{document: binaryDoc}
				}
			}
			change.whiteouts = append(change.whiteouts, name)
			continue
		}
		if name == denoBinaryPath && (header.Typeflag == tar.TypeReg || header.Typeflag == tar.TypeRegA) {
			if change.denoBinary != nil {
				return layerChange{}, "", errors.New("duplicate OCI Deno executable entry")
			}
			if header.Size > maxDenoBinaryBytes {
				change.denoBinary = &denoBinaryState{status: "oversized"}
			} else {
				input := "oci:" + item.Digest + "!/" + name
				binaryDoc, err := inspectDenoBinary(reader, header.Size, input, project, architecture)
				if errors.Is(err, errDenoBinaryIO) {
					return layerChange{}, "", err
				}
				if err != nil {
					change.denoBinary = &denoBinaryState{status: "invalid"}
				} else {
					change.denoBinary = &denoBinaryState{document: binaryDoc}
				}
			}
			change.whiteouts = append(change.whiteouts, name)
			continue
		}
		if name == httpdBinaryPath && (header.Typeflag == tar.TypeReg || header.Typeflag == tar.TypeRegA) {
			if change.httpdBinary != nil {
				return layerChange{}, "", errors.New("duplicate OCI httpd executable entry")
			}
			if header.Size > maxHTTPDBinaryBytes {
				change.httpdBinary = &httpdBinaryState{status: "oversized"}
			} else {
				data, err := io.ReadAll(io.LimitReader(reader, maxHTTPDBinaryBytes+1))
				if err != nil || len(data) != int(header.Size) {
					return layerChange{}, "", errors.New("invalid OCI httpd executable entry")
				}
				input := "oci:" + item.Digest + "!/" + name
				binaryDoc, err := inspectHTTPDBinary(data, input, project, architecture)
				if err != nil {
					change.httpdBinary = &httpdBinaryState{status: "invalid"}
				} else {
					change.httpdBinary = &httpdBinaryState{document: binaryDoc}
				}
			}
			change.whiteouts = append(change.whiteouts, name)
			continue
		}
		if name == haproxyBinaryPath && (header.Typeflag == tar.TypeReg || header.Typeflag == tar.TypeRegA) {
			if change.haproxyBinary != nil {
				return layerChange{}, "", errors.New("duplicate OCI HAProxy executable entry")
			}
			if header.Size < 0 {
				return layerChange{}, "", errors.New("invalid OCI HAProxy executable size")
			}
			if header.Size > maxHAProxyBinaryBytes {
				change.haproxyBinary = &haproxyBinaryState{status: "oversized"}
			} else {
				data := make([]byte, int(header.Size))
				if _, err := io.ReadFull(reader, data); err != nil {
					return layerChange{}, "", errors.New("invalid OCI HAProxy executable entry")
				}
				input := "oci:" + item.Digest + "!/" + name
				binaryDoc, err := inspectHAProxyBinary(data, input, project, architecture)
				if err != nil {
					change.haproxyBinary = &haproxyBinaryState{status: "invalid"}
				} else {
					change.haproxyBinary = &haproxyBinaryState{document: binaryDoc}
				}
			}
			change.whiteouts = append(change.whiteouts, name)
			continue
		}
		if name == memcachedBinaryPath && (header.Typeflag == tar.TypeReg || header.Typeflag == tar.TypeRegA) {
			if change.memcachedBinary != nil {
				return layerChange{}, "", errors.New("duplicate OCI Memcached executable entry")
			}
			if header.Size > maxMemcachedBinaryBytes {
				change.memcachedBinary = &memcachedBinaryState{status: "oversized"}
			} else {
				data, err := io.ReadAll(io.LimitReader(reader, maxMemcachedBinaryBytes+1))
				if err != nil || len(data) != int(header.Size) {
					return layerChange{}, "", errors.New("invalid OCI Memcached executable entry")
				}
				input := "oci:" + item.Digest + "!/" + name
				binaryDoc, err := inspectMemcachedBinary(data, input, project, architecture)
				if err != nil {
					change.memcachedBinary = &memcachedBinaryState{status: "invalid"}
				} else {
					change.memcachedBinary = &memcachedBinaryState{document: binaryDoc}
				}
			}
			change.whiteouts = append(change.whiteouts, name)
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
				case header.Size > maxGoBinaryDiskBytes:
					hasMagic, err := hasGoBuildInfoMagic(reader, header.Size-4)
					if err != nil {
						return layerChange{}, "", err
					}
					if hasMagic {
						change.goBinaries[name] = goBinaryState{status: "oversized"}
					}
				case goFiles > maxGoBinaryFiles || int64(goBytes)+header.Size > maxGoBinaryLayerBytes:
					change.goLimited = true
				case header.Size > maxGoBinaryBytes:
					input := "oci:" + item.Digest + "!/" + name
					binaryDoc, recognized, err := inspectLargeGoBinary(magic[:], reader, header.Size, input, project, name)
					if errors.Is(err, errGoBinaryIO) {
						return layerChange{}, "", err
					}
					goBytes += int(header.Size)
					if err != nil {
						status := "invalid"
						if errors.Is(err, errGoBinaryModuleLimit) {
							status = "scan_limited"
						}
						change.goBinaries[name] = goBinaryState{status: status}
					} else if recognized {
						change.goBinaries[name] = goBinaryState{document: binaryDoc}
					}
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
	for name := range change.composerInstalled {
		for ancestor := path.Dir(name); ancestor != "."; ancestor = path.Dir(ancestor) {
			if nonDirectoryPaths[ancestor] {
				return layerChange{}, "", fmt.Errorf("OCI layer contains Composer metadata beneath a non-directory entry: %s", ancestor)
			}
		}
	}
	for name := range change.composerPackageManifests {
		for ancestor := path.Dir(name); ancestor != "."; ancestor = path.Dir(ancestor) {
			if nonDirectoryPaths[ancestor] {
				return layerChange{}, "", fmt.Errorf("OCI layer contains Composer package metadata beneath a non-directory entry: %s", ancestor)
			}
		}
	}
	for name := range change.dotnetAssemblies {
		for ancestor := path.Dir(name); ancestor != "."; ancestor = path.Dir(ancestor) {
			if nonDirectoryPaths[ancestor] {
				return layerChange{}, "", fmt.Errorf("OCI layer contains .NET assembly beneath a non-directory entry: %s", ancestor)
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
	for name := range change.rubyRuntimes {
		for ancestor := path.Dir(name); ancestor != "."; ancestor = path.Dir(ancestor) {
			if nonDirectoryPaths[ancestor] {
				return layerChange{}, "", fmt.Errorf("OCI layer contains Ruby runtime library beneath a non-directory entry: %s", ancestor)
			}
		}
	}
	if change.postgresBinary != nil {
		for ancestor := path.Dir(postgresBinaryPath); ancestor != "."; ancestor = path.Dir(ancestor) {
			if nonDirectoryPaths[ancestor] {
				return layerChange{}, "", fmt.Errorf("OCI layer contains PostgreSQL executable beneath a non-directory entry: %s", ancestor)
			}
		}
	}
	if change.redisBinary != nil {
		for ancestor := path.Dir(redisBinaryPath); ancestor != "."; ancestor = path.Dir(ancestor) {
			if nonDirectoryPaths[ancestor] {
				return layerChange{}, "", fmt.Errorf("OCI layer contains Redis executable beneath a non-directory entry: %s", ancestor)
			}
		}
	}
	if change.bunBinary != nil {
		for ancestor := path.Dir(bunBinaryPath); ancestor != "."; ancestor = path.Dir(ancestor) {
			if nonDirectoryPaths[ancestor] {
				return layerChange{}, "", fmt.Errorf("OCI layer contains Bun executable beneath a non-directory entry: %s", ancestor)
			}
		}
	}
	if change.denoBinary != nil {
		for ancestor := path.Dir(denoBinaryPath); ancestor != "."; ancestor = path.Dir(ancestor) {
			if nonDirectoryPaths[ancestor] {
				return layerChange{}, "", fmt.Errorf("OCI layer contains Deno executable beneath a non-directory entry: %s", ancestor)
			}
		}
	}
	if change.httpdBinary != nil {
		for ancestor := path.Dir(httpdBinaryPath); ancestor != "."; ancestor = path.Dir(ancestor) {
			if nonDirectoryPaths[ancestor] {
				return layerChange{}, "", fmt.Errorf("OCI layer contains httpd executable beneath a non-directory entry: %s", ancestor)
			}
		}
	}
	if change.haproxyBinary != nil {
		for ancestor := path.Dir(haproxyBinaryPath); ancestor != "."; ancestor = path.Dir(ancestor) {
			if nonDirectoryPaths[ancestor] {
				return layerChange{}, "", fmt.Errorf("OCI layer contains HAProxy executable beneath a non-directory entry: %s", ancestor)
			}
		}
	}
	if change.memcachedBinary != nil {
		for ancestor := path.Dir(memcachedBinaryPath); ancestor != "."; ancestor = path.Dir(ancestor) {
			if nonDirectoryPaths[ancestor] {
				return layerChange{}, "", fmt.Errorf("OCI layer contains Memcached executable beneath a non-directory entry: %s", ancestor)
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
