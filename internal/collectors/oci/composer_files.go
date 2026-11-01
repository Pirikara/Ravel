package oci

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/Pirikara/Ravel/internal/collectors/composer"
	"github.com/Pirikara/Ravel/internal/model"
)

const (
	maxComposerPackageJSONBytes  = 1 << 20
	maxComposerPackageLayerBytes = 32 << 20
	maxComposerPackageFiles      = 20000
)

type composerPackageManifestState struct {
	name   string
	digest string
	layer  string
	status string
}

// A package-owned composer.json records a package name and content digest.
// Layer overlay handling decides whether that entry survives whiteouts. Other
// package files and the installed version remain unverified.
func inspectComposerPackageManifest(data []byte) composerPackageManifestState {
	var manifest struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil || manifest.Name == "" || len(manifest.Name) > 256 {
		return composerPackageManifestState{status: "invalid"}
	}
	hash := sha256.Sum256(data)
	return composerPackageManifestState{name: manifest.Name, digest: "sha256:" + hex.EncodeToString(hash[:])}
}

func verifyComposerPackageManifests(doc *model.Document, metadataPath string, installedData []byte, packages map[string]composerPackageManifestState) {
	paths := composer.InstalledPackageManifestPaths(installedData, metadataPath)
	for i := range doc.Components {
		component := &doc.Components[i]
		packageManifestPath := paths[strings.ToLower(component.Name)]
		if packageManifestPath == "" {
			continue
		}
		state, found := packages[packageManifestPath]
		if !found {
			continue
		}
		if state.status != "" {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "composer_package_manifest_" + state.status, Name: component.Name})
			continue
		}
		if !strings.EqualFold(state.name, component.Name) {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "composer_package_manifest_mismatch", Name: component.Name})
			continue
		}
		component.Evidence = append(component.Evidence, model.Evidence{
			Collector: "composer-package-manifest", InputPath: "oci:" + state.layer + "!/" + packageManifestPath,
			InputDigest: state.digest, Pointer: "/name", Method: "final-layer-file-record",
		})
	}
}
