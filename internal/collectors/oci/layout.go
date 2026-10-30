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
	"strings"

	"ravel/internal/collectors/common"
	"ravel/internal/collectors/dpkg"
	"ravel/internal/model"
)

const (
	maxMetadataBytes  = 8 << 20
	maxStatusBytes    = 128 << 20
	maxLayerBytes     = 2 << 30
	maxExpandedLayer  = 4 << 30
	maxLayerEntries   = 1000000
	maxImageLayers    = 128
	manifestMediaType = "application/vnd.oci.image.manifest.v1+json"
	indexMediaType    = "application/vnd.oci.image.index.v1+json"
	configMediaType   = "application/vnd.oci.image.config.v1+json"
	plainLayerType    = "application/vnd.oci.image.layer.v1.tar"
	gzipLayerType     = "application/vnd.oci.image.layer.v1.tar+gzip"
	plainNonDistType  = "application/vnd.oci.image.layer.nondistributable.v1.tar"
	gzipNonDistType   = "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip"
	statusPath        = "var/lib/dpkg/status"
)

var (
	sha256Digest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	platformName = regexp.MustCompile(`^[a-z0-9]+/[a-z0-9]+(?:/[a-z0-9._-]+)?$`)
)

type descriptor struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
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

// Collect reads an OCI image layout directory. It reconstructs the final
// dpkg status database across layers without extracting arbitrary image files.
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
		if err := collectManifests(layout, item, 0, seen, &manifests, &sources); err != nil {
			return model.Document{}, err
		}
	}
	if len(manifests) == 0 {
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
		if err := json.Unmarshal(manifestData, &manifest); err != nil || manifest.SchemaVersion != 2 || manifest.Config.MediaType != configMediaType || len(manifest.Layers) > maxImageLayers {
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
		if requestedPlatform == "" || requestedPlatform == platform {
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
	var status []byte
	statusLayer := ""
	for i, layer := range choice.layers {
		change, blobPath, err := scanLayer(layout, layer, choice.config.RootFS.DiffIDs[i])
		if err != nil {
			return model.Document{}, fmt.Errorf("OCI layer %d: %w", i, err)
		}
		sources = append(sources, blobPath)
		if change.deleted {
			status, statusLayer = nil, ""
		}
		if change.present {
			status, statusLayer = change.status, layer.Digest
		}
	}
	platform := choice.config.OS + "/" + choice.config.Architecture
	if choice.config.Variant != "" {
		platform += "/" + choice.config.Variant
	}
	if statusLayer == "" {
		doc := common.NewDocument(layout, project, "oci", nil)
		doc.Sources = sources
		doc.Coverage.Platforms = []string{platform}
		doc.Coverage.GraphState = "unknown"
		doc.Coverage.OriginState = "unknown"
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "os_package_database_not_found", Name: "dpkg"}, model.Issue{Code: "image_language_packages_unscanned"})
		common.Finalize(&doc)
		doc.Coverage.GraphState = "unknown"
		return doc, nil
	}
	evidencePath := "oci:" + statusLayer + "!/" + statusPath
	doc, err := dpkg.CollectBytes(status, evidencePath, project)
	if err != nil {
		return model.Document{}, fmt.Errorf("invalid dpkg database in OCI image: %w", err)
	}
	doc.Source = layout
	doc.Sources = sources
	doc.Coverage.Manager = "oci"
	doc.Coverage.Platforms = []string{platform}
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

func collectManifests(layout string, item descriptor, depth int, seen map[string]bool, out *[]descriptor, sources *[]string) error {
	if depth > 8 || len(*out) > 128 {
		return errors.New("OCI image index exceeds traversal limit")
	}
	if item.MediaType != manifestMediaType && item.MediaType != indexMediaType {
		return nil // indexes may contain artifact descriptors
	}
	if seen[item.Digest] {
		return nil
	}
	seen[item.Digest] = true
	if item.MediaType == manifestMediaType {
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
		if err := collectManifests(layout, child, depth+1, seen, out, sources); err != nil {
			return err
		}
	}
	return nil
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

type layerChange struct {
	deleted bool
	present bool
	status  []byte
}

func scanLayer(layout string, item descriptor, diffID string) (layerChange, string, error) {
	if item.MediaType != plainLayerType && item.MediaType != gzipLayerType && item.MediaType != plainNonDistType && item.MediaType != gzipNonDistType {
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
	if item.MediaType == gzipLayerType || item.MediaType == gzipNonDistType {
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
	change := layerChange{}
	statusSeen, parentReplaced, entries := false, false, 0
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
		base := path.Base(name)
		if strings.HasPrefix(base, ".wh.") {
			if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA || header.Size != 0 {
				return layerChange{}, "", errors.New("invalid OCI whiteout entry")
			}
			if base == ".wh." {
				return layerChange{}, "", errors.New("invalid OCI whiteout")
			}
			if base == ".wh..wh..opq" {
				if ancestorOfStatus(path.Dir(name)) {
					change.deleted = true
				}
			} else if ancestorOfStatus(path.Join(path.Dir(name), strings.TrimPrefix(base, ".wh."))) {
				change.deleted = true
			}
			continue
		}
		if name == statusPath {
			if statusSeen || header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA || header.Size > maxStatusBytes {
				return layerChange{}, "", errors.New("unsupported or duplicate OCI dpkg status entry")
			}
			statusSeen = true
			change.present = true
			change.status, err = io.ReadAll(io.LimitReader(reader, maxStatusBytes+1))
			if err != nil || len(change.status) > maxStatusBytes {
				return layerChange{}, "", errors.New("OCI dpkg status exceeded size limit")
			}
		} else if ancestorOfStatus(name) && header.Typeflag != tar.TypeDir {
			if header.Typeflag == tar.TypeSymlink || header.Typeflag == tar.TypeLink {
				return layerChange{}, "", errors.New("OCI dpkg path has an unsupported link")
			}
			change.deleted = true
			parentReplaced = true
		}
	}
	if parentReplaced && statusSeen {
		return layerChange{}, "", errors.New("OCI layer replaces dpkg parent directory and status together")
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
	if raw == "" || strings.HasPrefix(raw, "/") || strings.ContainsAny(raw, "\\\x00") {
		return "", errors.New("unsafe OCI layer path")
	}
	for _, segment := range strings.Split(raw, "/") {
		if segment == ".." {
			return "", errors.New("unsafe OCI layer path")
		}
	}
	return path.Clean(raw), nil
}

func ancestorOfStatus(candidate string) bool {
	return candidate == "." || candidate == statusPath || strings.HasPrefix(statusPath, candidate+"/")
}
