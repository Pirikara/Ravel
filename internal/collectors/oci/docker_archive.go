package oci

import (
	"archive/tar"
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

	"ravel/internal/model"
)

type dockerSaveManifest struct {
	Config string   `json:"Config"`
	Layers []string `json:"Layers"`
}

var dockerConfigHash = regexp.MustCompile(`^[0-9a-f]{64}\.json$`)

// collectLegacyDockerArchive converts one docker-save manifest into a
// temporary content-addressed OCI layout, then uses the same verified layer
// scanner as native OCI archives. Only referenced config and layer entries
// are copied; other archive contents are never extracted.
func collectLegacyDockerArchive(archive, project, platform string) (model.Document, error) {
	manifest, err := readDockerSaveManifest(archive)
	if err != nil {
		return model.Document{}, err
	}
	if len(manifest) != 1 {
		return model.Document{}, errors.New("Docker save archive must contain exactly one image")
	}
	selected := manifest[0]
	if len(selected.Layers) > maxImageLayers {
		return model.Document{}, errors.New("Docker save archive has too many layers")
	}
	expected := map[string]bool{}
	for _, raw := range append([]string{selected.Config}, selected.Layers...) {
		name, err := cleanTarPath(raw)
		if err != nil || name != raw || name == "." {
			return model.Document{}, errors.New("Docker save archive has an unsafe reference")
		}
		expected[name] = true
	}
	if selected.Config == "" || len(expected) == 0 {
		return model.Document{}, errors.New("Docker save archive lacks an image config")
	}
	temp, err := os.MkdirTemp("", "ravel-docker-layout-")
	if err != nil {
		return model.Document{}, err
	}
	defer os.RemoveAll(temp)
	blobDir := filepath.Join(temp, "blobs", "sha256")
	if err := os.MkdirAll(blobDir, 0o700); err != nil {
		return model.Document{}, err
	}
	file, err := os.Open(archive)
	if err != nil {
		return model.Document{}, err
	}
	defer file.Close()
	reader := tar.NewReader(file)
	seen := map[string]bool{}
	descriptors := map[string]descriptor{}
	var copied int64
	for entries := 0; ; entries++ {
		if entries >= maxArchiveEntries {
			return model.Document{}, errors.New("Docker save archive has too many entries")
		}
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return model.Document{}, err
		}
		name, err := cleanTarPath(header.Name)
		if err != nil {
			return model.Document{}, err
		}
		if !expected[name] {
			continue
		}
		if seen[name] || header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA {
			return model.Document{}, fmt.Errorf("duplicate or unsupported Docker save entry: %s", name)
		}
		seen[name] = true
		limit := int64(maxLayerBytes)
		mediaType := plainLayerType
		if name == selected.Config {
			limit = maxMetadataBytes
			mediaType = configMediaType
		}
		if header.Size < 0 || header.Size > limit || copied > maxExtractedBytes-header.Size {
			return model.Document{}, errors.New("Docker save extraction limit exceeded")
		}
		copied += header.Size
		entryFile, err := os.CreateTemp(temp, "entry-")
		if err != nil {
			return model.Document{}, err
		}
		hasher := sha256.New()
		_, copyErr := io.CopyN(io.MultiWriter(entryFile, hasher), reader, header.Size)
		closeErr := entryFile.Close()
		if copyErr != nil || closeErr != nil {
			_ = os.Remove(entryFile.Name())
			if copyErr != nil {
				return model.Document{}, copyErr
			}
			return model.Document{}, closeErr
		}
		digest := hex.EncodeToString(hasher.Sum(nil))
		if archiveBlobName.MatchString(name) && path.Base(name) != digest {
			_ = os.Remove(entryFile.Name())
			return model.Document{}, errors.New("Docker save content-addressed blob digest mismatch")
		}
		if name == selected.Config && !dockerConfigFilenameMatches(name, digest) {
			_ = os.Remove(entryFile.Name())
			return model.Document{}, errors.New("Docker save config filename digest mismatch")
		}
		blob := filepath.Join(blobDir, digest)
		if _, err := os.Stat(blob); errors.Is(err, os.ErrNotExist) {
			if err := os.Rename(entryFile.Name(), blob); err != nil {
				return model.Document{}, err
			}
		} else if err == nil {
			_ = os.Remove(entryFile.Name())
		} else {
			return model.Document{}, err
		}
		if mediaType == plainLayerType {
			probe, err := os.Open(blob)
			if err != nil {
				return model.Document{}, err
			}
			var prefix [2]byte
			_, readErr := io.ReadFull(probe, prefix[:])
			_ = probe.Close()
			if readErr == nil && prefix == [2]byte{0x1f, 0x8b} {
				mediaType = gzipLayerType
			}
		}
		descriptors[name] = descriptor{MediaType: mediaType, Digest: "sha256:" + digest, Size: header.Size}
	}
	for name := range expected {
		if !seen[name] {
			return model.Document{}, fmt.Errorf("Docker save archive lacks referenced entry: %s", name)
		}
	}
	layers := make([]descriptor, 0, len(selected.Layers))
	for _, name := range selected.Layers {
		if name == selected.Config {
			return model.Document{}, errors.New("Docker save config cannot also be a layer")
		}
		layers = append(layers, descriptors[name])
	}
	image := imageManifest{SchemaVersion: 2, Config: descriptors[selected.Config], Layers: layers}
	imageData, err := json.Marshal(image)
	if err != nil {
		return model.Document{}, err
	}
	imageDescriptor, err := writeDockerLayoutBlob(blobDir, imageData, manifestMediaType)
	if err != nil {
		return model.Document{}, err
	}
	indexData, err := json.Marshal(imageIndex{SchemaVersion: 2, Manifests: []descriptor{imageDescriptor}})
	if err != nil {
		return model.Document{}, err
	}
	if err := os.WriteFile(filepath.Join(temp, "oci-layout"), []byte(`{"imageLayoutVersion":"1.0.0"}`), 0o600); err != nil {
		return model.Document{}, err
	}
	if err := os.WriteFile(filepath.Join(temp, "index.json"), indexData, 0o600); err != nil {
		return model.Document{}, err
	}
	doc, err := Collect(temp, project, platform)
	if err != nil {
		return model.Document{}, err
	}
	doc.Source = archive
	doc.Sources = []string{archive}
	return doc, nil
}

func readDockerSaveManifest(archive string) ([]dockerSaveManifest, error) {
	file, err := os.Open(archive)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	reader := tar.NewReader(file)
	found := false
	var data []byte
	for entries := 0; ; entries++ {
		if entries >= maxArchiveEntries {
			return nil, errors.New("Docker save archive has too many entries")
		}
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		name, err := cleanTarPath(header.Name)
		if err != nil {
			return nil, err
		}
		if name != "manifest.json" {
			continue
		}
		if found || header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA || header.Size < 0 || header.Size > maxMetadataBytes {
			return nil, errors.New("invalid Docker save manifest entry")
		}
		found = true
		data, err = io.ReadAll(io.LimitReader(reader, maxMetadataBytes+1))
		if err != nil || len(data) > maxMetadataBytes {
			return nil, errors.New("Docker save manifest exceeds size limit")
		}
	}
	if !found {
		return nil, errors.New("archive lacks OCI layout and Docker save manifest")
	}
	var manifest []dockerSaveManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, errors.New("invalid Docker save manifest JSON")
	}
	return manifest, nil
}

func dockerConfigFilenameMatches(name, digest string) bool {
	base := path.Base(name)
	if dockerConfigHash.MatchString(base) {
		return strings.TrimSuffix(base, ".json") == digest
	}
	if archiveBlobName.MatchString(name) {
		return base == digest
	}
	return true // legacy archives may use a non-content-addressed config name
}

func writeDockerLayoutBlob(dir string, data []byte, mediaType string) (descriptor, error) {
	hash := sha256.Sum256(data)
	digest := hex.EncodeToString(hash[:])
	if err := os.WriteFile(filepath.Join(dir, digest), data, 0o600); err != nil {
		return descriptor{}, err
	}
	return descriptor{MediaType: mediaType, Digest: "sha256:" + digest, Size: int64(len(data))}, nil
}
