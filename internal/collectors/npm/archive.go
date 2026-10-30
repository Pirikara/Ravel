package npm

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"ravel/internal/collectors/common"
	"ravel/internal/model"
	"ravel/internal/safeurl"
)

const maxNpmTarballBytes = 512 << 20
const maxNpmUncompressedBytes = 512 << 20
const maxNpmPackageJSON = 2 << 20
const maxNpmTarEntries = 10000

type archiveManifest struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	Repository           json.RawMessage   `json:"repository"`
	Dependencies         map[string]string `json:"dependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
}

// CollectArchive inventories an npm tarball's exact bytes and its declared
// package identity. Dependency ranges are not a resolved dependency graph.
func CollectArchive(file, project string) (model.Document, error) {
	input, err := os.Open(file)
	if err != nil {
		return model.Document{}, err
	}
	defer input.Close()
	info, err := input.Stat()
	if err != nil {
		return model.Document{}, err
	}
	if info.IsDir() || info.Size() < 0 || info.Size() > maxNpmTarballBytes {
		return model.Document{}, fmt.Errorf("npm tarball is not a file or exceeds %d bytes", maxNpmTarballBytes)
	}
	hasher := sha256.New()
	if _, err := io.Copy(hasher, input); err != nil {
		return model.Document{}, err
	}
	digest := hex.EncodeToString(hasher.Sum(nil))
	if _, err := input.Seek(0, io.SeekStart); err != nil {
		return model.Document{}, err
	}
	compressed, err := gzip.NewReader(input)
	if err != nil {
		return model.Document{}, fmt.Errorf("invalid npm tarball: %w", err)
	}
	defer compressed.Close()
	limited := &io.LimitedReader{R: compressed, N: maxNpmUncompressedBytes + 1}
	archive := tar.NewReader(limited)
	var manifest []byte
	manifestCount := 0
	bundled := false
	entryCount := 0
	for {
		entry, err := archive.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return model.Document{}, fmt.Errorf("invalid npm tarball: %w", err)
		}
		entryCount++
		if entryCount > maxNpmTarEntries || limited.N <= 0 {
			return model.Document{}, fmt.Errorf("npm tarball exceeds scan limits")
		}
		if strings.HasPrefix(entry.Name, "package/node_modules/") {
			bundled = true
		}
		if entry.Name != "package/package.json" {
			continue
		}
		manifestCount++
		if entry.Typeflag != tar.TypeReg && entry.Typeflag != tar.TypeRegA {
			continue
		}
		if entry.Size < 0 || entry.Size > maxNpmPackageJSON {
			return model.Document{}, fmt.Errorf("npm package.json exceeds %d bytes", maxNpmPackageJSON)
		}
		data, err := io.ReadAll(io.LimitReader(archive, maxNpmPackageJSON+1))
		if err != nil || len(data) > maxNpmPackageJSON {
			return model.Document{}, fmt.Errorf("npm package.json could not be read within limit")
		}
		manifest = data
	}
	if limited.N <= 0 {
		return model.Document{}, fmt.Errorf("npm tarball exceeds uncompressed size limit")
	}
	doc := common.NewDocument(file, project, "npm-archive", nil)
	doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "artifact_graph_partial"})
	if bundled {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "bundled_dependencies_unscanned"})
	}
	ev := model.Evidence{Collector: "npm-archive", InputPath: file, InputDigest: "sha256:" + digest, Method: "artifact-inspection"}
	component := model.Component{ID: "npm-archive:" + common.ID(digest), Kind: "file", Name: filepath.Base(file), Hashes: []model.Hash{{Alg: "SHA-256", Content: digest}}, Evidence: []model.Evidence{ev}}
	switch {
	case manifestCount == 0:
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "missing_archive_metadata"})
	case manifestCount > 1:
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "ambiguous_archive_metadata"})
	default:
		var pkg archiveManifest
		if len(manifest) == 0 || json.Unmarshal(manifest, &pkg) != nil || !validArchiveNpmName(pkg.Name) || pkg.Version == "" || strings.TrimSpace(pkg.Version) != pkg.Version || strings.ContainsAny(pkg.Version, " \t\r\n") {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "invalid_archive_metadata"})
		} else {
			component.Kind, component.Name, component.Version = "package", pkg.Name, pkg.Version
			if len(pkg.Dependencies)+len(pkg.OptionalDependencies)+len(pkg.PeerDependencies) > 0 {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "declared_dependencies_unresolved"})
			}
			repository := archiveRepository(pkg.Repository)
			if repository != "" {
				clean := safeurl.Clean(repository)
				if clean == "" {
					doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unsafe_or_invalid_development_source", Name: pkg.Name})
				} else {
					devEvidence := ev
					devEvidence.Pointer = "/package/package.json/repository"
					doc.Development = append(doc.Development, model.Development{Occurrence: component.ID, SafeURL: clean, Status: "declared", Evidence: devEvidence})
				}
			}
		}
	}
	if component.Kind == "package" {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "distribution_source_unavailable", Name: component.Name})
	}
	doc.Components = append(doc.Components, component)
	doc.Origins = append(doc.Origins, model.Origin{Occurrence: component.ID, Kind: "local", Status: "confirmed", Evidence: ev})
	common.Finalize(&doc)
	return doc, nil
}

func archiveRepository(raw json.RawMessage) string {
	var repository string
	if json.Unmarshal(raw, &repository) != nil {
		var object struct {
			URL string `json:"url"`
		}
		if json.Unmarshal(raw, &object) != nil {
			return ""
		}
		repository = object.URL
	}
	return strings.TrimPrefix(repository, "git+")
}

func validArchiveNpmName(name string) bool {
	if name == "" || len(name) > 214 || strings.ContainsAny(name, " \t\r\n\\") {
		return false
	}
	if strings.HasPrefix(name, "@") {
		parts := strings.Split(name, "/")
		return len(parts) == 2 && len(parts[0]) > 1 && parts[1] != "" && !strings.ContainsAny(parts[0]+parts[1], "/:")
	}
	return !strings.ContainsAny(name, "/:")
}
