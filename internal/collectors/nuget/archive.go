package nuget

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/Pirikara/Ravel/internal/collectors/common"
	"github.com/Pirikara/Ravel/internal/model"
	"github.com/Pirikara/Ravel/internal/safeurl"
)

const (
	maxNupkgBytes  = 512 << 20
	maxNuspecBytes = 2 << 20
)

type nuspec struct {
	XMLName  xml.Name `xml:"package"`
	Metadata struct {
		ID         string `xml:"id"`
		Version    string `xml:"version"`
		Repository struct {
			Type string `xml:"type,attr"`
			URL  string `xml:"url,attr"`
		} `xml:"repository"`
	} `xml:"metadata"`
}

// CollectArchive observes an actual NuGet package archive. The nuspec records
// declared metadata, while the SHA-256 covers the exact supplied bytes.
func CollectArchive(file, project string) (model.Document, error) {
	info, err := os.Stat(file)
	if err != nil {
		return model.Document{}, err
	}
	if info.IsDir() || info.Size() > maxNupkgBytes {
		return model.Document{}, fmt.Errorf("NuGet archive is not a file or exceeds %d bytes", maxNupkgBytes)
	}
	input, err := os.Open(file)
	if err != nil {
		return model.Document{}, err
	}
	hasher := sha256.New()
	_, err = io.Copy(hasher, input)
	_ = input.Close()
	if err != nil {
		return model.Document{}, err
	}
	digest := hex.EncodeToString(hasher.Sum(nil))
	archive, err := zip.OpenReader(file)
	if err != nil {
		return model.Document{}, fmt.Errorf("invalid NuGet archive: %w", err)
	}
	defer archive.Close()
	if len(archive.File) > 10000 {
		return model.Document{}, fmt.Errorf("NuGet archive contains too many entries")
	}
	doc := common.NewDocument(file, project, "nuget-archive", nil)
	doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "artifact_graph_partial"})
	ev := model.Evidence{Collector: "nuget-archive", InputPath: file, InputDigest: "sha256:" + digest, Method: "artifact-inspection"}
	component := model.Component{ID: "nuget-archive:" + common.ID(digest), Kind: "file", Name: filepath.Base(file), Hashes: []model.Hash{{Alg: "SHA-256", Content: digest}}, Evidence: []model.Evidence{ev}}
	var descriptor *zip.File
	for _, entry := range archive.File {
		if entry.FileInfo().IsDir() || strings.Contains(entry.Name, "/") || !strings.EqualFold(path.Ext(entry.Name), ".nuspec") {
			continue
		}
		if descriptor != nil {
			descriptor = nil
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "ambiguous_archive_metadata"})
			break
		}
		descriptor = entry
	}
	if descriptor == nil {
		if len(doc.Coverage.Issues) == 1 {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "missing_archive_metadata"})
		}
	} else {
		if descriptor.UncompressedSize64 > maxNuspecBytes {
			return model.Document{}, fmt.Errorf("NuGet nuspec exceeds %d bytes", maxNuspecBytes)
		}
		reader, err := descriptor.Open()
		if err != nil {
			return model.Document{}, err
		}
		metadata, err := io.ReadAll(io.LimitReader(reader, maxNuspecBytes+1))
		_ = reader.Close()
		if err != nil || len(metadata) > maxNuspecBytes {
			return model.Document{}, fmt.Errorf("NuGet nuspec could not be read within limit")
		}
		var spec nuspec
		if err := xml.Unmarshal(metadata, &spec); err != nil {
			return model.Document{}, fmt.Errorf("invalid NuGet nuspec: %w", err)
		}
		id := strings.TrimSpace(spec.Metadata.ID)
		version := strings.TrimSpace(spec.Metadata.Version)
		if id != "" && version != "" && !strings.ContainsAny(id+version, " \t\r\n") {
			component.Kind, component.Name, component.Version = "package", id, version
		} else {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "missing_archive_identity"})
		}
		if spec.Metadata.Repository.URL != "" {
			clean := safeurl.Clean(spec.Metadata.Repository.URL)
			if clean == "" {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unsafe_or_invalid_source", Name: component.Name})
			} else {
				doc.Development = append(doc.Development, model.Development{Occurrence: component.ID, SafeURL: clean, Status: "declared", Evidence: ev})
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
