package bundler

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/Pirikara/Ravel/internal/collectors/common"
	"github.com/Pirikara/Ravel/internal/model"
	"github.com/Pirikara/Ravel/internal/safeurl"
)

const maxGemBytes = 512 << 20
const maxGemMetadataCompressed = 8 << 20
const maxGemMetadata = 4 << 20
const maxGemEntries = 10000
const maxGemUnpackedBytes = 512 << 20

// CollectArchive observes a RubyGems archive. A .gem file does not prove
// which registry served it, so its package identity has no RubyGems PURL.
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
	if info.IsDir() || info.Size() < 0 || info.Size() > maxGemBytes {
		return model.Document{}, fmt.Errorf("gem archive is not a file or exceeds %d bytes", maxGemBytes)
	}
	hasher := sha256.New()
	if _, err := io.Copy(hasher, input); err != nil {
		return model.Document{}, err
	}
	digest := hex.EncodeToString(hasher.Sum(nil))
	if _, err := input.Seek(0, io.SeekStart); err != nil {
		return model.Document{}, err
	}
	limited := &io.LimitedReader{R: input, N: maxGemBytes + 1}
	archive := tar.NewReader(limited)
	var metadata []byte
	var metadataPath string
	metadataCount := 0
	dataCount := 0
	invalidData := false
	entryCount := 0
	for {
		entry, err := archive.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return model.Document{}, fmt.Errorf("invalid gem archive: %w", err)
		}
		entryCount++
		if entryCount > maxGemEntries || limited.N <= 0 {
			return model.Document{}, fmt.Errorf("gem archive exceeds scan limits")
		}
		if entry.Name == "data.tar.gz" {
			dataCount++
			if entry.Typeflag != tar.TypeReg && entry.Typeflag != tar.TypeRegA {
				invalidData = true
			} else if err := validateGemData(archive); err != nil {
				return model.Document{}, fmt.Errorf("invalid gem contents: %w", err)
			}
			continue
		}
		if entry.Name != "metadata.gz" && entry.Name != "metadata" {
			continue
		}
		metadataCount++
		metadataPath = entry.Name
		if entry.Typeflag != tar.TypeReg && entry.Typeflag != tar.TypeRegA {
			continue
		}
		if entry.Size < 0 || entry.Size > maxGemMetadataCompressed {
			return model.Document{}, fmt.Errorf("gem metadata exceeds %d bytes", maxGemMetadataCompressed)
		}
		var reader io.Reader = archive
		if entry.Name == "metadata.gz" {
			compressed, err := gzip.NewReader(archive)
			if err != nil {
				return model.Document{}, fmt.Errorf("invalid gem metadata compression: %w", err)
			}
			reader = compressed
			metadata, err = io.ReadAll(io.LimitReader(reader, maxGemMetadata+1))
			closeErr := compressed.Close()
			if err != nil || closeErr != nil || len(metadata) > maxGemMetadata {
				return model.Document{}, fmt.Errorf("gem metadata could not be read within limit")
			}
		} else {
			metadata, err = io.ReadAll(io.LimitReader(reader, maxGemMetadata+1))
			if err != nil || len(metadata) > maxGemMetadata {
				return model.Document{}, fmt.Errorf("gem metadata could not be read within limit")
			}
		}
	}
	doc := common.NewDocument(file, project, "ruby-gem", nil)
	doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "artifact_graph_partial"})
	ev := model.Evidence{Collector: "ruby-gem", InputPath: file, InputDigest: "sha256:" + digest, Method: "artifact-inspection"}
	component := model.Component{ID: "ruby-gem:" + common.ID(digest), Kind: "file", Name: filepath.Base(file), Hashes: []model.Hash{{Alg: "SHA-256", Content: digest}}, Evidence: []model.Evidence{ev}}
	switch {
	case metadataCount == 0:
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "missing_archive_metadata"})
	case metadataCount > 1 || dataCount > 1:
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "ambiguous_archive_metadata"})
	case dataCount == 0 || invalidData:
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "invalid_archive_metadata"})
	default:
		name, version, platform, source, hasDependencies, ok := parseGemMetadata(metadata)
		if !ok {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "invalid_archive_metadata"})
		} else {
			component.Kind, component.Name, component.Version, component.Platform = "package", name, version, platform
			if hasDependencies {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "declared_dependencies_unresolved"})
			}
			if source != "" {
				clean := safeurl.Clean(source)
				if clean == "" {
					doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unsafe_or_invalid_development_source", Name: name})
				} else {
					devEvidence := ev
					devEvidence.Pointer = "/" + metadataPath + "/metadata/source_code_uri"
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

func validateGemData(input io.Reader) error {
	compressed, err := gzip.NewReader(input)
	if err != nil {
		return err
	}
	defer compressed.Close()
	limited := &io.LimitedReader{R: compressed, N: maxGemUnpackedBytes + 1}
	archive := tar.NewReader(limited)
	count := 0
	for {
		_, err := archive.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		count++
		if count > maxGemEntries || limited.N <= 0 {
			return fmt.Errorf("gem contents exceed scan limits")
		}
	}
	if _, err := io.Copy(io.Discard, limited); err != nil {
		return err
	}
	if limited.N <= 0 {
		return fmt.Errorf("gem contents exceed uncompressed size limit")
	}
	return nil
}

func parseGemMetadata(data []byte) (name, version, platform, source string, hasDependencies, ok bool) {
	var document yaml.Node
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&document); err != nil || len(document.Content) != 1 {
		return "", "", "", "", false, false
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); err != io.EOF {
		return "", "", "", "", false, false
	}
	spec := document.Content[0]
	if spec.Kind != yaml.MappingNode || spec.Tag != "!ruby/object:Gem::Specification" {
		return "", "", "", "", false, false
	}
	name = gemScalar(gemField(spec, "name"))
	versionNode := gemField(spec, "version")
	if versionNode != nil {
		if versionNode.Kind == yaml.MappingNode && versionNode.Tag == "!ruby/object:Gem::Version" {
			version = gemScalar(gemField(versionNode, "version"))
		} else {
			version = gemScalar(versionNode)
		}
	}
	if name == "" || version == "" || len(name) > 256 || len(version) > 128 || strings.ContainsAny(name+version, " \\/:\t\r\n") || strings.TrimSpace(name) != name || strings.TrimSpace(version) != version {
		return "", "", "", "", false, false
	}
	platform = gemScalar(gemField(spec, "platform"))
	if platform == "ruby" {
		platform = ""
	}
	if strings.ContainsAny(platform, " \t\r\n") {
		return "", "", "", "", false, false
	}
	if dependencies := gemField(spec, "dependencies"); dependencies != nil {
		if dependencies.Kind != yaml.SequenceNode {
			return "", "", "", "", false, false
		}
		hasDependencies = len(dependencies.Content) > 0
	}
	if values := gemField(spec, "metadata"); values != nil {
		if values.Kind != yaml.MappingNode {
			return "", "", "", "", false, false
		}
		source = gemScalar(gemField(values, "source_code_uri"))
	}
	return name, version, platform, source, hasDependencies, true
}

func gemField(mapping *yaml.Node, key string) *yaml.Node {
	if mapping == nil || mapping.Kind != yaml.MappingNode {
		return nil
	}
	var result *yaml.Node
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value == key {
			if result != nil {
				return nil
			}
			result = mapping.Content[i+1]
		}
	}
	return result
}

func gemScalar(node *yaml.Node) string {
	if node == nil || node.Kind != yaml.ScalarNode {
		return ""
	}
	return node.Value
}
