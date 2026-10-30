package python

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"unicode"

	"ravel/internal/collectors/common"
	"ravel/internal/model"
	"ravel/internal/safeurl"
)

const maxWheelBytes = 512 << 20
const maxWheelMetadata = 2 << 20
const maxWheelEntries = 10000

type wheelHeader struct {
	name, value string
}

// CollectWheel observes one wheel archive. Its metadata declares a package,
// but neither the archive nor its filename proves which index served it.
func CollectWheel(file, project string) (model.Document, error) {
	input, err := os.Open(file)
	if err != nil {
		return model.Document{}, err
	}
	defer input.Close()
	info, err := input.Stat()
	if err != nil {
		return model.Document{}, err
	}
	if info.IsDir() || info.Size() < 0 || info.Size() > maxWheelBytes {
		return model.Document{}, fmt.Errorf("wheel is not a file or exceeds %d bytes", maxWheelBytes)
	}
	archive, err := zip.NewReader(input, info.Size())
	if err != nil {
		return model.Document{}, fmt.Errorf("invalid wheel archive: %w", err)
	}
	if len(archive.File) > maxWheelEntries {
		return model.Document{}, fmt.Errorf("wheel archive contains too many entries")
	}
	if _, err := input.Seek(0, io.SeekStart); err != nil {
		return model.Document{}, err
	}
	hasher := sha256.New()
	if _, err := io.Copy(hasher, input); err != nil {
		return model.Document{}, err
	}
	digest := hex.EncodeToString(hasher.Sum(nil))
	doc := common.NewDocument(file, project, "python-wheel", nil)
	doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "artifact_graph_partial"})
	ev := model.Evidence{Collector: "python-wheel", InputPath: file, InputDigest: "sha256:" + digest, Method: "artifact-inspection"}
	component := model.Component{ID: "python-wheel:" + common.ID(digest), Kind: "file", Name: filepath.Base(file), Hashes: []model.Hash{{Alg: "SHA-256", Content: digest}}, Evidence: []model.Evidence{ev}}
	var metadata *zip.File
	var folder string
	entryCount := map[string]int{}
	for _, entry := range archive.File {
		entryCount[entry.Name]++
		if entry.FileInfo().IsDir() || !strings.HasSuffix(entry.Name, ".dist-info/METADATA") || strings.Count(entry.Name, "/") != 1 || path.Clean(entry.Name) != entry.Name {
			continue
		}
		if metadata == nil {
			metadata = entry
			folder = strings.TrimSuffix(entry.Name, "/METADATA")
		} else {
			metadata = nil
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "ambiguous_archive_metadata"})
			break
		}
	}
	if metadata == nil {
		if len(doc.Coverage.Issues) == 1 {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "missing_archive_metadata"})
		}
	} else if entryCount[folder+"/METADATA"] != 1 || entryCount[folder+"/WHEEL"] != 1 || entryCount[folder+"/RECORD"] != 1 {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "invalid_archive_metadata"})
	} else {
		if metadata.UncompressedSize64 > maxWheelMetadata {
			return model.Document{}, fmt.Errorf("wheel METADATA exceeds %d bytes", maxWheelMetadata)
		}
		reader, err := metadata.Open()
		if err != nil {
			return model.Document{}, err
		}
		data, err := io.ReadAll(io.LimitReader(reader, maxWheelMetadata+1))
		_ = reader.Close()
		if err != nil || len(data) > maxWheelMetadata {
			return model.Document{}, fmt.Errorf("wheel METADATA could not be read within limit")
		}
		headers, ok := parseWheelHeaders(data)
		name, version := singleWheelHeader(headers, "name"), singleWheelHeader(headers, "version")
		stem := strings.TrimSuffix(folder, ".dist-info")
		fileName := strings.ToLower(filepath.Base(file))
		if !ok || name == "" || version == "" || strings.ToLower(stem) != wheelNameToken(name)+"-"+wheelVersionToken(version) || !strings.HasPrefix(fileName, strings.ToLower(stem)+"-") {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "invalid_archive_metadata"})
		} else {
			component.Kind, component.Name, component.Version = "package", name, version
			for _, h := range headers {
				if h.name == "requires-dist" {
					doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "declared_dependencies_unresolved"})
					break
				}
			}
			seen := map[string]bool{}
			for _, h := range headers {
				if h.name != "project-url" {
					continue
				}
				label, rawURL, found := strings.Cut(h.value, ",")
				if !found || !wheelSourceLabel(label) {
					continue
				}
				clean := safeurl.Clean(strings.TrimSpace(rawURL))
				if clean == "" {
					doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unsafe_or_invalid_development_source", Name: name})
				} else if !seen[clean] {
					seen[clean] = true
					devEvidence := ev
					devEvidence.Pointer = "/" + folder + "/METADATA"
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

func parseWheelHeaders(data []byte) ([]wheelHeader, bool) {
	var headers []wheelHeader
	for _, line := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
		if line == "" {
			break
		}
		if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
			if len(headers) == 0 {
				return nil, false
			}
			headers[len(headers)-1].value += " " + strings.TrimSpace(line)
			continue
		}
		name, value, found := strings.Cut(line, ":")
		if !found || name == "" || strings.IndexFunc(name, func(r rune) bool { return !unicode.IsLetter(r) && r != '-' }) >= 0 {
			return nil, false
		}
		headers = append(headers, wheelHeader{name: strings.ToLower(name), value: strings.TrimSpace(value)})
	}
	return headers, true
}

func singleWheelHeader(headers []wheelHeader, key string) string {
	value := ""
	for _, h := range headers {
		if h.name != key {
			continue
		}
		if value != "" || h.value == "" {
			return ""
		}
		value = h.value
	}
	return value
}

func wheelNameToken(raw string) string {
	var out strings.Builder
	separator := false
	for _, r := range strings.ToLower(raw) {
		if r == '-' || r == '_' || r == '.' {
			if !separator {
				out.WriteByte('_')
			}
			separator = true
		} else {
			out.WriteRune(r)
			separator = false
		}
	}
	return out.String()
}

func wheelVersionToken(raw string) string {
	return strings.ToLower(strings.ReplaceAll(raw, "-", "_"))
}

func wheelSourceLabel(label string) bool {
	var normalized strings.Builder
	for _, r := range strings.ToLower(label) {
		if r < 128 && (unicode.IsPunct(r) || unicode.IsSpace(r)) {
			continue
		}
		normalized.WriteRune(r)
	}
	switch normalized.String() {
	case "source", "repository", "sourcecode", "github":
		return true
	default:
		return false
	}
}
