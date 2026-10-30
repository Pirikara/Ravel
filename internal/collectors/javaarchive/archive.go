package javaarchive

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"ravel/internal/collectors/common"
	"ravel/internal/model"
	"ravel/internal/safeurl"
)

const maxNestedJAR = 64 << 20
const maxDescriptor = 1 << 20
const maxArchiveEntries = 100000

type coordinate struct {
	group, artifact, version string
}

// Collect inventories the submitted archive and physically bundled Java
// libraries. It does not infer dependencies from filenames or shaded classes.
func Collect(file, project string) (model.Document, error) {
	f, err := os.Open(file)
	if err != nil {
		return model.Document{}, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return model.Document{}, err
	}
	if info.Size() < 0 {
		return model.Document{}, fmt.Errorf("invalid Java archive size")
	}
	archive, err := zip.NewReader(f, info.Size())
	if err != nil {
		return model.Document{}, fmt.Errorf("invalid Java archive: %w", err)
	}
	if len(archive.File) > maxArchiveEntries {
		return model.Document{}, fmt.Errorf("Java archive has too many entries")
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return model.Document{}, err
	}
	hasher := sha256.New()
	if _, err := io.Copy(hasher, f); err != nil {
		return model.Document{}, err
	}
	wholeHash := hex.EncodeToString(hasher.Sum(nil))
	doc := common.NewDocument(file, project, "java-archive", nil)
	doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "artifact_graph_partial"})
	outerCoord, outerAmbiguous, err := identify(archive)
	if err != nil {
		return model.Document{}, err
	}
	if outerAmbiguous {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "ambiguous_archive_metadata", Name: filepath.Base(file)})
	}
	outerName := filepath.Base(file)
	outerVersion := ""
	if outerCoord != nil {
		outerName = outerCoord.group + ":" + outerCoord.artifact
		outerVersion = outerCoord.version
	} else {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "artifact_identity_unresolved", Name: outerName})
	}
	outerRef := "java-archive:" + common.ID("outer|"+wholeHash)
	outerEvidence := artifactEvidence(file, wholeHash, "/", "java-archive")
	doc.Components = append(doc.Components, model.Component{ID: outerRef, Kind: "application", Name: outerName, Version: outerVersion, Hashes: []model.Hash{{Alg: "SHA-256", Content: wholeHash}}, Evidence: []model.Evidence{outerEvidence}})
	if outerCoord != nil {
		addDevelopment(&doc, archive, *outerCoord, outerRef, file, wholeHash, "")
	}
	doc.Edges = append(doc.Edges, model.Edge{From: "root", To: outerRef, Kind: "direct", Evidence: outerEvidence})
	doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "missing_source", Name: outerName})
	nestedCounts := map[string]int{}
	for _, entry := range archive.File {
		if _, ok := nestedJARCondition(entry.Name); ok {
			nestedCounts[entry.Name]++
		}
	}
	reportedDuplicates := map[string]bool{}
	for _, entry := range archive.File {
		name := entry.Name
		condition, ok := nestedJARCondition(name)
		if !ok {
			continue
		}
		if nestedCounts[name] > 1 {
			if !reportedDuplicates[name] {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "duplicate_archive_entry"})
				reportedDuplicates[name] = true
			}
			continue
		}
		if path.Clean(name) != name || entry.UncompressedSize64 > maxNestedJAR {
			return model.Document{}, fmt.Errorf("unsafe or oversized nested JAR %q", name)
		}
		content, err := readEntry(entry, maxNestedJAR)
		if err != nil {
			return model.Document{}, fmt.Errorf("nested JAR %q: %w", name, err)
		}
		nested, err := zip.NewReader(bytes.NewReader(content), int64(len(content)))
		if err != nil {
			return model.Document{}, fmt.Errorf("invalid nested JAR %q: %w", name, err)
		}
		if len(nested.File) > maxArchiveEntries {
			return model.Document{}, fmt.Errorf("nested JAR %q has too many entries", name)
		}
		coord, ambiguous, err := identify(nested)
		if err != nil {
			return model.Document{}, fmt.Errorf("nested JAR %q: %w", name, err)
		}
		if ambiguous {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "ambiguous_archive_metadata", Name: name})
		}
		componentName := path.Base(name)
		version := ""
		if coord != nil {
			componentName = coord.group + ":" + coord.artifact
			version = coord.version
		} else {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "artifact_identity_unresolved", Name: name})
		}
		digest := sha256.Sum256(content)
		hash := hex.EncodeToString(digest[:])
		ref := "java-archive:" + common.ID(name+"|"+hash)
		ev := artifactEvidence(file, wholeHash, "/"+name, "java-archive")
		doc.Components = append(doc.Components, model.Component{ID: ref, Kind: "package", Name: componentName, Version: version, Hashes: []model.Hash{{Alg: "SHA-256", Content: hash}}, Evidence: []model.Evidence{ev}})
		if coord != nil {
			addDevelopment(&doc, nested, *coord, ref, file, wholeHash, name+"/")
		}
		doc.Edges = append(doc.Edges, model.Edge{From: outerRef, To: ref, Kind: "depends_on", Condition: condition, Evidence: ev})
		if condition != "" {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "conditional_graph", Name: componentName})
		}
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "missing_source", Name: componentName})
	}
	common.Finalize(&doc)
	return doc, nil
}

func nestedJARCondition(name string) (string, bool) {
	switch {
	case strings.HasPrefix(name, "BOOT-INF/lib/") && strings.HasSuffix(strings.ToLower(name), ".jar"):
		return "", true
	case strings.HasPrefix(name, "WEB-INF/lib/") && strings.HasSuffix(strings.ToLower(name), ".jar"):
		return "", true
	case strings.HasPrefix(name, "WEB-INF/lib-provided/") && strings.HasSuffix(strings.ToLower(name), ".jar"):
		return "runtime=embedded", true
	default:
		return "", false
	}
}

type embeddedPOM struct {
	XMLName    xml.Name `xml:"project"`
	GroupID    string   `xml:"groupId"`
	ArtifactID string   `xml:"artifactId"`
	Version    string   `xml:"version"`
	SCM        struct {
		URL        string `xml:"url"`
		Connection string `xml:"connection"`
	} `xml:"scm"`
}

func addDevelopment(doc *model.Document, archive *zip.Reader, coord coordinate, ref, file, digest, prefix string) {
	want := "META-INF/maven/" + coord.group + "/" + coord.artifact + "/pom.xml"
	count := 0
	for _, entry := range archive.File {
		if entry.Name == want {
			count++
		}
	}
	if count > 1 {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "development_metadata_ambiguous", Name: coord.artifact})
		return
	}
	for _, entry := range archive.File {
		if entry.Name != want {
			continue
		}
		if entry.UncompressedSize64 > maxDescriptor {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "development_metadata_invalid", Name: coord.artifact})
			return
		}
		content, err := readEntry(entry, maxDescriptor)
		if err != nil {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "development_metadata_invalid", Name: coord.artifact})
			return
		}
		var pom embeddedPOM
		if err := xml.Unmarshal(content, &pom); err != nil || pom.ArtifactID != coord.artifact || pom.GroupID != "" && pom.GroupID != coord.group || pom.Version != "" && pom.Version != coord.version {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "development_metadata_invalid", Name: coord.artifact})
			return
		}
		raw := strings.TrimSpace(pom.SCM.URL)
		if raw == "" && strings.HasPrefix(pom.SCM.Connection, "scm:git:") {
			raw = strings.TrimPrefix(pom.SCM.Connection, "scm:git:")
		}
		if raw == "" {
			return
		}
		clean := safeurl.Clean(raw)
		if clean == "" {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unsafe_or_invalid_development_source", Name: coord.artifact})
			return
		}
		doc.Development = append(doc.Development, model.Development{Occurrence: ref, SafeURL: clean, Status: "declared", Evidence: artifactEvidence(file, digest, "/"+prefix+want, "java-archive")})
		return
	}
}

func artifactEvidence(file, digest, pointer, collector string) model.Evidence {
	return model.Evidence{Collector: collector, InputPath: file, InputDigest: "sha256:" + digest, Pointer: pointer, Method: "artifact-inspection"}
}

func identify(archive *zip.Reader) (*coordinate, bool, error) {
	var selected *coordinate
	seen := map[string]bool{}
	for _, entry := range archive.File {
		parts := strings.Split(entry.Name, "/")
		if len(parts) != 5 || parts[0] != "META-INF" || parts[1] != "maven" || parts[4] != "pom.properties" {
			continue
		}
		if seen[entry.Name] {
			return nil, true, nil
		}
		seen[entry.Name] = true
		if entry.UncompressedSize64 > maxDescriptor {
			return nil, false, fmt.Errorf("oversized Maven descriptor %q", entry.Name)
		}
		content, err := readEntry(entry, maxDescriptor)
		if err != nil {
			return nil, false, err
		}
		props := map[string]string{}
		for _, raw := range strings.Split(string(content), "\n") {
			line := strings.TrimSpace(raw)
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
				continue
			}
			key, value, found := strings.Cut(line, "=")
			if !found {
				key, value, found = strings.Cut(line, ":")
			}
			if found {
				props[strings.TrimSpace(key)] = strings.TrimSpace(value)
			}
		}
		if props["groupId"] != parts[2] || props["artifactId"] != parts[3] || props["version"] == "" {
			continue
		}
		candidate := coordinate{props["groupId"], props["artifactId"], props["version"]}
		if selected != nil && *selected != candidate {
			return nil, true, nil // shaded or otherwise ambiguous archive
		}
		selected = &candidate
	}
	return selected, false, nil
}

func readEntry(entry *zip.File, limit int64) ([]byte, error) {
	r, err := entry.Open()
	if err != nil {
		return nil, err
	}
	defer r.Close()
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("entry exceeds size limit")
	}
	return data, nil
}
