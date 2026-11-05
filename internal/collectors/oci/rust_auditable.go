package oci

import (
	"bytes"
	"compress/zlib"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/Masterminds/semver/v3"

	"github.com/Pirikara/Ravel/internal/collectors/common"
	"github.com/Pirikara/Ravel/internal/model"
)

const (
	maxRustAuditCompressedBytes = 2 << 20
	maxRustAuditJSONBytes       = 8 << 20
	maxRustAuditPackages        = 5000
	maxRustAuditEdges           = 100000
)

var rustCrateName = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_-]{0,254}$`)

type rustAuditableState struct {
	document model.Document
	status   string
}

type rustAuditPayload struct {
	Format   uint32             `json:"format"`
	Packages []rustAuditPackage `json:"packages"`
}

type rustAuditPackage struct {
	Name         string          `json:"name"`
	Version      string          `json:"version"`
	Source       json.RawMessage `json:"source"`
	Kind         string          `json:"kind"`
	Root         bool            `json:"root"`
	Dependencies []int           `json:"dependencies"`
}

var errRustAuditLegacy = errors.New("cargo-auditable format 0 does not distinguish build dependencies")

// inspectRustAuditableBinary reads cargo-auditable's explicit ELF section.
// A missing section is an ordinary ELF, not a malformed Rust binary.
func inspectRustAuditableBinary(data []byte, source, project, binaryPath string) (model.Document, bool, error) {
	if len(data) == 0 || len(data) > maxGoBinaryBytes {
		return model.Document{}, false, errors.New("Rust audit binary exceeds memory limit")
	}
	if !bytes.Contains(data, []byte(".dep-v0")) {
		return model.Document{}, false, nil
	}
	hash := sha256.Sum256(data)
	return inspectRustAuditableReader(bytes.NewReader(data), int64(len(data)), hex.EncodeToString(hash[:]), source, project, binaryPath)
}

func inspectRustAuditableReader(reader io.ReaderAt, size int64, digest, source, project, binaryPath string) (document model.Document, recognized bool, err error) {
	defer func() {
		if recover() != nil {
			document = model.Document{}
			err = errors.New("malformed Rust audit ELF")
		}
	}()
	if err := guardELFMetadataReader(reader, size); err != nil {
		return model.Document{}, false, err
	}
	file, err := elf.NewFile(reader)
	if err != nil || file.Type != elf.ET_EXEC && file.Type != elf.ET_DYN {
		return model.Document{}, false, errors.New("invalid Rust audit ELF")
	}
	var section *elf.Section
	for _, candidate := range file.Sections {
		if candidate.Name == ".dep-v0" {
			if section != nil {
				return model.Document{}, true, errors.New("duplicate Rust audit ELF section")
			}
			section = candidate
		}
	}
	if section == nil {
		return model.Document{}, false, nil
	}
	if section.Type != elf.SHT_PROGBITS || section.Flags&elf.SHF_COMPRESSED != 0 || section.Size == 0 || section.Size > maxRustAuditCompressedBytes || section.Offset > uint64(size) || section.Size > uint64(size)-section.Offset {
		return model.Document{}, true, errors.New("invalid Rust audit ELF section")
	}
	compressed := make([]byte, int(section.Size))
	if _, err := reader.ReadAt(compressed, int64(section.Offset)); err != nil {
		return model.Document{}, true, errors.New("unreadable Rust audit ELF section")
	}
	zr, err := zlib.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return model.Document{}, true, errors.New("invalid Rust audit compression")
	}
	payload, readErr := io.ReadAll(io.LimitReader(zr, maxRustAuditJSONBytes+1))
	closeErr := zr.Close()
	if readErr != nil || closeErr != nil || len(payload) > maxRustAuditJSONBytes {
		return model.Document{}, true, errors.New("Rust audit payload exceeds limit or is corrupt")
	}
	doc, err := collectRustAuditPayload(payload, digest, source, project, binaryPath)
	return doc, true, err
}

func collectRustAuditPayload(data []byte, digest, source, project, binaryPath string) (model.Document, error) {
	var audit rustAuditPayload
	if err := json.Unmarshal(data, &audit); err != nil || len(audit.Packages) == 0 || len(audit.Packages) > maxRustAuditPackages {
		return model.Document{}, errors.New("invalid Rust audit JSON")
	}
	if audit.Format == 0 {
		return model.Document{}, errRustAuditLegacy
	}
	root := -1
	sources := make([]string, len(audit.Packages))
	indegree := make([]int, len(audit.Packages))
	edges := 0
	for i, item := range audit.Packages {
		if !rustCrateName.MatchString(item.Name) || len(item.Version) > 128 || item.Kind != "" && item.Kind != "runtime" && item.Kind != "build" {
			return model.Document{}, errors.New("invalid Rust audit package identity or kind")
		}
		if _, err := semver.StrictNewVersion(item.Version); err != nil {
			return model.Document{}, errors.New("invalid Rust audit package version")
		}
		declaredSource, err := rustAuditSource(item.Source)
		if err != nil {
			return model.Document{}, errors.New("invalid Rust audit package source")
		}
		sources[i] = declaredSource
		if item.Root {
			if root >= 0 || item.Kind == "build" {
				return model.Document{}, errors.New("invalid Rust audit root package")
			}
			root = i
		}
		edges += len(item.Dependencies)
		if edges > maxRustAuditEdges {
			return model.Document{}, errors.New("Rust audit dependency graph exceeds limit")
		}
		for _, dependency := range item.Dependencies {
			if dependency < 0 || dependency >= len(audit.Packages) {
				return model.Document{}, errors.New("Rust audit dependency index is invalid")
			}
			indegree[dependency]++
		}
	}
	if root < 0 {
		return model.Document{}, errors.New("Rust audit root package is missing")
	}
	// The format permits cycles, so validate the graph before following it.
	ready := make([]int, 0, len(audit.Packages))
	for i, degree := range indegree {
		if degree == 0 {
			ready = append(ready, i)
		}
	}
	visited := 0
	for len(ready) > 0 {
		i := ready[len(ready)-1]
		ready = ready[:len(ready)-1]
		visited++
		for _, dependency := range audit.Packages[i].Dependencies {
			indegree[dependency]--
			if indegree[dependency] == 0 {
				ready = append(ready, dependency)
			}
		}
	}
	if visited != len(audit.Packages) {
		return model.Document{}, errors.New("Rust audit dependency graph contains a cycle")
	}
	// Build-only nodes and their descendants are not necessarily in the final
	// executable. Keep only paths composed of runtime dependencies.
	runtime := make([]bool, len(audit.Packages))
	runtime[root] = true
	queue := []int{root}
	for len(queue) > 0 {
		i := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		for _, dependency := range audit.Packages[i].Dependencies {
			if audit.Packages[dependency].Kind == "build" || runtime[dependency] {
				continue
			}
			runtime[dependency] = true
			queue = append(queue, dependency)
		}
	}
	doc := common.NewDocument(source, project, "rust-auditable", nil)
	evidence := model.Evidence{Collector: "cargo-auditable-elf", InputPath: source, InputDigest: "sha256:" + digest, Pointer: "elf/section/.dep-v0/packages/" + strconv.Itoa(root), Method: "embedded-audit-metadata"}
	rootPackage := audit.Packages[root]
	outerID := "rust-auditable:" + common.ID(source+"\x00"+digest)
	doc.Components = append(doc.Components, model.Component{ID: outerID, Kind: "application", Name: rootPackage.Name, Version: rootPackage.Version, Context: "location=/" + binaryPath + ";audit_format=" + strconv.FormatUint(uint64(audit.Format), 10), Hashes: []model.Hash{{Alg: "SHA-256", Content: digest}}, Evidence: []model.Evidence{evidence}})
	doc.Edges = append(doc.Edges, model.Edge{From: "root", To: outerID, Kind: "installed", Evidence: evidence})
	ids := make([]string, len(audit.Packages))
	ids[root] = outerID
	for i, item := range audit.Packages {
		if !runtime[i] || i == root {
			continue
		}
		id := "rust-auditable:" + common.ID(source+"\x00"+strconv.Itoa(i)+"\x00"+item.Name+"\x00"+item.Version)
		ids[i] = id
		itemEvidence := evidence
		itemEvidence.Pointer = "elf/section/.dep-v0/packages/" + strconv.Itoa(i)
		purl := ""
		if sources[i] == "crates.io" {
			purl = "pkg:cargo/" + url.PathEscape(item.Name) + "@" + common.PURLVersion(item.Version)
		}
		doc.Components = append(doc.Components, model.Component{ID: id, Kind: "package", Name: item.Name, Version: item.Version, Context: "binary=/" + binaryPath + ";source=" + sources[i], PURL: purl, Evidence: []model.Evidence{itemEvidence}})
	}
	for i, item := range audit.Packages {
		if !runtime[i] {
			continue
		}
		for offset, dependency := range item.Dependencies {
			if !runtime[dependency] {
				continue
			}
			edgeEvidence := evidence
			edgeEvidence.Pointer = fmt.Sprintf("elf/section/.dep-v0/packages/%d/dependencies/%d", i, offset)
			doc.Edges = append(doc.Edges, model.Edge{From: ids[i], To: ids[dependency], Kind: "embedded", Evidence: edgeEvidence})
		}
	}
	doc.Coverage.Issues = append(doc.Coverage.Issues,
		model.Issue{Code: "rust_auditable_graph_declared", Name: binaryPath},
		model.Issue{Code: "rust_auditable_origin_unverified", Name: binaryPath},
	)
	common.Finalize(&doc)
	return doc, nil
}

func rustAuditSource(raw json.RawMessage) (string, error) {
	var source string
	if err := json.Unmarshal(raw, &source); err == nil {
		if source == "" || len(source) > 128 || strings.ContainsAny(source, "\x00\r\n") {
			return "", errors.New("invalid Rust audit source")
		}
		switch source {
		case "crates.io", "CratesIo":
			return "crates.io", nil
		case "local", "Local":
			return "local", nil
		case "git", "Git":
			return "git", nil
		case "registry", "Registry":
			return "registry", nil
		default:
			return "other", nil
		}
	}
	var other map[string]string
	if err := json.Unmarshal(raw, &other); err != nil || len(other) != 1 || other["Other"] == "" || len(other["Other"]) > 512 {
		return "", errors.New("invalid Rust audit source")
	}
	return "other", nil
}
