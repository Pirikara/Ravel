package oci

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"path"
	"sort"
	"strings"

	"github.com/Pirikara/Ravel/internal/collectors/npm"
	"github.com/Pirikara/Ravel/internal/model"
)

const (
	maxDPKGInfoListBytes      = 1 << 20
	maxDPKGInfoListLayerBytes = 64 << 20
	maxDPKGInfoListFiles      = 10000
	maxDPKGNodeOwnedPaths     = 100000
)

type dpkgNodeFileListState struct {
	paths  map[string]int
	digest string
	layer  string
}

func isDPKGInfoListPath(name string) bool {
	if path.Clean(name) != name || path.Dir(name) != "var/lib/dpkg/info" || !strings.HasSuffix(name, ".list") {
		return false
	}
	packageName := strings.TrimSuffix(path.Base(name), ".list")
	if packageName == "" || strings.ContainsAny(packageName, "/\\\x00\r\n") {
		return false
	}
	return true
}

// inspectDPKGNodeFileList retains only exact global Node package manifests;
// the complete dpkg list is hashed while it is streamed from the image layer.
func inspectDPKGNodeFileList(input io.Reader, size int64) (dpkgNodeFileListState, error) {
	if size < 0 || size > maxDPKGInfoListBytes {
		return dpkgNodeFileListState{}, errors.New("invalid dpkg file list size")
	}
	hash := sha256.New()
	limited := &io.LimitedReader{R: input, N: size}
	scanner := bufio.NewScanner(io.TeeReader(limited, hash))
	scanner.Buffer(make([]byte, 4096), maxDPKGInfoListBytes)
	state := dpkgNodeFileListState{}
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := scanner.Bytes()
		if !bytes.HasPrefix(line, []byte("/usr/share/nodejs/")) {
			continue
		}
		name := string(line[1:])
		if npm.IsSystemNodePackagePath(name) {
			if state.paths == nil {
				state.paths = map[string]int{}
			}
			state.paths[name] = lineNumber
		}
	}
	if err := scanner.Err(); err != nil {
		return dpkgNodeFileListState{}, err
	}
	if limited.N != 0 {
		return dpkgNodeFileListState{}, errors.New("truncated dpkg file list")
	}
	state.digest = hex.EncodeToString(hash.Sum(nil))
	return state, nil
}

func linkSystemNodeOwners(doc *model.Document, records []npm.InstalledRecord, lists map[string]dpkgNodeFileListState, limited bool) {
	byPackage := map[string][]model.Component{}
	for _, component := range doc.Components {
		if strings.HasPrefix(component.ID, "dpkg:") {
			byPackage[component.Name] = append(byPackage[component.Name], component)
		}
	}
	type owner struct {
		id       string
		evidence model.Evidence
	}
	byPath := map[string][]owner{}
	names := make([]string, 0, len(lists))
	for name := range lists {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		state := lists[name]
		packageName := strings.TrimSuffix(path.Base(name), ".list")
		arch := ""
		if index := strings.LastIndexByte(packageName, ':'); index >= 0 {
			arch = packageName[index+1:]
			packageName = packageName[:index]
		}
		matches := []model.Component{}
		for _, component := range byPackage[packageName] {
			if arch == "" || component.Platform == arch {
				matches = append(matches, component)
			}
		}
		if len(matches) != 1 {
			continue
		}
		for nodePath, line := range state.paths {
			evidence := model.Evidence{Collector: "dpkg-file-list", InputPath: "oci:" + state.layer + "!/" + name, InputDigest: "sha256:" + state.digest, Line: line, Method: "installed-file-ownership"}
			byPath[nodePath] = append(byPath[nodePath], owner{id: matches[0].ID, evidence: evidence})
		}
	}
	systemRecords := false
	for _, record := range records {
		if !npm.IsSystemNodePackagePath(record.MetadataPath) {
			continue
		}
		systemRecords = true
		candidates := byPath[record.MetadataPath]
		if len(candidates) != 1 {
			code := "node_system_owner_unresolved"
			if len(candidates) > 1 {
				code = "node_system_owner_ambiguous"
			}
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: code, Name: record.Component.Name})
			continue
		}
		candidate := candidates[0]
		linked := false
		for i := range doc.Edges {
			if doc.Edges[i].From == "root" && doc.Edges[i].To == record.Component.ID && doc.Edges[i].Kind == "installed" {
				doc.Edges[i].From = candidate.id
				doc.Edges[i].Kind = "embedded"
				doc.Edges[i].Evidence = candidate.evidence
				linked = true
				break
			}
		}
		if !linked {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "node_system_owner_unresolved", Name: record.Component.Name})
			continue
		}
		for i := range doc.Components {
			if doc.Components[i].ID == record.Component.ID {
				doc.Components[i].Evidence = append(doc.Components[i].Evidence, candidate.evidence)
				break
			}
		}
	}
	if limited && systemRecords {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "node_system_ownership_scan_limited"})
	}
}
