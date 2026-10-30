package swiftpm

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"ravel/internal/collectors/common"
	"ravel/internal/model"
	"ravel/internal/safeurl"
)

const maxSwiftGraphBytes = 64 << 20

type resolvedPackage struct {
	Identity     string            `json:"identity"`
	Name         string            `json:"name"`
	URL          string            `json:"url"`
	Version      string            `json:"version"`
	Path         string            `json:"path"`
	Dependencies []resolvedPackage `json:"dependencies"`
}

// CollectResolved runs SwiftPM only after the CLI's explicit execution gate.
// The returned graph is at package granularity, not a selected target graph.
func CollectResolved(manifest, project string, allowNetwork bool) (model.Document, error) {
	if filepath.Base(manifest) != "Package.swift" {
		return model.Document{}, fmt.Errorf("SwiftPM resolver requires Package.swift")
	}
	manifestData, err := os.ReadFile(manifest)
	if err != nil {
		return model.Document{}, err
	}
	packagePath, err := filepath.Abs(filepath.Dir(manifest))
	if err != nil {
		return model.Document{}, err
	}
	tmp, err := os.MkdirTemp("", "ravel-swiftpm-")
	if err != nil {
		return model.Document{}, err
	}
	defer os.RemoveAll(tmp)
	output := filepath.Join(tmp, "graph.json")
	args := []string{"package", "--package-path", packagePath, "--scratch-path", filepath.Join(tmp, "scratch"), "--cache-path", filepath.Join(tmp, "cache"), "--config-path", filepath.Join(tmp, "config"), "--security-path", filepath.Join(tmp, "security"), "--disable-automatic-resolution", "--only-use-versions-from-resolved-file", "--disable-prefetching"}
	if !allowNetwork {
		args = append(args, "--skip-update")
	}
	args = append(args, "show-dependencies", "--format", "json", "--output-path", output)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "swift", args...)
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return model.Document{}, fmt.Errorf("SwiftPM resolver timed out")
		}
		return model.Document{}, fmt.Errorf("SwiftPM show-dependencies failed")
	}
	info, err := os.Stat(output)
	if err != nil {
		return model.Document{}, fmt.Errorf("SwiftPM did not produce a dependency graph")
	}
	if info.Size() > maxSwiftGraphBytes {
		return model.Document{}, fmt.Errorf("SwiftPM graph exceeds %d bytes", maxSwiftGraphBytes)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		return model.Document{}, err
	}
	var root resolvedPackage
	if err := json.Unmarshal(data, &root); err != nil || root.Identity == "" {
		return model.Document{}, fmt.Errorf("invalid SwiftPM dependency graph")
	}
	doc := common.NewDocument(manifest, project, "swiftpm", manifestData)
	seen := map[string]string{}
	edges := map[string]bool{}
	count := 0
	var visit func(resolvedPackage, string, string, int) error
	visit = func(item resolvedPackage, parent, pointer string, depth int) error {
		if depth > 128 || count > 100000 {
			return fmt.Errorf("SwiftPM graph exceeds traversal limits")
		}
		if item.Identity == "" || item.Name == "" {
			return fmt.Errorf("SwiftPM graph contains an unnamed package")
		}
		key := item.Identity + "\x00" + item.Version + "\x00" + item.URL + "\x00" + item.Path
		ref := seen[key]
		if ref == "" {
			count++
			ref = "swiftpm:" + common.ID(key)
			seen[key] = ref
			ev := common.Evidence(manifest, "swiftpm-resolver", pointer, manifestData)
			ev.Method = "resolver-output"
			version := item.Version
			if version == "unspecified" {
				version = ""
			}
			kind := "package"
			if item.URL == "" || filepath.IsAbs(item.URL) || strings.HasPrefix(item.URL, "file:") || !strings.Contains(item.URL, "://") {
				kind = "application"
				doc.Origins = append(doc.Origins, model.Origin{Occurrence: ref, Kind: "local", Status: "declared", Evidence: ev})
			} else {
				clean := safeurl.Clean(strings.TrimPrefix(item.URL, "git+"))
				if clean == "" {
					doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unsafe_or_invalid_source", Name: item.Name})
				} else {
					doc.Origins = append(doc.Origins, model.Origin{Occurrence: ref, Kind: "vcs", SafeURL: clean, Status: "declared", Evidence: ev})
				}
			}
			doc.Components = append(doc.Components, model.Component{ID: ref, Kind: kind, Name: item.Name, Version: version, Evidence: []model.Evidence{ev}})
		}
		if !edges[parent+"\x00"+ref] {
			edges[parent+"\x00"+ref] = true
			ev := common.Evidence(manifest, "swiftpm-resolver", pointer, manifestData)
			ev.Method = "resolver-output"
			doc.Edges = append(doc.Edges, model.Edge{From: parent, To: ref, Kind: "depends_on", Evidence: ev})
		}
		for index, child := range item.Dependencies {
			if err := visit(child, ref, fmt.Sprintf("%s/dependencies/%d", pointer, index), depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	for index, child := range root.Dependencies {
		if err := visit(child, "root", fmt.Sprintf("/dependencies/%d", index), 1); err != nil {
			return model.Document{}, err
		}
	}
	common.Finalize(&doc)
	return doc, nil
}
