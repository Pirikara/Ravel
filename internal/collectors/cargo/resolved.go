package cargo

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/Pirikara/Ravel/internal/collectors/common"
	"github.com/Pirikara/Ravel/internal/model"
	"github.com/Pirikara/Ravel/internal/safeurl"
)

const maxMetadataOutput = 64 << 20

type metadataDepKind struct {
	Kind   string `json:"kind"`
	Target string `json:"target"`
}

type metadataOutput struct {
	Version          int      `json:"version"`
	WorkspaceMembers []string `json:"workspace_members"`
	Packages         []struct {
		ID         string `json:"id"`
		Name       string `json:"name"`
		Version    string `json:"version"`
		Source     string `json:"source"`
		Repository string `json:"repository"`
	} `json:"packages"`
	Resolve *struct {
		Root  string `json:"root"`
		Nodes []struct {
			ID           string   `json:"id"`
			Dependencies []string `json:"dependencies"`
			Deps         []struct {
				Name     string            `json:"name"`
				Package  string            `json:"pkg"`
				DepKinds []metadataDepKind `json:"dep_kinds"`
			} `json:"deps"`
		} `json:"nodes"`
	} `json:"resolve"`
}

type cappedMetadata struct {
	buffer   bytes.Buffer
	exceeded bool
}

func (w *cappedMetadata) Write(p []byte) (int, error) {
	remaining := maxMetadataOutput - w.buffer.Len()
	if remaining < len(p) {
		w.exceeded = true
	}
	if remaining > 0 {
		if remaining > len(p) {
			remaining = len(p)
		}
		_, _ = w.buffer.Write(p[:remaining])
	}
	return len(p), nil
}

// CollectResolved asks Cargo for the host-platform, default-feature graph.
// Cargo's --offline prevents Cargo network access, while --locked protects an
// existing lockfile. Without Cargo.lock, Cargo may create one in the project.
func CollectResolved(manifest, project string, networkAllow bool) (model.Document, error) {
	if filepath.Base(manifest) != "Cargo.toml" {
		return model.Document{}, errors.New("Cargo resolver requires Cargo.toml")
	}
	if _, err := os.Stat(manifest); err != nil {
		return model.Document{}, err
	}
	absManifest, err := filepath.Abs(manifest)
	if err != nil {
		return model.Document{}, err
	}
	args := []string{"metadata", "--format-version", "1", "--manifest-path", absManifest, "--filter-platform", "host-tuple"}
	if !networkAllow {
		args = append(args, "--offline")
	}
	if stat, err := os.Stat(filepath.Join(filepath.Dir(manifest), "Cargo.lock")); err == nil && !stat.IsDir() {
		args = append(args, "--locked")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "cargo", args...)
	cmd.Dir = filepath.Dir(manifest)
	output := &cappedMetadata{}
	cmd.Stdout = output
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return model.Document{}, fmt.Errorf("Cargo metadata timed out: %w", ctx.Err())
		}
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return model.Document{}, fmt.Errorf("Cargo metadata failed (exit code %d)", exit.ExitCode())
		}
		return model.Document{}, fmt.Errorf("Cargo metadata failed: %w", err)
	}
	if output.exceeded {
		return model.Document{}, errors.New("Cargo metadata exceeded size limit")
	}
	return collectMetadata(manifest, project, output.buffer.Bytes())
}

func collectMetadata(manifest, project string, data []byte) (model.Document, error) {
	var metadata metadataOutput
	if err := json.Unmarshal(data, &metadata); err != nil {
		return model.Document{}, fmt.Errorf("invalid Cargo metadata: %w", err)
	}
	if metadata.Version != 1 || metadata.Resolve == nil || len(metadata.Resolve.Nodes) == 0 || len(metadata.Resolve.Nodes) > 100000 {
		return model.Document{}, errors.New("unsupported Cargo metadata version or empty graph")
	}
	packages := map[string]struct{ Name, Version, Source, Repository string }{}
	for _, pkg := range metadata.Packages {
		if pkg.ID == "" || pkg.Name == "" || pkg.Version == "" {
			return model.Document{}, errors.New("Cargo metadata package missing identity")
		}
		if _, exists := packages[pkg.ID]; exists {
			return model.Document{}, errors.New("duplicate Cargo metadata package ID")
		}
		packages[pkg.ID] = struct{ Name, Version, Source, Repository string }{pkg.Name, pkg.Version, pkg.Source, pkg.Repository}
	}
	rootID := metadata.Resolve.Root
	if rootID == "" && len(metadata.WorkspaceMembers) == 0 {
		return model.Document{}, errors.New("Cargo metadata has no root or workspace members")
	}
	ids := map[string]string{}
	seenNodes := map[string]bool{}
	for _, node := range metadata.Resolve.Nodes {
		if node.ID == "" || seenNodes[node.ID] {
			return model.Document{}, errors.New("invalid or duplicate Cargo graph node")
		}
		seenNodes[node.ID] = true
		if _, exists := packages[node.ID]; !exists {
			return model.Document{}, errors.New("Cargo graph node missing package metadata")
		}
		ids[node.ID] = "cargo:" + common.ID(node.ID)
	}
	if rootID != "" {
		if !seenNodes[rootID] {
			return model.Document{}, errors.New("Cargo graph root node missing")
		}
		ids[rootID] = "root"
	}
	doc := common.NewDocument(manifest, project, "cargo", data)
	doc.Coverage.Platforms = []string{"host-tuple"}
	input := "cargo metadata"
	for i, node := range metadata.Resolve.Nodes {
		pkg := packages[node.ID]
		ev := common.Evidence(input, "cargo-metadata", fmt.Sprintf("/resolve/nodes/%d", i), data)
		ev.Method = "resolver-output"
		if node.ID != rootID {
			component := model.Component{ID: ids[node.ID], Kind: "package", Name: pkg.Name, Version: pkg.Version, Context: "target=host-tuple,features=default", Evidence: []model.Evidence{ev}}
			if pkg.Source == "" {
				component.Kind = "application"
			} else {
				component.PURL = cargoPURL(pkg.Name, pkg.Version, pkg.Source)
			}
			doc.Components = append(doc.Components, component)
			kind, source, revision := cargoSource(pkg.Source)
			switch {
			case kind == "local":
				doc.Origins = append(doc.Origins, model.Origin{Occurrence: component.ID, Kind: "local", Status: "declared", Evidence: ev})
			case source != "":
				clean := safeurl.Clean(source)
				if clean == "" {
					doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unsafe_or_invalid_source", Name: pkg.Name})
				} else {
					doc.Origins = append(doc.Origins, model.Origin{Occurrence: component.ID, Kind: kind, SafeURL: clean, Revision: revision, Status: "declared", Evidence: ev})
				}
			default:
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "missing_source", Name: pkg.Name})
			}
			if pkg.Repository != "" {
				clean := safeurl.Clean(pkg.Repository)
				if clean != "" {
					doc.Development = append(doc.Development, model.Development{Occurrence: component.ID, SafeURL: clean, Status: "declared", Evidence: ev})
				} else {
					doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unsafe_or_invalid_source", Name: pkg.Name})
				}
			}
		}
		if len(node.Deps) == 0 && len(node.Dependencies) > 0 {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "cargo_dep_kinds_unavailable", Name: pkg.Name})
			for j, dependency := range node.Dependencies {
				to, ok := ids[dependency]
				if !ok || to == "root" || dependency == node.ID {
					return model.Document{}, errors.New("Cargo graph has dangling or self dependency")
				}
				kind := "depends_on"
				if node.ID == rootID {
					kind = "direct"
				}
				edgeEvidence := ev
				edgeEvidence.Pointer = fmt.Sprintf("/resolve/nodes/%d/dependencies/%d", i, j)
				doc.Edges = append(doc.Edges, model.Edge{From: ids[node.ID], To: to, Kind: kind, Condition: "kind_or_target_unavailable", Evidence: edgeEvidence})
			}
		}
		seenEdges := map[string]bool{}
		for j, dep := range node.Deps {
			to, ok := ids[dep.Package]
			if !ok || to == "root" || dep.Package == node.ID {
				return model.Document{}, errors.New("Cargo graph has dangling or self dependency")
			}
			if len(dep.DepKinds) == 0 {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "cargo_dep_kinds_unavailable", Name: packages[dep.Package].Name})
				dep.DepKinds = append(dep.DepKinds, metadataDepKind{Kind: "unknown"})
			}
			for k, detail := range dep.DepKinds {
				condition := ""
				if detail.Kind != "" {
					condition = "kind=" + detail.Kind
				}
				if detail.Target != "" {
					if condition != "" {
						condition += " && "
					}
					condition += "target=" + detail.Target
				}
				if condition != "" {
					doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "conditional_graph", Name: packages[dep.Package].Name})
				}
				key := to + "\x00" + condition
				if seenEdges[key] {
					continue
				}
				seenEdges[key] = true
				kind := "depends_on"
				if node.ID == rootID {
					kind = "direct"
				}
				edgeEvidence := ev
				edgeEvidence.Pointer = fmt.Sprintf("/resolve/nodes/%d/deps/%d/dep_kinds/%d", i, j, k)
				doc.Edges = append(doc.Edges, model.Edge{From: ids[node.ID], To: to, Kind: kind, Condition: condition, Evidence: edgeEvidence})
			}
		}
	}
	for _, member := range metadata.WorkspaceMembers {
		if !seenNodes[member] {
			return model.Document{}, errors.New("Cargo workspace member missing from graph")
		}
		if member == rootID {
			continue
		}
		ev := common.Evidence(input, "cargo-metadata", "/workspace_members", data)
		ev.Method = "resolver-output"
		doc.Edges = append(doc.Edges, model.Edge{From: "root", To: ids[member], Kind: "direct", Evidence: ev})
	}
	common.Finalize(&doc)
	return doc, nil
}
