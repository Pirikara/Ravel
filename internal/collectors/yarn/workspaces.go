package yarn

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	semver "github.com/Masterminds/semver/v3"
	"github.com/Pirikara/Ravel/internal/collectors/common"
	"github.com/Pirikara/Ravel/internal/licensing"
	"github.com/Pirikara/Ravel/internal/model"
)

type classicWorkspace struct {
	ref, directory, input string
	manifest              classicManifest
	data                  []byte
}

// Workspace membership supplies independent scan roots, never dependency edges.
// Classic locks omit local workspace records, so static manifests supply those
// identities; lock selectors still supply external dependency identities.
func collectClassicWorkspaces(doc *model.Document, lockfile string, manifest classicManifest) []classicWorkspace {
	raw := bytes.TrimSpace(manifest.Workspaces)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return nil
	}
	issue := func(name string) {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "workspace_unresolved", Name: name})
	}
	var patterns []string
	if json.Unmarshal(raw, &patterns) != nil {
		var object struct {
			Packages []string `json:"packages"`
		}
		if json.Unmarshal(raw, &object) != nil {
			issue("invalid Yarn workspace patterns")
			return nil
		}
		patterns = object.Packages
	}
	if len(patterns) == 0 {
		return nil
	}
	if private := bytes.TrimSpace(manifest.Private); !bytes.Equal(private, []byte("true")) && !bytes.Equal(private, []byte(`"true"`)) {
		issue("Yarn workspaces require a private root")
		return nil
	}
	if len(patterns) > 256 {
		issue("Yarn workspace pattern limit")
		return nil
	}
	var expanded [][]string
	for _, pattern := range patterns {
		parts, err := classicWorkspacePatterns(pattern)
		if err != nil {
			issue("unsupported Yarn workspace pattern")
			continue
		}
		expanded = append(expanded, parts...)
		if len(expanded) > 256 {
			issue("Yarn workspace pattern limit")
			return nil
		}
	}
	if len(expanded) == 0 {
		return nil
	}
	root, err := os.OpenRoot(filepath.Dir(lockfile))
	if err != nil {
		issue("Yarn workspace root unavailable")
		return nil
	}
	defer root.Close()
	var workspaces []classicWorkspace
	visited := 0
	err = fs.WalkDir(root.FS(), ".", func(directory string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			issue("Yarn workspace directory unavailable")
			return fs.SkipDir
		}
		visited++
		if visited > 50000 || len(workspaces) >= 4096 {
			return fmt.Errorf("Yarn workspace scan limit")
		}
		if directory == "." {
			return nil
		}
		if entry.Name() == "node_modules" || entry.Name() == ".git" {
			if entry.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		segments := strings.Split(directory, "/")
		possible, matched := false, false
		for _, pattern := range expanded {
			possible = possible || classicWorkspaceMatch(pattern, segments, true)
			matched = matched || classicWorkspaceMatch(pattern, segments, false)
		}
		if entry.Type()&os.ModeSymlink != 0 {
			if possible {
				issue("Yarn workspace symlink directory")
			}
			return nil
		}
		if !entry.IsDir() {
			return nil
		}
		if !possible {
			return fs.SkipDir
		}
		if len(segments) > 64 {
			issue("Yarn workspace depth limit")
			return fs.SkipDir
		}
		if !matched {
			return nil
		}
		data, input, err := common.ReadLocalNodeManifest(lockfile, directory)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			issue("Yarn workspace manifest unavailable")
			return nil
		}
		doc.Sources = append(doc.Sources, input)
		var local classicManifest
		if json.Unmarshal(data, &local) != nil || !classicName.MatchString(local.Name) {
			issue("invalid Yarn workspace manifest")
			return nil
		}
		ref := "yarn-workspace:" + common.ID(directory)
		evidence := common.Evidence(input, "yarn-workspace-manifest", "/name", data)
		component := model.Component{ID: ref, Kind: "application", Name: local.Name, Version: local.Version, Context: "workspace=" + directory, Evidence: []model.Evidence{evidence}, Licenses: licensing.JSONFields(data, evidence)}
		if _, err := semver.StrictNewVersion(local.Version); err != nil {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "workspace_version_unresolved", Name: local.Name})
		}
		doc.Components = append(doc.Components, component)
		doc.Origins = append(doc.Origins, model.Origin{Occurrence: ref, Kind: "local", Status: "declared", Target: directory, Evidence: evidence})
		common.CollectNodeDevelopment(doc, ref, data, common.Evidence(input, "yarn-workspace-manifest", "", data))
		workspaces = append(workspaces, classicWorkspace{ref: ref, directory: directory, input: input, manifest: local, data: data})
		return nil
	})
	if err != nil {
		issue("Yarn workspace scan limit or unreadable directory")
	}
	names := map[string]bool{}
	for _, workspace := range workspaces {
		if names[workspace.manifest.Name] {
			issue("duplicate Yarn workspace name")
		}
		names[workspace.manifest.Name] = true
	}
	return workspaces
}

func classicWorkspaceTarget(doc *model.Document, workspaces []classicWorkspace, name, required string) (string, bool) {
	var candidates []classicWorkspace
	for _, workspace := range workspaces {
		if workspace.manifest.Name == name {
			candidates = append(candidates, workspace)
		}
	}
	if len(candidates) == 0 {
		return "", true
	}
	issue := func(code string) {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: code, Name: name})
	}
	if len(candidates) > 1 {
		issue("ambiguous_dependency")
		return "", false
	}
	version, err := semver.StrictNewVersion(candidates[0].manifest.Version)
	if err != nil {
		issue("workspace_version_unresolved")
		return "", false
	}
	constraint, err := semver.NewConstraint(required)
	if err != nil { // Non-semver locators are not Yarn Classic workspace links.
		return "", true
	}
	if constraint.Check(version) {
		return candidates[0].ref, true
	}
	return "", true // Yarn installs the registry version for an incompatible range.
}

// Support path globs, globstar, and bounded comma brace alternatives. More
// complex expressions stay explicit in coverage instead of silently guessing.
func classicWorkspacePatterns(pattern string) ([][]string, error) {
	pattern = strings.TrimSuffix(strings.TrimPrefix(pattern, "./"), "/")
	if len(pattern) > 4096 || pattern == "" || pattern == "." || path.IsAbs(pattern) || strings.ContainsAny(pattern, "\\\x00\r\n()!") {
		return nil, fmt.Errorf("unsupported workspace pattern")
	}
	pending := []string{pattern}
	var result [][]string
	for len(pending) > 0 {
		current := pending[0]
		pending = pending[1:]
		if start := strings.IndexByte(current, '{'); start >= 0 {
			end := strings.IndexByte(current[start:], '}')
			if end < 0 {
				return nil, fmt.Errorf("invalid braces")
			}
			end += start
			values := strings.Split(current[start+1:end], ",")
			if len(values) < 2 {
				return nil, fmt.Errorf("unsupported brace range")
			}
			for _, value := range values {
				if value == "" || strings.ContainsAny(value, "{}") {
					return nil, fmt.Errorf("invalid brace alternative")
				}
				pending = append(pending, current[:start]+value+current[end+1:])
			}
			if len(pending)+len(result) > 256 {
				return nil, fmt.Errorf("workspace expansion limit")
			}
			continue
		}
		parts := strings.Split(current, "/")
		for _, part := range parts {
			if part == "" || part == "." || part == ".." || strings.ContainsAny(part, "{}") {
				return nil, fmt.Errorf("non-local workspace pattern")
			}
			if part != "**" {
				if _, err := path.Match(part, ""); err != nil {
					return nil, err
				}
			}
		}
		result = append(result, parts)
	}
	return result, nil
}

func classicWorkspaceMatch(pattern, directory []string, prefix bool) bool {
	memo := map[[2]int]bool{}
	seen := map[[2]int]bool{}
	var match func(int, int) bool
	match = func(p, n int) bool {
		key := [2]int{p, n}
		if seen[key] {
			return memo[key]
		}
		seen[key] = true
		found := false
		if n == len(directory) {
			found = prefix || p == len(pattern)
			if !found && p < len(pattern) && pattern[p] == "**" {
				found = match(p+1, n)
			}
		} else if p < len(pattern) {
			if pattern[p] == "**" {
				found = match(p+1, n) || (!strings.HasPrefix(directory[n], ".") && match(p, n+1))
			} else if !strings.HasPrefix(directory[n], ".") || strings.HasPrefix(pattern[p], ".") {
				ok, _ := path.Match(pattern[p], directory[n])
				found = ok && match(p+1, n+1)
			}
		}
		memo[key] = found
		return found
	}
	return match(0, 0)
}
