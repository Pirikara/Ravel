package main

import (
	"bytes"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

const maxGitSubmodules = 32
const maxGitSubmoduleDepth = 3

type gitSubmodule struct {
	Path, URL, Commit string
}

type gitSubmoduleConfig struct {
	path, url string
}

func fetchGitSubmodules(root, checkout string, parent *url.URL) ([]gitSubmodule, []string, error) {
	submodules := []gitSubmodule{}
	depthLimited := []string{}
	err := fetchNestedGitSubmodules(root, checkout, parent, "", 0, &submodules, &depthLimited)
	return submodules, depthLimited, err
}

func fetchNestedGitSubmodules(root, checkout string, parent *url.URL, scope string, depth int, collected *[]gitSubmodule, depthLimited *[]string) error {
	if depth == maxGitSubmoduleDepth {
		gitlinks, err := remoteGitlinks(root, checkout, parent.Scheme)
		if err != nil {
			return fmt.Errorf("submodule %q: %w", scope, err)
		}
		if len(gitlinks) != 0 {
			*depthLimited = append(*depthLimited, scope)
		}
		return nil
	}
	submodules, err := configuredGitSubmodules(root, checkout, parent)
	if err != nil {
		return err
	}
	if len(*collected)+len(submodules) > maxGitSubmodules {
		return errors.New("remote Git checkout exceeds total submodule limit")
	}
	for i := range submodules {
		item := submodules[i]
		location := filepath.Join(checkout, filepath.FromSlash(item.Path))
		item.Path = path.Join(scope, item.Path)
		if err := prepareSubmoduleDirectory(checkout, submodules[i].Path); err != nil {
			return err
		}
		if _, err := remoteGitCommand(root, location, parent.Scheme, false, "init", "--quiet"); err != nil {
			return fmt.Errorf("could not initialize submodule %q", item.Path)
		}
		if _, err := remoteGitCommand(root, location, parent.Scheme, false, "remote", "add", "origin", item.URL); err != nil {
			return fmt.Errorf("could not configure submodule %q", item.Path)
		}
		if _, err := remoteGitCommand(root, location, parent.Scheme, false, "fetch", "--depth", "1", "--no-tags", "origin", item.Commit); err != nil {
			return fmt.Errorf("submodule %q fetch failed or exceeded its time or size limit", item.Path)
		}
		fetched, err := remoteGitCommand(root, location, parent.Scheme, false, "rev-parse", "--verify", "FETCH_HEAD^{commit}")
		if err != nil || strings.TrimSpace(fetched) != item.Commit {
			return fmt.Errorf("submodule %q did not resolve to its pinned commit", item.Path)
		}
		if _, err := remoteGitCommand(root, location, parent.Scheme, true, "-c", "core.hooksPath="+os.DevNull, "checkout", "--detach", "--force", item.Commit); err != nil {
			return fmt.Errorf("submodule %q checkout failed or exceeded its time or size limit", item.Path)
		}
		if err := checkRemoteGitTree(root, location); err != nil {
			return fmt.Errorf("submodule %q: %w", item.Path, err)
		}
		*collected = append(*collected, item)
		child, err := validateGitURL(item.URL)
		if err != nil {
			return fmt.Errorf("submodule %q has an invalid URL", item.Path)
		}
		if err := fetchNestedGitSubmodules(root, location, child, item.Path, depth+1, collected, depthLimited); err != nil {
			return err
		}
	}
	return nil
}

func configuredGitSubmodules(root, checkout string, parent *url.URL) ([]gitSubmodule, error) {
	gitlinks, err := remoteGitlinks(root, checkout, parent.Scheme)
	if err != nil {
		return nil, err
	}
	manifest := filepath.Join(checkout, ".gitmodules")
	info, err := os.Lstat(manifest)
	if errors.Is(err, os.ErrNotExist) {
		if len(gitlinks) != 0 {
			return nil, errors.New("Git tree contains submodules without .gitmodules URLs")
		}
		return nil, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Size() > 256<<10 {
		return nil, errors.New("invalid or oversized .gitmodules")
	}
	out, err := remoteGitCommand(root, checkout, parent.Scheme, false, "config", "--no-includes", "-z", "-f", ".gitmodules", "--get-regexp", `^submodule\..*\.(path|url)$`)
	if err != nil {
		return nil, errors.New("could not read .gitmodules")
	}
	configured := map[string]*gitSubmoduleConfig{}
	for _, record := range bytes.Split([]byte(out), []byte{0}) {
		if len(record) == 0 {
			continue
		}
		key, value, ok := strings.Cut(string(record), "\n")
		if !ok || !strings.HasPrefix(key, "submodule.") {
			return nil, errors.New("malformed .gitmodules entry")
		}
		field := ""
		if strings.HasSuffix(key, ".path") {
			field = "path"
		} else if strings.HasSuffix(key, ".url") {
			field = "url"
		} else {
			return nil, errors.New("malformed .gitmodules key")
		}
		name := strings.TrimSuffix(strings.TrimPrefix(key, "submodule."), "."+field)
		if name == "" || len(configured) >= maxGitSubmodules && configured[name] == nil {
			return nil, errors.New("remote Git checkout exceeds submodule limit")
		}
		entry := configured[name]
		if entry == nil {
			entry = &gitSubmoduleConfig{}
			configured[name] = entry
		}
		if field == "path" {
			if entry.path != "" {
				return nil, errors.New("duplicate .gitmodules path setting")
			}
			entry.path = value
		} else {
			if entry.url != "" {
				return nil, errors.New("duplicate .gitmodules URL setting")
			}
			entry.url = value
		}
	}
	if len(configured) == 0 {
		return nil, errors.New(".gitmodules contains no submodule path and URL pairs")
	}
	if len(configured) != len(gitlinks) {
		return nil, errors.New(".gitmodules does not cover every pinned submodule")
	}
	result := make([]gitSubmodule, 0, len(configured))
	paths := map[string]bool{}
	for _, entry := range configured {
		if !safeSubmodulePath(entry.path) || entry.url == "" || paths[entry.path] {
			return nil, errors.New("invalid or duplicate submodule path or URL")
		}
		paths[entry.path] = true
		resolvedURL, err := resolveSubmoduleURL(parent, entry.url)
		if err != nil {
			return nil, fmt.Errorf("submodule %q: %w", entry.path, err)
		}
		commit, exists := gitlinks[entry.path]
		if !exists {
			return nil, fmt.Errorf("submodule %q has no pinned Git commit", entry.path)
		}
		result = append(result, gitSubmodule{Path: entry.path, URL: resolvedURL, Commit: commit})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Path < result[j].Path })
	return result, nil
}

func remoteGitlinks(root, checkout, scheme string) (map[string]string, error) {
	out, err := remoteGitCommandWithLimit(root, checkout, scheme, false, 32<<20, "ls-tree", "-r", "-z", "HEAD")
	if err != nil {
		return nil, errors.New("could not inspect Git tree for submodules within 32 MiB limit")
	}
	links := map[string]string{}
	for _, record := range bytes.Split([]byte(out), []byte{0}) {
		if len(record) == 0 || !bytes.HasPrefix(record, []byte("160000 ")) {
			continue
		}
		_, pathBytes, ok := bytes.Cut(record, []byte{'\t'})
		if !ok || !safeSubmodulePath(string(pathBytes)) {
			return nil, errors.New("Git tree contains an unsafe submodule path")
		}
		commit, err := parseSubmoduleGitlink(string(record), string(pathBytes))
		if err != nil {
			return nil, err
		}
		if len(links) >= maxGitSubmodules || links[string(pathBytes)] != "" {
			return nil, errors.New("remote Git checkout exceeds submodule limit or repeats a path")
		}
		links[string(pathBytes)] = commit
	}
	return links, nil
}

func safeSubmodulePath(value string) bool {
	if value == "" || !utf8.ValidString(value) || path.IsAbs(value) || path.Clean(value) != value || !filepath.IsLocal(filepath.FromSlash(value)) {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == ".git" || segment == ".." || segment == "." {
			return false
		}
	}
	return true
}

func parseSubmoduleGitlink(out, wanted string) (string, error) {
	parts := bytes.Split(bytes.TrimSuffix([]byte(out), []byte{0}), []byte{0})
	if len(parts) != 1 {
		return "", fmt.Errorf("submodule %q has an ambiguous gitlink", wanted)
	}
	metadata, foundPath, ok := bytes.Cut(parts[0], []byte{'\t'})
	fields := strings.Fields(string(metadata))
	if !ok || string(foundPath) != wanted || len(fields) != 3 || fields[0] != "160000" || fields[1] != "commit" || !gitCommitID.MatchString(fields[2]) {
		return "", fmt.Errorf("submodule %q has no pinned Git commit", wanted)
	}
	return fields[2], nil
}

func resolveSubmoduleURL(parent *url.URL, raw string) (string, error) {
	if strings.HasPrefix(raw, "./") || strings.HasPrefix(raw, "../") {
		base := *parent
		base.Path = strings.TrimSuffix(base.Path, "/") + "/"
		raw = base.ResolveReference(&url.URL{Path: raw}).String()
	}
	resolved, err := validateGitURL(raw)
	if err != nil || resolved.Scheme != parent.Scheme || resolved.Host != parent.Host || gitURLUser(resolved) != gitURLUser(parent) {
		return "", errors.New("submodule URL must use the parent Git transport, host, and user")
	}
	if parent.Scheme == "file" {
		parentDirectory, err := filepath.EvalSymlinks(filepath.Dir(parent.Path))
		if err != nil {
			return "", errors.New("cannot resolve parent file repository directory")
		}
		target, err := filepath.EvalSymlinks(resolved.Path)
		if err != nil {
			return "", errors.New("cannot resolve file submodule repository")
		}
		relative, err := filepath.Rel(parentDirectory, target)
		if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return "", errors.New("file submodule URL is outside the parent repository directory")
		}
	}
	return raw, nil
}

func gitURLUser(value *url.URL) string {
	if value.User == nil {
		return ""
	}
	return value.User.Username()
}

func prepareSubmoduleDirectory(checkout, relative string) error {
	current := checkout
	for _, segment := range strings.Split(relative, "/") {
		current = filepath.Join(current, segment)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			if err := os.Mkdir(current, 0o700); err != nil {
				return err
			}
			continue
		}
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("submodule path is not a regular directory")
		}
	}
	entries, err := os.ReadDir(current)
	if err != nil || len(entries) != 0 {
		return errors.New("submodule checkout directory is not empty")
	}
	return nil
}
