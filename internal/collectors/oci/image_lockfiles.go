package oci

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Pirikara/Ravel/internal/collectors/bun"
	"github.com/Pirikara/Ravel/internal/collectors/bundler"
	"github.com/Pirikara/Ravel/internal/collectors/cargo"
	"github.com/Pirikara/Ravel/internal/collectors/composer"
	"github.com/Pirikara/Ravel/internal/collectors/condalock"
	"github.com/Pirikara/Ravel/internal/collectors/deno"
	"github.com/Pirikara/Ravel/internal/collectors/gomod"
	"github.com/Pirikara/Ravel/internal/collectors/gradle"
	"github.com/Pirikara/Ravel/internal/collectors/maven"
	"github.com/Pirikara/Ravel/internal/collectors/npm"
	"github.com/Pirikara/Ravel/internal/collectors/nuget"
	"github.com/Pirikara/Ravel/internal/collectors/pixi"
	"github.com/Pirikara/Ravel/internal/collectors/pnpm"
	"github.com/Pirikara/Ravel/internal/collectors/python"
	"github.com/Pirikara/Ravel/internal/collectors/renv"
	"github.com/Pirikara/Ravel/internal/collectors/sbt"
	"github.com/Pirikara/Ravel/internal/collectors/yarn"
	"github.com/Pirikara/Ravel/internal/model"
)

const (
	maxImageProjectFileBytes = 8 << 20
	maxImageProjectFiles     = 256
	maxImageProjectTotal     = 64 << 20
	maxImageLockRecords      = 50000
	maxImageLockEdges        = 200000
)

type imageProjectFile struct {
	data          []byte
	layer, status string
}

type imageLockDocument struct {
	name, scope, manager string
	doc                  model.Document
	origins              map[string][]model.Origin
	development          map[string][]model.Development
}

// Only static collectors are used. No package manager, image program, network
// resolver, or repository checkout is executed while inspecting these files.
func imageLockManager(name string) string {
	base := path.Base(name)
	switch base {
	case "package-lock.json", "npm-shrinkwrap.json", ".package-lock.json":
		return "npm"
	case "pnpm-lock.yaml":
		return "pnpm"
	case "yarn.lock":
		return "yarn"
	case "bun.lock":
		return "bun"
	case "deno.lock":
		return "deno"
	case "uv.lock":
		return "uv"
	case "poetry.lock":
		return "poetry"
	case "Pipfile.lock":
		return "pipenv"
	case "pdm.lock":
		return "pdm"
	case "composer.lock":
		return "composer"
	case "packages.lock.json":
		return "nuget"
	case "packages.config":
		return "nuget-config"
	case "project.assets.json":
		return "nuget-assets"
	case "Cargo.lock":
		return "cargo"
	case "go.mod":
		return "go"
	case "gradle.lockfile", "buildscript-gradle.lockfile":
		return "gradle"
	case "dependency-tree.json":
		return "maven"
	case "renv.lock":
		return "renv"
	case "conda-lock.yml", "conda-lock.yaml":
		return "conda-lock"
	case "pixi.lock":
		return "pixi"
	}
	if base == "Gemfile.lock" || strings.HasPrefix(base, "Gemfile.") && strings.HasSuffix(base, ".lock") {
		return "bundler"
	}
	if base == "pylock.toml" || strings.HasPrefix(base, "pylock.") && strings.HasSuffix(base, ".toml") {
		return "pylock"
	}
	if (base == "requirements.txt" || strings.HasPrefix(base, "requirements-") || strings.HasPrefix(base, "requirements.")) && strings.HasSuffix(base, ".txt") {
		return "requirements"
	}
	if strings.HasSuffix(base, ".sbt.lock") {
		return "sbt"
	}
	if strings.HasPrefix(base, "conda-lock.") && (strings.HasSuffix(base, ".yml") || strings.HasSuffix(base, ".yaml")) {
		return "conda-lock"
	}
	if (strings.HasPrefix(name, "requirements/") || strings.Contains(name, "/requirements/")) && strings.HasSuffix(base, ".txt") {
		return "requirements"
	}
	return ""
}

func isImageProjectFile(name string) bool {
	if path.Base(name) == "direct_url.json" && python.IsInstalledMetadataPath(path.Join(path.Dir(name), "METADATA")) {
		return true
	}
	if path.Base(name) == ".package-lock.json" && path.Base(path.Dir(name)) == "node_modules" {
		return true
	}
	for _, part := range strings.Split(name, "/") {
		if part == "node_modules" || part == "site-packages" || part == "dist-packages" || part == ".git" {
			return false
		}
	}
	if i := strings.LastIndex(name, "/gems/"); i >= 0 && isInstalledRubySpecPath(name[:i]+"/specifications/probe-1.0.0.gemspec") {
		return false
	}
	if imageLockManager(name) != "" {
		return true
	}
	if npm.IsInstalledPackagePath(name) {
		return false
	}
	// Installed package manifests are already handled by their collectors. Do
	// not stage thousands of node_modules/vendor sidecars as project manifests.
	for _, part := range strings.Split(name, "/") {
		if part == "node_modules" || part == "vendor" || part == ".git" {
			return false
		}
	}
	switch path.Base(name) {
	case "package.json", "pyproject.toml", "Cargo.toml", "pixi.toml", "go.work", "deno.json", "deno.jsonc":
		return true
	}
	return false
}

func collectImageLock(manager, file, project, root string) (model.Document, error) {
	switch manager {
	case "npm":
		return npm.Collect(file, project)
	case "pnpm":
		return pnpm.Collect(file, project)
	case "yarn":
		return yarn.Collect(file, project)
	case "bun":
		return bun.Collect(file, project)
	case "deno":
		return deno.Collect(file, project)
	case "bundler":
		return bundler.Collect(file, project)
	case "uv":
		return python.CollectUV(file, project)
	case "poetry":
		return python.CollectPoetry(file, project)
	case "pdm":
		return python.CollectPDM(file, project)
	case "pipenv":
		return python.CollectPipenv(file, project)
	case "pylock":
		return python.CollectPylock(file, project)
	case "requirements":
		return python.CollectRequirementsWithin(file, project, root)
	case "composer":
		return composer.Collect(file, project)
	case "nuget":
		return nuget.Collect(file, project)
	case "nuget-assets":
		return nuget.CollectAssets(file, project)
	case "nuget-config":
		return nuget.CollectPackagesConfig(file, project)
	case "cargo":
		return cargo.Collect(file, project)
	case "go":
		return gomod.CollectManifest(file, project)
	case "gradle":
		return gradle.Collect(file, project)
	case "maven":
		return maven.CollectTree(file, project)
	case "sbt":
		return sbt.CollectLock(file, project)
	case "renv":
		return renv.CollectLock(file, project)
	case "conda-lock":
		return condalock.CollectLock(file, project)
	default:
		return pixi.CollectLock(file, project)
	}
}

func parseImageLocks(files map[string]imageProjectFile, project string) ([]imageLockDocument, []model.Issue, error) {
	if len(files) == 0 {
		return nil, nil, nil
	}
	root, err := os.MkdirTemp("", "ravel-image-locks-")
	if err != nil {
		return nil, nil, err
	}
	defer os.RemoveAll(root)
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	var issues []model.Issue
	for _, name := range names {
		state := files[name]
		if state.status != "" {
			issues = append(issues, model.Issue{Code: "image_project_file_" + state.status, Name: name})
			continue
		}
		file := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(file), 0700); err != nil {
			return nil, nil, err
		}
		if err := os.WriteFile(file, state.data, 0600); err != nil {
			return nil, nil, err
		}
	}
	var locks []imageLockDocument
	records, edges := 0, 0
	for _, name := range names {
		manager := imageLockManager(name)
		if manager == "" || files[name].status != "" {
			continue
		}
		parsed, err := collectImageLock(manager, filepath.Join(root, filepath.FromSlash(name)), project, root)
		if err != nil {
			issues = append(issues, model.Issue{Code: "image_lockfile_invalid", Name: name})
			continue
		}
		records += len(parsed.Components)
		edges += len(parsed.Edges)
		if records > maxImageLockRecords || edges > maxImageLockEdges {
			issues = append(issues, model.Issue{Code: "image_lockfile_scan_limited", Name: name})
			break
		}
		rewrite := func(e *model.Evidence) {
			relative, err := filepath.Rel(root, e.InputPath)
			if err != nil || !filepath.IsLocal(relative) {
				*e = model.Evidence{}
				return
			}
			imagePath := filepath.ToSlash(relative)
			state, ok := files[imagePath]
			if !ok || state.status != "" {
				*e = model.Evidence{}
				return
			}
			e.InputPath = "oci:" + state.layer + "!/" + imagePath
			hash := sha256.Sum256(state.data)
			e.InputDigest = "sha256:" + hex.EncodeToString(hash[:])
			e.Method = "image-lockfile-correlation"
		}
		for i := range parsed.Components {
			for j := range parsed.Components[i].Evidence {
				rewrite(&parsed.Components[i].Evidence[j])
			}
		}
		for i := range parsed.Edges {
			rewrite(&parsed.Edges[i].Evidence)
		}
		for i := range parsed.Origins {
			rewrite(&parsed.Origins[i].Evidence)
		}
		for i := range parsed.Development {
			rewrite(&parsed.Development[i].Evidence)
		}
		scope := path.Dir(name)
		if manager == "requirements" {
			if prefix, _, ok := strings.Cut(name, "/requirements/"); ok {
				scope = prefix
			}
		}
		if manager == "nuget-assets" {
			if prefix, _, ok := strings.Cut(name, "/obj/"); ok {
				scope = prefix
			}
		}
		if path.Base(name) == ".package-lock.json" && path.Base(scope) == "node_modules" {
			scope = path.Dir(scope)
		}
		lock := imageLockDocument{name: name, scope: scope, manager: manager, doc: parsed, origins: map[string][]model.Origin{}, development: map[string][]model.Development{}}
		for _, origin := range parsed.Origins {
			lock.origins[origin.Occurrence] = append(lock.origins[origin.Occurrence], origin)
		}
		for _, development := range parsed.Development {
			lock.development[development.Occurrence] = append(lock.development[development.Occurrence], development)
		}
		locks = append(locks, lock)
	}
	return locks, issues, nil
}
