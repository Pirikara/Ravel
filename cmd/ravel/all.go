package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"ravel/internal/collectors/apk"
	"ravel/internal/collectors/bun"
	"ravel/internal/collectors/bundler"
	"ravel/internal/collectors/cargo"
	"ravel/internal/collectors/cocoapods"
	"ravel/internal/collectors/composer"
	"ravel/internal/collectors/conan"
	"ravel/internal/collectors/deno"
	"ravel/internal/collectors/dpkg"
	"ravel/internal/collectors/gomod"
	"ravel/internal/collectors/gradle"
	"ravel/internal/collectors/maven"
	"ravel/internal/collectors/mix"
	"ravel/internal/collectors/npm"
	"ravel/internal/collectors/nuget"
	"ravel/internal/collectors/oci"
	"ravel/internal/collectors/pnpm"
	"ravel/internal/collectors/pub"
	"ravel/internal/collectors/python"
	"ravel/internal/collectors/rpm"
	"ravel/internal/collectors/swiftpm"
	"ravel/internal/collectors/yarn"
	"ravel/internal/export"
	"ravel/internal/merge"
	"ravel/internal/model"
)

var staticManagers = []string{
	"bundler", "npm", "bun", "deno", "swiftpm", "nuget", "uv", "pylock",
	"requirements", "pnpm", "poetry", "yarn", "cargo", "composer", "conan", "cocoapods",
	"pipenv", "pdm", "go", "pub", "gradle", "maven", "mix", "dpkg", "apk", "rpm", "oci",
}

// runScanAll scans static manager inputs at the directory root, and nested
// subprojects when requested. It does not execute package managers.
func runScanAll(path, format, output, report string, strict, recursive bool) int {
	info, err := os.Stat(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ravel:", err)
		return 1
	}
	if !info.IsDir() {
		fmt.Fprintln(os.Stderr, "ravel: --all requires a directory")
		return 2
	}
	if report == "-" || report != "" && samePath(output, report) {
		fmt.Fprintln(os.Stderr, "ravel: output and report must be distinct files")
		return 2
	}
	var inputs []model.Document
	var skipped []model.Issue
	var observed []string
	project := filepath.Base(filepath.Clean(path))
	directories := []string{path}
	if recursive {
		directories, err = scanDirectories(path)
		if err != nil {
			fmt.Fprintln(os.Stderr, "ravel:", err)
			return 1
		}
	}
	for _, directory := range directories {
		foundManagers := map[string]bool{}
		chosenJS, ignoredJS, err := selectedJSManager(directory)
		if err != nil {
			fmt.Fprintln(os.Stderr, "ravel:", err)
			return 2
		}
		if chosenJS != "" {
			observed = append(observed, filepath.Join(directory, "package.json"))
		}
		for _, ignored := range ignoredJS {
			if samePath(output, ignored.Scope) || report != "" && samePath(report, ignored.Scope) {
				fmt.Fprintln(os.Stderr, "ravel: output and report cannot overwrite a lockfile")
				return 2
			}
		}
		skipped = append(skipped, ignoredJS...)
		for _, manager := range staticManagers {
			if chosenJS != "" && isJSManager(manager) && manager != chosenJS {
				continue
			}
			lock, _, err := selectLock(directory, true, manager)
			if err != nil {
				if manager == "pylock" && strings.Contains(err.Error(), "multiple pylock files") || manager == "rpm" && strings.Contains(err.Error(), "multiple RPM databases") {
					fmt.Fprintln(os.Stderr, "ravel:", err)
					return 2
				}
				continue
			}
			if manager == "go" && filepath.Base(lock) == "go.mod" || manager == "cargo" && filepath.Base(lock) == "Cargo.toml" || manager == "gradle" && (filepath.Base(lock) == "build.gradle" || filepath.Base(lock) == "build.gradle.kts") || manager == "swiftpm" && filepath.Base(lock) == "Package.swift" {
				skipped = append(skipped, model.Issue{Code: "collector_skipped_requires_resolve", Name: manager, Scope: lock})
				continue
			}
			if samePath(output, lock) || report != "" && samePath(report, lock) {
				fmt.Fprintln(os.Stderr, "ravel: output and report cannot overwrite an input")
				return 2
			}
			doc, err := collectStatic(manager, lock, filepath.Base(filepath.Clean(directory)))
			if err != nil {
				fmt.Fprintf(os.Stderr, "ravel: %s: %v\n", manager, err)
				return 1
			}
			for _, source := range doc.Sources {
				if samePath(output, source) || report != "" && samePath(report, source) {
					fmt.Fprintln(os.Stderr, "ravel: output and report cannot overwrite an included input")
					return 2
				}
			}
			inputs = append(inputs, doc)
			foundManagers[manager] = true
		}
		foundJS := foundManagers["npm"] || foundManagers["pnpm"] || foundManagers["yarn"] || foundManagers["bun"] || foundManagers["deno"]
		foundPython := foundManagers["uv"] || foundManagers["pylock"] || foundManagers["poetry"] || foundManagers["pipenv"] || foundManagers["pdm"] || foundManagers["requirements"]
		for _, manifest := range []struct {
			name    string
			covered bool
		}{
			{"package.json", foundJS},
			{"pyproject.toml", foundPython},
			{"Package.swift", foundManagers["swiftpm"]},
		} {
			if !manifest.covered {
				candidate := filepath.Join(directory, manifest.name)
				if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
					skipped = append(skipped, model.Issue{Code: "collector_skipped_missing_lockfile", Name: manifest.name, Scope: candidate})
				}
			}
		}
	}
	if len(inputs) == 0 {
		fmt.Fprintln(os.Stderr, "ravel: no statically scannable inputs found; Go, Cargo, Gradle, and SwiftPM manifests without lock data require --resolve --allow-exec in a separate scan")
		return 2
	}
	doc := inputs[0]
	if len(inputs) > 1 {
		doc, err = merge.Documents(project, inputs)
		if err != nil {
			fmt.Fprintln(os.Stderr, "ravel:", err)
			return 1
		}
	}
	if len(skipped) > 0 {
		doc.Coverage.Issues = append(doc.Coverage.Issues, skipped...)
		for _, issue := range skipped {
			if issue.Scope != "" {
				observed = append(observed, issue.Scope)
			}
			if strings.HasPrefix(issue.Code, "collector_skipped_") {
				doc.Coverage.GraphState = "partial"
				doc.Coverage.OriginState = "partial"
			}
		}
	}
	seenSources := map[string]bool{doc.Source: true}
	for _, source := range doc.Sources {
		seenSources[source] = true
	}
	for _, source := range observed {
		if samePath(output, source) || report != "" && samePath(report, source) {
			fmt.Fprintln(os.Stderr, "ravel: output and report cannot overwrite a discovered input")
			return 2
		}
		if !seenSources[source] {
			seenSources[source] = true
			doc.Sources = append(doc.Sources, source)
		}
	}
	var data []byte
	switch format {
	case "cyclonedx-json":
		data, err = export.CycloneDX(doc)
	case "spdx-json":
		data, err = export.SPDX23(doc)
	case "ravel-json":
		data, err = json.MarshalIndent(doc, "", "  ")
	default:
		fmt.Fprintln(os.Stderr, "ravel: unsupported format")
		return 2
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "ravel:", err)
		return 1
	}
	if err := write(output, append(data, '\n')); err != nil {
		fmt.Fprintln(os.Stderr, "ravel:", err)
		return 1
	}
	if report != "" {
		coverage, err := coverageReport(doc, format)
		if err != nil {
			fmt.Fprintln(os.Stderr, "ravel:", err)
			return 1
		}
		if err := write(report, append(coverage, '\n')); err != nil {
			fmt.Fprintln(os.Stderr, "ravel:", err)
			return 1
		}
	}
	fmt.Fprintf(os.Stderr, "ravel: %d inputs, %d packages, graph=%s, origin=%s\n", len(inputs), doc.Coverage.Packages, doc.Coverage.GraphState, doc.Coverage.OriginState)
	if strict && len(doc.Coverage.Issues) > 0 {
		return 3
	}
	return 0
}

func isJSManager(manager string) bool {
	switch manager {
	case "npm", "pnpm", "yarn", "bun":
		return true
	}
	return false
}

func selectedJSManager(directory string) (string, []model.Issue, error) {
	locks := map[string]string{}
	for _, manager := range []string{"npm", "pnpm", "yarn", "bun"} {
		if lock, _, err := selectLock(directory, true, manager); err == nil {
			locks[manager] = lock
		}
	}
	if len(locks) <= 1 {
		return "", nil, nil
	}
	data, err := os.ReadFile(filepath.Join(directory, "package.json"))
	if err != nil {
		return "", nil, fmt.Errorf("multiple JavaScript lockfiles in %s; package.json packageManager is required", directory)
	}
	var pkg struct {
		PackageManager string `json:"packageManager"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return "", nil, fmt.Errorf("invalid package.json in %s: %w", directory, err)
	}
	chosen := ""
	for manager := range locks {
		if strings.HasPrefix(pkg.PackageManager, manager+"@") {
			chosen = manager
		}
	}
	if chosen == "" {
		return "", nil, fmt.Errorf("multiple JavaScript lockfiles in %s; packageManager does not select one", directory)
	}
	var ignored []model.Issue
	for _, manager := range []string{"npm", "pnpm", "yarn", "bun"} {
		if manager != chosen && locks[manager] != "" {
			ignored = append(ignored, model.Issue{Code: "manager_lockfile_not_selected", Name: manager, Scope: locks[manager]})
		}
	}
	return chosen, ignored, nil
}

func scanDirectories(root string) ([]string, error) {
	dirs := map[string]bool{root: true}
	seen := 0
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		seen++
		if seen > 100000 {
			return fmt.Errorf("recursive scan exceeds 100000 entries")
		}
		if entry.IsDir() {
			if path != root {
				if entry.Name() == "blobs" {
					if _, err := os.Stat(filepath.Join(filepath.Dir(path), "oci-layout")); err == nil {
						return filepath.SkipDir
					}
				}
				switch entry.Name() {
				case ".git", ".hg", ".svn", "node_modules", ".pnpm-store", ".yarn", ".gradle", "target", "build", "dist", "Pods", ".venv", "venv", "__pycache__", ".cache", "testdata":
					return filepath.SkipDir
				case "vendor":
					if _, err := os.Stat(filepath.Join(path, "modules.txt")); err == nil {
						dirs[filepath.Dir(path)] = true
					}
					return filepath.SkipDir
				case "obj":
					if _, err := os.Stat(filepath.Join(path, "project.assets.json")); err == nil {
						dirs[filepath.Dir(path)] = true
					}
					return filepath.SkipDir
				}
			}
			return nil
		}
		name := entry.Name()
		if name == "status" && filepath.Base(filepath.Dir(path)) == "dpkg" && filepath.Base(filepath.Dir(filepath.Dir(path))) == "lib" && filepath.Base(filepath.Dir(filepath.Dir(filepath.Dir(path)))) == "var" {
			dirs[filepath.Dir(filepath.Dir(filepath.Dir(filepath.Dir(path))))] = true
		}
		if (name == "installed" || name == "installed.adb") && filepath.Base(filepath.Dir(path)) == "db" && filepath.Base(filepath.Dir(filepath.Dir(path))) == "apk" && filepath.Base(filepath.Dir(filepath.Dir(filepath.Dir(path)))) == "lib" {
			dirs[filepath.Dir(filepath.Dir(filepath.Dir(filepath.Dir(path))))] = true
		}
		if recursiveCandidate(name) {
			dirs[filepath.Dir(path)] = true
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	result := make([]string, 0, len(dirs))
	for directory := range dirs {
		result = append(result, directory)
	}
	sort.Strings(result)
	return result, nil
}

func recursiveCandidate(name string) bool {
	switch name {
	case "Gemfile.lock", "package-lock.json", "npm-shrinkwrap.json", "bun.lock", "deno.lock", "Package.resolved", "packages.lock.json", "uv.lock", "pnpm-lock.yaml", "poetry.lock", "Pipfile.lock", "pdm.lock", "go.mod", "pubspec.lock", "gradle.lockfile", "buildscript-gradle.lockfile", "build.gradle", "build.gradle.kts", "dependency-tree.json", "pom.xml", "yarn.lock", "Cargo.lock", "Cargo.toml", "composer.lock", "conan.lock", "mix.lock", "Podfile.lock", "package.json", "pyproject.toml", "Package.swift", "oci-layout":
		return true
	}
	return isPylockName(name) || name == "requirements.txt"
}

func collectStatic(manager, lock, project string) (model.Document, error) {
	switch manager {
	case "bundler":
		return bundler.Collect(lock, project)
	case "npm":
		return npm.Collect(lock, project)
	case "bun":
		return bun.Collect(lock, project)
	case "deno":
		return deno.Collect(lock, project)
	case "swiftpm":
		return swiftpm.Collect(lock, project)
	case "nuget":
		if filepath.Base(lock) == "project.assets.json" {
			return nuget.CollectAssets(lock, project)
		}
		return nuget.Collect(lock, project)
	case "nuget-archive":
		return nuget.CollectArchive(lock, project)
	case "uv":
		return python.CollectUV(lock, project)
	case "pylock":
		return python.CollectPylock(lock, project)
	case "requirements":
		return python.CollectRequirements(lock, project)
	case "pnpm":
		return pnpm.Collect(lock, project)
	case "poetry":
		return python.CollectPoetry(lock, project)
	case "yarn":
		return yarn.Collect(lock, project)
	case "cargo":
		return cargo.Collect(lock, project)
	case "composer":
		return composer.Collect(lock, project)
	case "conan":
		return conan.Collect(lock, project)
	case "cocoapods":
		return cocoapods.Collect(lock, project)
	case "pipenv":
		return python.CollectPipenv(lock, project)
	case "pdm":
		return python.CollectPDM(lock, project)
	case "go":
		return gomod.CollectVendor(lock, project)
	case "pub":
		return pub.Collect(lock, project)
	case "gradle":
		return gradle.Collect(lock, project)
	case "maven":
		if filepath.Base(lock) == "pom.xml" {
			return maven.CollectPOM(lock, project)
		}
		return maven.CollectTree(lock, project)
	case "mix":
		return mix.Collect(lock, project)
	case "dpkg":
		return dpkg.Collect(lock, project)
	case "apk":
		return apk.Collect(lock, project)
	case "rpm":
		return rpm.Collect(lock, project)
	case "oci":
		return oci.Collect(filepath.Dir(lock), project, "")
	}
	return model.Document{}, fmt.Errorf("unsupported manager %s", manager)
}
