package deno

import (
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/evanw/esbuild/pkg/api"
	"github.com/tailscale/hujson"

	"ravel/internal/collectors/common"
	"ravel/internal/model"
)

type sourceImport struct {
	specifier string
	path      string
	evidence  model.Evidence
}

const (
	maxSourceFiles = 2000
	maxSourceFile  = 2 << 20
	maxSourceBytes = 64 << 20
)

var skippedSourceDirs = map[string]bool{
	".git": true, ".deno": true, ".next": true, ".output": true,
	"node_modules": true, "vendor": true, "dist": true, "build": true,
	"coverage": true,
}

// scanSourceImports parses project source files as data. It never resolves a
// package or runs source code. The full source tree is the scan scope because
// deno.json tasks and runtime-selected entry points cannot be inferred safely.
func scanSourceImports(base string) ([]sourceImport, []string, []model.Issue) {
	var imports []sourceImport
	var sources []string
	var issues []model.Issue
	totalBytes := int64(0)
	err := filepath.WalkDir(base, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			issues = append(issues, model.Issue{Code: "source_scan_limited", Scope: path})
			return nil
		}
		if entry.IsDir() {
			if path != base && skippedSourceDirs[entry.Name()] {
				return filepath.SkipDir
			}
			if path != base && hasNestedDenoProject(path) {
				issues = append(issues, model.Issue{Code: "source_scan_limited", Scope: path})
				return filepath.SkipDir
			}
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return nil
		}
		if strings.HasSuffix(entry.Name(), ".d.ts") || strings.HasSuffix(entry.Name(), ".d.mts") || strings.HasSuffix(entry.Name(), ".d.cts") {
			return nil
		}
		loader, ok := sourceLoader(filepath.Ext(entry.Name()))
		if !ok {
			return nil
		}
		info, err := entry.Info()
		if err != nil || info.Size() > maxSourceFile || len(sources) >= maxSourceFiles || totalBytes+info.Size() > maxSourceBytes {
			issues = append(issues, model.Issue{Code: "source_scan_limited", Scope: path})
			if len(sources) >= maxSourceFiles || totalBytes+info.Size() > maxSourceBytes {
				return filepath.SkipAll
			}
			return nil
		}
		file, err := os.Open(path)
		if err != nil {
			issues = append(issues, model.Issue{Code: "source_scan_limited", Scope: path})
			return nil
		}
		data, readErr := io.ReadAll(io.LimitReader(file, maxSourceFile+1))
		closeErr := file.Close()
		if readErr != nil || closeErr != nil || len(data) > maxSourceFile {
			issues = append(issues, model.Issue{Code: "source_scan_limited", Scope: path})
			return nil
		}
		totalBytes += int64(len(data))
		sources = append(sources, path)
		result := api.Build(api.BuildOptions{
			Stdin: &api.StdinOptions{
				Contents: string(data), Sourcefile: filepath.ToSlash(path), Loader: loader,
			},
			Bundle:      false,
			TreeShaking: api.TreeShakingFalse,
			TsconfigRaw: `{"compilerOptions":{"verbatimModuleSyntax":true}}`,
			Metafile:    true,
			Write:       false,
			Outfile:     "out.js",
			LogLevel:    api.LogLevelSilent,
		})
		if len(result.Errors) != 0 {
			issues = append(issues, model.Issue{Code: "source_parse_error", Scope: path})
			return nil
		}
		var meta struct {
			Outputs map[string]struct {
				Imports []struct {
					Path string `json:"path"`
					Kind string `json:"kind"`
				} `json:"imports"`
			} `json:"outputs"`
		}
		if err := json.Unmarshal([]byte(result.Metafile), &meta); err != nil {
			issues = append(issues, model.Issue{Code: "source_parse_error", Scope: path})
			return nil
		}
		evidence := common.Evidence(path, "deno-source", "", data)
		evidence.Method = "source-import-analysis"
		seen := map[string]bool{}
		for _, output := range meta.Outputs {
			for _, imp := range output.Imports {
				if imp.Kind != "import-statement" && imp.Kind != "dynamic-import" && imp.Kind != "require-call" {
					continue
				}
				if seen[imp.Path] {
					continue
				}
				seen[imp.Path] = true
				imports = append(imports, sourceImport{specifier: imp.Path, path: path, evidence: evidence})
			}
		}
		return nil
	})
	if err != nil {
		issues = append(issues, model.Issue{Code: "source_scan_limited"})
	}
	return imports, sources, issues
}

func hasNestedDenoProject(path string) bool {
	for _, name := range []string{"deno.json", "deno.jsonc", "deno.lock"} {
		if _, err := os.Stat(filepath.Join(path, name)); err == nil {
			return true
		}
	}
	return false
}

func sourceLoader(ext string) (api.Loader, bool) {
	switch strings.ToLower(ext) {
	case ".ts", ".mts", ".cts":
		return api.LoaderTS, true
	case ".tsx":
		return api.LoaderTSX, true
	case ".js", ".mjs", ".cjs":
		return api.LoaderJS, true
	case ".jsx":
		return api.LoaderJSX, true
	default:
		return 0, false
	}
}

// mappedSourceSpecifier applies a local import map. The mapping value is
// returned unchanged when it names an external package or URL.
func mappedSourceSpecifier(spec, source, base string, imports map[string]string, scopes map[string]map[string]string) (string, bool) {
	bestScope := ""
	for scope := range scopes {
		if !strings.HasPrefix(scope, "./") && !strings.HasPrefix(scope, "../") {
			continue
		}
		root := filepath.Clean(filepath.Join(base, filepath.FromSlash(scope)))
		if withinPath(root, source) && len(scope) > len(bestScope) {
			bestScope = scope
		}
	}
	if bestScope != "" {
		if mapped, ok := mapInScope(spec, scopes[bestScope]); ok {
			return mapped, true
		}
	}
	return mapInScope(spec, imports)
}

func mapInScope(spec string, mappings map[string]string) (string, bool) {
	if mapped, ok := mappings[spec]; ok {
		return mapped, true
	}
	best := ""
	for key := range mappings {
		if strings.HasSuffix(key, "/") && strings.HasPrefix(spec, key) && len(key) > len(best) {
			best = key
		}
	}
	if best == "" || !strings.HasSuffix(mappings[best], "/") {
		return "", false
	}
	return mappings[best] + strings.TrimPrefix(spec, best), true
}

func withinPath(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func localSourcePath(spec, source, base string, fromMap bool) (string, bool) {
	if !strings.HasPrefix(spec, "./") && !strings.HasPrefix(spec, "../") {
		return "", false
	}
	parent := filepath.Dir(source)
	if fromMap {
		parent = base
	}
	target := filepath.Clean(filepath.Join(parent, filepath.FromSlash(spec)))
	if !withinPath(base, target) {
		return "", false
	}
	resolved, err := filepath.EvalSymlinks(target)
	if err != nil || !withinPath(base, resolved) {
		return "", false
	}
	info, err := os.Stat(resolved)
	if err != nil || info.IsDir() {
		return "", false
	}
	return resolved, true
}

func barePackageName(spec string) string {
	if strings.HasPrefix(spec, "@") {
		first := strings.IndexByte(spec, '/')
		if first < 0 {
			return ""
		}
		rest := spec[first+1:]
		if rest == "" {
			return ""
		}
		if slash := strings.IndexByte(rest, '/'); slash >= 0 {
			return spec[:first+1+slash]
		}
		return spec
	}
	if slash := strings.IndexByte(spec, '/'); slash >= 0 {
		return spec[:slash]
	}
	return spec
}

func readImportMap(base, raw string) (configFile, string, error) {
	if raw == "" || filepath.IsAbs(raw) || strings.ContainsAny(raw, "?#") || strings.Contains(raw, ":") {
		return configFile{}, "", fmt.Errorf("import map is not a local path")
	}
	path := filepath.Clean(filepath.Join(base, filepath.FromSlash(raw)))
	if !withinPath(base, path) {
		return configFile{}, "", fmt.Errorf("import map is outside project")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || !withinPath(base, resolved) {
		return configFile{}, "", fmt.Errorf("import map is unavailable")
	}
	info, err := os.Stat(resolved)
	if err != nil || info.IsDir() || info.Size() > maxSourceFile {
		return configFile{}, "", fmt.Errorf("import map is unavailable")
	}
	file, err := os.Open(resolved)
	if err != nil {
		return configFile{}, "", err
	}
	data, readErr := io.ReadAll(io.LimitReader(file, maxSourceFile+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || len(data) > maxSourceFile {
		return configFile{}, "", fmt.Errorf("import map is unavailable")
	}
	standard, err := hujson.Standardize(data)
	if err != nil {
		return configFile{}, "", err
	}
	var config configFile
	if err := json.Unmarshal(standard, &config); err != nil {
		return configFile{}, "", err
	}
	return config, resolved, nil
}
