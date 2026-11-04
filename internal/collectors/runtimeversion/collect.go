package runtimeversion

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/Pirikara/Ravel/internal/collectors/common"
	"github.com/Pirikara/Ravel/internal/model"
	"github.com/pelletier/go-toml/v2"
	"golang.org/x/mod/modfile"
	"gopkg.in/yaml.v3"
)

const maxSourceBytes = 2 << 20

var swiftToolsVersion = regexp.MustCompile(`^//\s*swift-tools-version:\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)\s*$`)

type Result struct {
	Requirements []model.RuntimeRequirement
	Sources      []string
	Issues       []model.Issue
}

// CollectDirectory reads only well-known declarations at this directory's
// root. It never invokes a runtime or treats a declaration as an installed one.
func CollectDirectory(directory string) Result {
	result := Result{}
	rustLegacy := false
	for _, name := range []string{
		".nvmrc", ".node-version", ".python-version", ".ruby-version", ".tool-versions",
		"package.json", "pyproject.toml", "go.mod", "go.work", "Cargo.toml",
		"rust-toolchain", "rust-toolchain.toml", "global.json", "Package.swift", "pubspec.yaml",
	} {
		if name == "rust-toolchain.toml" && rustLegacy {
			continue // rustup gives rust-toolchain precedence when both exist.
		}
		file := filepath.Join(directory, name)
		data, exists, err := readSource(file)
		if !exists {
			continue
		}
		if name == "rust-toolchain" {
			rustLegacy = true
		}
		if err != nil {
			result.Sources = append(result.Sources, file)
			result.Issues = append(result.Issues, model.Issue{Code: "runtime_declaration_invalid", Name: name, Scope: file})
			continue
		}
		declarations, err := parse(name, file, directory, data)
		if err != nil {
			result.Sources = append(result.Sources, file)
			result.Issues = append(result.Issues, model.Issue{Code: "runtime_declaration_invalid", Name: name, Scope: file})
			continue
		}
		if len(declarations) > 0 {
			result.Sources = append(result.Sources, file)
		}
		result.Requirements = append(result.Requirements, declarations...)
	}
	return result
}

func readSource(path string) ([]byte, bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, true, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxSourceBytes {
		return nil, true, errors.New("runtime declaration must be a bounded regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, true, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxSourceBytes+1))
	if err != nil || len(data) > maxSourceBytes {
		return nil, true, errors.New("runtime declaration exceeds read limit")
	}
	return data, true, nil
}

func parse(name, file, scope string, data []byte) ([]model.RuntimeRequirement, error) {
	var out []model.RuntimeRequirement
	add := func(runtime, requirement, relation, pointer, policy string) error {
		requirement = strings.TrimSpace(requirement)
		if requirement == "" || requirement == "*" || requirement == "system" {
			return nil
		}
		if len(requirement) > 128 || strings.ContainsAny(requirement, "\x00\r\n\t") || len(policy) > 128 || strings.ContainsAny(policy, "\x00\r\n\t") {
			return errors.New("invalid runtime version requirement")
		}
		evidence := common.Evidence(file, "repository-runtime", pointer, data)
		evidence.Method = "repository-declaration"
		if line, err := strconv.Atoi(strings.TrimPrefix(pointer, "line:")); strings.HasPrefix(pointer, "line:") && err == nil {
			evidence.Line = line
		}
		out = append(out, model.RuntimeRequirement{Name: runtime, Requirement: requirement, Relation: relation, Scope: scope, Policy: policy, Evidence: evidence})
		return nil
	}
	switch name {
	case ".nvmrc", ".node-version", ".python-version", ".ruby-version":
		runtime := map[string]string{".nvmrc": "node", ".node-version": "node", ".python-version": "python", ".ruby-version": "ruby"}[name]
		lines := versionLines(data)
		if len(lines) == 0 {
			return nil, errors.New("empty version file")
		}
		if name != ".python-version" {
			lines = lines[:1]
		}
		for _, line := range lines {
			if err := add(runtime, line.value, "selection", fmt.Sprintf("line:%d", line.number), ""); err != nil {
				return nil, err
			}
		}
	case ".tool-versions":
		for _, line := range versionLines(data) {
			fields := strings.Fields(line.value)
			if len(fields) < 2 {
				continue
			}
			runtime := map[string]string{
				"nodejs": "node", "python": "python", "ruby": "ruby", "golang": "go", "rust": "rust",
				"java": "java", "deno": "deno", "bun": "bun", "dotnet": "dotnet-sdk", "flutter": "flutter", "dart": "dart",
				"elixir": "elixir", "erlang": "erlang", "php": "php", "julia": "julia", "crystal": "crystal",
				"scala": "scala", "kotlin": "kotlin", "lua": "lua", "perl": "perl", "R": "r", "ghc": "haskell",
			}[fields[0]]
			if runtime == "" {
				continue
			}
			for _, value := range fields[1:] {
				if value == "system" || strings.HasPrefix(value, "path:") {
					continue
				}
				if err := add(runtime, value, "selection", fmt.Sprintf("line:%d", line.number), ""); err != nil {
					return nil, err
				}
			}
		}
	case "package.json":
		var manifest struct {
			Engines map[string]string `json:"engines"`
		}
		if err := json.Unmarshal(data, &manifest); err != nil {
			return nil, err
		}
		if value := manifest.Engines["node"]; value != "" {
			if err := add("node", value, "compatibility", "/engines/node", ""); err != nil {
				return nil, err
			}
		}
	case "pyproject.toml":
		var manifest struct {
			Project struct {
				RequiresPython string `toml:"requires-python"`
			} `toml:"project"`
			Tool struct {
				Poetry struct {
					Dependencies map[string]any `toml:"dependencies"`
				} `toml:"poetry"`
			} `toml:"tool"`
		}
		if err := toml.Unmarshal(data, &manifest); err != nil {
			return nil, err
		}
		if err := add("python", manifest.Project.RequiresPython, "compatibility", "project.requires-python", ""); err != nil {
			return nil, err
		}
		if value, ok := manifest.Tool.Poetry.Dependencies["python"].(string); ok {
			if err := add("python", value, "compatibility", "tool.poetry.dependencies.python", ""); err != nil {
				return nil, err
			}
		} else if value, ok := manifest.Tool.Poetry.Dependencies["python"].(map[string]any); ok {
			if version, ok := value["version"].(string); ok {
				if err := add("python", version, "compatibility", "tool.poetry.dependencies.python.version", ""); err != nil {
					return nil, err
				}
			}
		}
	case "go.mod", "go.work":
		if name == "go.mod" {
			mod, err := modfile.Parse(file, data, nil)
			if err != nil {
				return nil, err
			}
			if mod.Go != nil {
				if err := add("go", mod.Go.Version, "minimum", "go", ""); err != nil {
					return nil, err
				}
			}
			if mod.Toolchain != nil {
				if err := add("go", strings.TrimPrefix(mod.Toolchain.Name, "go"), "suggested", "toolchain", ""); err != nil {
					return nil, err
				}
			}
		} else {
			work, err := modfile.ParseWork(file, data, nil)
			if err != nil {
				return nil, err
			}
			if work.Go != nil {
				if err := add("go", work.Go.Version, "minimum", "go", ""); err != nil {
					return nil, err
				}
			}
			if work.Toolchain != nil {
				if err := add("go", strings.TrimPrefix(work.Toolchain.Name, "go"), "suggested", "toolchain", ""); err != nil {
					return nil, err
				}
			}
		}
	case "Cargo.toml":
		var manifest struct {
			Package struct {
				RustVersion any `toml:"rust-version"`
			} `toml:"package"`
			Workspace struct {
				Package struct {
					RustVersion string `toml:"rust-version"`
				} `toml:"package"`
			} `toml:"workspace"`
		}
		if err := toml.Unmarshal(data, &manifest); err != nil {
			return nil, err
		}
		if value, ok := manifest.Package.RustVersion.(string); ok {
			if err := add("rust", value, "minimum", "package.rust-version", ""); err != nil {
				return nil, err
			}
		}
		if err := add("rust", manifest.Workspace.Package.RustVersion, "minimum", "workspace.package.rust-version", ""); err != nil {
			return nil, err
		}
	case "rust-toolchain", "rust-toolchain.toml":
		channel := ""
		pointer := "toolchain.channel"
		if name == "rust-toolchain" && !bytes.HasPrefix(bytes.TrimSpace(data), []byte("[")) {
			lines := versionLines(data)
			if len(lines) > 0 {
				channel = lines[0].value
				pointer = fmt.Sprintf("line:%d", lines[0].number)
			}
		} else {
			var manifest struct {
				Toolchain struct {
					Channel string `toml:"channel"`
				} `toml:"toolchain"`
			}
			if err := toml.Unmarshal(data, &manifest); err != nil {
				return nil, err
			}
			channel = manifest.Toolchain.Channel
		}
		if err := add("rust", channel, "selection", pointer, ""); err != nil {
			return nil, err
		}
	case "global.json":
		var manifest struct {
			SDK struct {
				Version     string `json:"version"`
				RollForward string `json:"rollForward"`
			} `json:"sdk"`
		}
		if err := json.Unmarshal(data, &manifest); err != nil {
			return nil, err
		}
		if err := add("dotnet-sdk", manifest.SDK.Version, "selection", "/sdk/version", manifest.SDK.RollForward); err != nil {
			return nil, err
		}
	case "Package.swift":
		line, _, _ := bytes.Cut(data, []byte("\n"))
		match := swiftToolsVersion.FindSubmatch(bytes.TrimSuffix(line, []byte("\r")))
		if match != nil {
			if err := add("swift-tools", string(match[1]), "minimum", "line:1", ""); err != nil {
				return nil, err
			}
		}
	case "pubspec.yaml":
		var manifest struct {
			Environment struct {
				SDK     string `yaml:"sdk"`
				Flutter string `yaml:"flutter"`
			} `yaml:"environment"`
		}
		if err := yaml.Unmarshal(data, &manifest); err != nil {
			return nil, err
		}
		if err := add("dart", manifest.Environment.SDK, "compatibility", "environment.sdk", ""); err != nil {
			return nil, err
		}
		if err := add("flutter", manifest.Environment.Flutter, "compatibility", "environment.flutter", ""); err != nil {
			return nil, err
		}
	}
	return out, nil
}

type versionLine struct {
	value  string
	number int
}

func versionLines(data []byte) []versionLine {
	var lines []versionLine
	for index, line := range strings.Split(string(data), "\n") {
		value, _, _ := strings.Cut(line, "#")
		value = strings.TrimSpace(value)
		if value != "" {
			lines = append(lines, versionLine{value: value, number: index + 1})
		}
	}
	return lines
}
