package oci

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"errors"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/Pirikara/Ravel/internal/collectors/common"
	"github.com/Pirikara/Ravel/internal/model"
	packageurl "github.com/package-url/packageurl-go"
)

var javaReleaseVersion = regexp.MustCompile(`^[0-9][A-Za-z0-9._+-]{0,127}$`)

func isJavaRuntimeMetadataPath(name string) bool {
	home := path.Dir(name)
	if path.Base(name) == "java" && path.Base(home) == "bin" {
		home = path.Dir(home)
	} else if path.Base(name) != "release" {
		return false
	}
	if home == "opt/java/openjdk" {
		return true
	}
	if path.Dir(home) == "usr/lib/jvm" {
		return path.Base(home) != "."
	}
	return path.Dir(home) == "usr/local" && strings.HasPrefix(path.Base(home), "openjdk-")
}

// The release file declares the runtime version. A matching final ELF launcher
// establishes the installation location, not the version of all runtime bytes.
func javaRuntimeDocument(data, launcher []byte, source, launcherSource, name, project, architecture string) (model.Document, error) {
	if len(data) == 0 || len(data) > maxImageSystemFileBytes || len(launcher) == 0 || len(launcher) > maxImageSystemFileBytes {
		return model.Document{}, errors.New("invalid Java runtime metadata size")
	}
	if err := guardELFMetadata(launcher); err != nil {
		return model.Document{}, err
	}
	f, err := elf.NewFile(bytes.NewReader(launcher))
	if err != nil || f.Type != elf.ET_DYN && f.Type != elf.ET_EXEC || !bytes.Contains(launcher, []byte("JLI_Launch\x00")) {
		return model.Document{}, errors.New("Java ELF launcher not identified")
	}
	defer f.Close()
	if architecture == "arm64" && f.Machine != elf.EM_AARCH64 || architecture == "amd64" && f.Machine != elf.EM_X86_64 || architecture == "386" && f.Machine != elf.EM_386 {
		return model.Document{}, errors.New("Java launcher architecture differs from image")
	}
	values := map[string]string{}
	lines := map[string]int{}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), 64<<10)
	line := 0
	for scanner.Scan() {
		line++
		text := strings.TrimSpace(scanner.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		key, raw, ok := strings.Cut(text, "=")
		if !ok || key == "" || key != strings.TrimSpace(key) {
			return model.Document{}, errors.New("invalid Java release assignment")
		}
		if _, exists := values[key]; exists {
			return model.Document{}, errors.New("duplicate Java release assignment")
		}
		if len(raw) < 2 || raw[0] != '"' || raw[len(raw)-1] != '"' {
			return model.Document{}, errors.New("nonliteral Java release value")
		}
		value, err := strconv.Unquote(raw)
		if err != nil {
			return model.Document{}, errors.New("nonliteral Java release value")
		}
		values[key], lines[key] = value, line
	}
	if err := scanner.Err(); err != nil {
		return model.Document{}, err
	}
	base := values["JAVA_VERSION"]
	version := base
	field := "JAVA_VERSION"
	if runtime := values["JAVA_RUNTIME_VERSION"]; runtime != "" {
		if runtime != base && !strings.HasPrefix(runtime, base+"+") && !strings.HasPrefix(runtime, base+"-") {
			return model.Document{}, errors.New("conflicting Java release versions")
		}
		version, field = runtime, "JAVA_RUNTIME_VERSION"
	}
	if !javaReleaseVersion.MatchString(base) || !javaReleaseVersion.MatchString(version) {
		return model.Document{}, errors.New("invalid Java runtime version")
	}
	hash := sha256.Sum256(data)
	launchHash := sha256.Sum256(launcher)
	evidence := model.Evidence{Collector: "java-runtime-release", InputPath: source, InputDigest: "sha256:" + hex.EncodeToString(hash[:]), Line: lines[field], Method: "runtime-release-metadata"}
	marker := model.Evidence{Collector: "java-runtime-launcher", InputPath: launcherSource, InputDigest: "sha256:" + hex.EncodeToString(launchHash[:]), Method: "runtime-installation-marker"}
	doc := common.NewDocument(source, project, "java-runtime", nil)
	id := "java-runtime:" + common.ID(source+"\x00"+version)
	context := "location=/" + path.Dir(name) + ";runtime=java"
	if vendor := values["IMPLEMENTOR"]; vendor != "" && len(vendor) <= 256 {
		context += ";implementor=" + strconv.Quote(vendor)
	}
	doc.Components = append(doc.Components, model.Component{ID: id, Kind: "package", Name: "java", Version: version, Context: context, PURL: packageurl.NewPackageURL("generic", "", "java", version, nil, "").ToString(), Evidence: []model.Evidence{evidence, marker}})
	doc.Edges = append(doc.Edges, model.Edge{From: "root", To: id, Kind: "installed", Evidence: evidence})
	if repository := values["SOURCE_REPO"]; repository != "" {
		e := evidence
		e.Line = lines["SOURCE_REPO"]
		common.AddDevelopment(&doc, id, repository, "declared", e)
	}
	doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "java_runtime_graph_unavailable", Name: name}, model.Issue{Code: "missing_source", Name: name}, model.Issue{Code: "java_runtime_binary_version_unverified", Name: name})
	common.Finalize(&doc)
	return doc, nil
}
