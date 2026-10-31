package npm

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"path"
	"regexp"
	"strings"

	"ravel/internal/collectors/common"
	"ravel/internal/model"
)

const MaxInstalledPackageJSONBytes = 2 << 20

var (
	installedNodePathToken = regexp.MustCompile(`^[A-Za-z0-9_~][A-Za-z0-9._~-]*$`)
	installedNodeName      = regexp.MustCompile(`^(?:@[A-Za-z0-9_~][A-Za-z0-9._~-]*/)?[A-Za-z0-9_~][A-Za-z0-9._~-]*$`)
)

// IsInstalledPackagePath recognizes package roots in conventional node_modules
// trees, Debian's system Node directory, pnpm's virtual store, and versioned
// Yarn installations. A pnpm store manifest still needs a reachable package
// symlink before it is inventoried.
func IsInstalledPackagePath(name string) bool {
	if path.Clean(name) != name || path.Base(name) != "package.json" {
		return false
	}
	parts := strings.Split(name, "/")
	if _, ok := versionedYarnPath(name); ok {
		return true
	}
	if _, ok := systemNodePackageName(name); ok {
		return true
	}
	for _, part := range parts {
		if part == ".pnpm" {
			return isPnpmStorePackagePath(name)
		}
	}
	if len(parts) >= 3 && parts[len(parts)-3] == "node_modules" && installedNodePathToken.MatchString(parts[len(parts)-2]) {
		return true
	}
	return len(parts) >= 4 && parts[len(parts)-4] == "node_modules" && strings.HasPrefix(parts[len(parts)-3], "@") && installedNodePathToken.MatchString(strings.TrimPrefix(parts[len(parts)-3], "@")) && installedNodePathToken.MatchString(parts[len(parts)-2])
}

// IsPnpmStorePackagePath reports a package root in pnpm's versioned virtual
// store. The locator is not trusted as package identity; package.json is.
func IsPnpmStorePackagePath(name string) bool {
	return isPnpmStorePackagePath(name)
}

// IsInstalledPackageLinkPath reports a package directory symlink whose
// package.json can be checked against the final image filesystem.
func IsInstalledPackageLinkPath(name string) bool {
	return IsInstalledPackagePath(path.Join(name, "package.json"))
}

func isPnpmStorePackagePath(name string) bool {
	parts := strings.Split(name, "/")
	for i := 0; i+5 < len(parts); i++ {
		if parts[i] != "node_modules" || parts[i+1] != ".pnpm" || parts[i+2] == "" || !strings.Contains(parts[i+2], "@") || parts[i+3] != "node_modules" {
			continue
		}
		if i+5 == len(parts)-1 && installedNodePathToken.MatchString(parts[i+4]) && parts[i+5] == "package.json" {
			return true
		}
		if i+6 == len(parts)-1 && strings.HasPrefix(parts[i+4], "@") && installedNodePathToken.MatchString(strings.TrimPrefix(parts[i+4], "@")) && installedNodePathToken.MatchString(parts[i+5]) && parts[i+6] == "package.json" {
			return true
		}
	}
	return false
}

// CollectInstalledPackage records a package manifest found at a recognized
// installation path. The manifest identifies the package but does not prove
// which registry or tarball supplied it.
func CollectInstalledPackage(data []byte, source, project, metadataPath string) (model.Document, error) {
	if len(data) > MaxInstalledPackageJSONBytes || !IsInstalledPackagePath(metadataPath) {
		return model.Document{}, errors.New("invalid installed Node package path or size")
	}
	manifest, err := decodeUniqueObject(data)
	if err != nil {
		return model.Document{}, errors.New("invalid installed Node package manifest")
	}
	var name, version string
	if json.Unmarshal(manifest["name"], &name) != nil || json.Unmarshal(manifest["version"], &version) != nil || len(name) > 214 || !installedNodeName.MatchString(name) || version == "" || len(version) > 128 || strings.ContainsAny(version, " \t\r\n\x00/\\") {
		return model.Document{}, errors.New("installed Node package identity is invalid")
	}
	if expected, ok := versionedYarnPath(metadataPath); ok && (name != "yarn" || version != expected) {
		return model.Document{}, errors.New("installed Yarn version does not match its installation path")
	}
	if expected, ok := systemNodePackageName(metadataPath); ok && name != expected {
		return model.Document{}, errors.New("installed system Node package name does not match its installation path")
	}
	hash := sha256.Sum256(data)
	digest := "sha256:" + hex.EncodeToString(hash[:])
	evidence := model.Evidence{Collector: "node-package-json", InputPath: source, InputDigest: digest, Method: "installed-metadata"}
	id := "npm-installed:" + common.ID(metadataPath+"\x00"+name+"\x00"+version)
	doc := common.NewDocument(source, project, "npm-installed", nil)
	doc.Components = append(doc.Components, model.Component{ID: id, Kind: "package", Name: name, Version: version, Context: "location=" + path.Dir(metadataPath), Evidence: []model.Evidence{evidence}})
	doc.Edges = append(doc.Edges, model.Edge{From: "root", To: id, Kind: "installed", Evidence: evidence})
	doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "distribution_source_unavailable", Name: name})
	for _, field := range []string{"dependencies", "optionalDependencies", "peerDependencies"} {
		value := bytes.TrimSpace(manifest[field])
		if len(value) > 0 && !bytes.Equal(value, []byte("null")) && !bytes.Equal(value, []byte("{}")) {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "declared_dependencies_unresolved", Name: name})
			break
		}
	}
	common.Finalize(&doc)
	return doc, nil
}

func versionedYarnPath(name string) (string, bool) {
	parts := strings.Split(name, "/")
	if len(parts) != 3 || parts[0] != "opt" || parts[2] != "package.json" || !strings.HasPrefix(parts[1], "yarn-v") {
		return "", false
	}
	version := strings.TrimPrefix(parts[1], "yarn-v")
	return version, installedNodePathToken.MatchString(version)
}

// systemNodePackageName recognizes the package roots that Debian places on
// Node's default global module path. Nested source manifests are excluded.
func systemNodePackageName(name string) (string, bool) {
	if path.Clean(name) != name || strings.HasPrefix(name, "/") {
		return "", false
	}
	parts := strings.Split(name, "/")
	if len(parts) < 5 || parts[0] != "usr" || parts[1] != "share" || parts[2] != "nodejs" || parts[len(parts)-1] != "package.json" {
		return "", false
	}
	if len(parts) == 5 && installedNodePathToken.MatchString(parts[3]) {
		return parts[3], true
	}
	if len(parts) == 6 && strings.HasPrefix(parts[3], "@") && installedNodePathToken.MatchString(strings.TrimPrefix(parts[3], "@")) && installedNodePathToken.MatchString(parts[4]) {
		return parts[3] + "/" + parts[4], true
	}
	return "", false
}

// IsSystemNodePackagePath distinguishes Debian's global module manifests
// from package roots in an application-local node_modules tree.
func IsSystemNodePackagePath(name string) bool {
	_, ok := systemNodePackageName(name)
	return ok
}

func decodeUniqueObject(data []byte) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return nil, errors.New("expected JSON object")
	}
	object := map[string]json.RawMessage{}
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		key, ok := token.(string)
		if !ok {
			return nil, errors.New("invalid JSON object key")
		}
		if _, duplicate := object[key]; duplicate {
			return nil, errors.New("duplicate JSON object key")
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, err
		}
		object[key] = value
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') {
		return nil, errors.New("invalid JSON object end")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, errors.New("trailing JSON data")
	}
	return object, nil
}
