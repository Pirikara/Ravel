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

// IsInstalledPackagePath recognizes conventional node_modules package roots.
// The pnpm content store needs symlink resolution before it can establish an
// installed package, so paths beneath .pnpm are excluded.
func IsInstalledPackagePath(name string) bool {
	if path.Clean(name) != name || path.Base(name) != "package.json" {
		return false
	}
	parts := strings.Split(name, "/")
	for _, part := range parts {
		if part == ".pnpm" {
			return false
		}
	}
	if len(parts) >= 3 && parts[len(parts)-3] == "node_modules" && installedNodePathToken.MatchString(parts[len(parts)-2]) {
		return true
	}
	return len(parts) >= 4 && parts[len(parts)-4] == "node_modules" && strings.HasPrefix(parts[len(parts)-3], "@") && installedNodePathToken.MatchString(strings.TrimPrefix(parts[len(parts)-3], "@")) && installedNodePathToken.MatchString(parts[len(parts)-2])
}

// CollectInstalledPackage records a package manifest found at an installed
// node_modules path. The manifest identifies the package but does not prove
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
