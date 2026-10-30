package npm

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	semver "github.com/Masterminds/semver/v3"

	"ravel/internal/collectors/common"
	"ravel/internal/model"
)

const maxPatchBytes = 16 << 20

// inspectPatch checks the bytes named by a v4 lockfile. A verified patch is
// still only a declaration about an install; no installed tree is inspected.
func inspectPatch(lockfile, location string, declared *lockPatch, lockEvidence model.Evidence) (model.Patch, *model.Issue) {
	patch := model.Patch{Status: "invalid_metadata", Evidence: []model.Evidence{lockEvidence}}
	issue := func(code string) (model.Patch, *model.Issue) {
		return patch, &model.Issue{Code: code, Name: location}
	}
	hashes := common.Integrity(declared.Integrity)
	if len(strings.Fields(declared.Integrity)) != 1 || len(hashes) != 1 || hashes[0].Alg != "SHA-512" {
		return issue("patch_metadata_invalid")
	}
	patch.Hash = &hashes[0]
	if !filepath.IsLocal(filepath.FromSlash(declared.Path)) || declared.Path != path.Clean(declared.Path) || strings.ContainsAny(declared.Path, "\\\x00\r\n") {
		return issue("patch_metadata_invalid")
	}
	patch.Path = declared.Path
	full := filepath.Join(filepath.Dir(lockfile), filepath.FromSlash(declared.Path))
	current := filepath.Dir(lockfile)
	for _, part := range strings.Split(declared.Path, "/") {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			patch.Status = "unavailable"
			return issue("patch_unavailable")
		}
	}
	info, err := os.Lstat(full)
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxPatchBytes {
		patch.Status = "unavailable"
		return issue("patch_unavailable")
	}
	file, err := os.Open(full)
	if err != nil {
		patch.Status = "unavailable"
		return issue("patch_unavailable")
	}
	content, readErr := io.ReadAll(io.LimitReader(file, maxPatchBytes+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || len(content) > maxPatchBytes {
		patch.Status = "unavailable"
		return issue("patch_unavailable")
	}
	observed := sha512.Sum512(content)
	evidenceDigest := sha256.Sum256(content)
	patch.Evidence = append(patch.Evidence, model.Evidence{
		Collector: "npm-patch", InputPath: full,
		InputDigest: "sha256:" + hex.EncodeToString(evidenceDigest[:]),
		Method:      "file-content-hash",
	})
	if patch.Hash.Content != hex.EncodeToString(observed[:]) {
		patch.Status = "integrity_mismatch"
		return issue("patch_integrity_mismatch")
	}
	patch.Status = "content_verified"
	return patch, nil
}

func verifyPatchManifest(doc *model.Document, lockfile string, entries map[string]*item) {
	patched := map[string]*item{}
	for location, entry := range entries {
		if entry.data.Patched != nil {
			patched[location] = entry
		}
	}
	manifestPath := filepath.Join(filepath.Dir(lockfile), "package.json")
	manifestData, err := os.ReadFile(manifestPath)
	if err != nil {
		for location := range patched {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "manifest_freshness_unverified", Name: location})
		}
		return
	}
	var manifest struct {
		PatchedDependencies map[string]string `json:"patchedDependencies"`
	}
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		for location := range patched {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "manifest_freshness_unverified", Name: location})
		}
		return
	}
	if len(patched) == 0 && len(manifest.PatchedDependencies) == 0 {
		return
	}
	foundSource := false
	for _, source := range doc.Sources {
		if source == manifestPath {
			foundSource = true
			break
		}
	}
	if !foundSource {
		doc.Sources = append(doc.Sources, manifestPath)
	}
	index := map[string]int{}
	for i, component := range doc.Components {
		index[component.ID] = i
	}
	selectors := make([]string, 0, len(manifest.PatchedDependencies))
	for selector := range manifest.PatchedDependencies {
		selectors = append(selectors, selector)
	}
	sort.Strings(selectors)
	for location, entry := range patched {
		name := entry.data.Name
		if name == "" {
			name = nameFromLocation(location)
		}
		matched := false
		for _, selector := range selectors {
			patchPath := manifest.PatchedDependencies[selector]
			if patchPath != entry.data.Patched.Path || !patchSelectorMatches(selector, name, entry.data.Version) {
				continue
			}
			matched = true
			if componentIndex, ok := index[entry.ref]; ok && len(doc.Components[componentIndex].Patches) != 0 {
				ev := common.Evidence(manifestPath, "npm-manifest", "/patchedDependencies/"+escapePointer(selector), manifestData)
				ev.Method = "manifest-analysis"
				doc.Components[componentIndex].Patches[0].Evidence = append(doc.Components[componentIndex].Patches[0].Evidence, ev)
			}
			break
		}
		if !matched {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "manifest_freshness_unverified", Name: location})
		}
	}
	for location, entry := range entries {
		if entry.data.Patched != nil {
			continue
		}
		name := entry.data.Name
		if name == "" {
			name = nameFromLocation(location)
		}
		for _, selector := range selectors {
			if patchSelectorMatches(selector, name, entry.data.Version) {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "manifest_freshness_unverified", Name: location})
				break
			}
		}
	}
}

func patchSelectorMatches(selector, name, version string) bool {
	selectorName, constraint := selector, ""
	if at := strings.LastIndex(selector, "@"); at > 0 {
		selectorName, constraint = selector[:at], selector[at+1:]
		if constraint == "" {
			return false
		}
	}
	if selectorName != name {
		return false
	}
	if constraint == "" {
		return true
	}
	wanted, err := semver.NewConstraint(constraint)
	if err != nil {
		return false
	}
	selected, err := semver.StrictNewVersion(version)
	return err == nil && wanted.Check(selected)
}
