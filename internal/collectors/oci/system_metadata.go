package oci

import (
	"path"
	"sort"
	"strings"

	"github.com/Pirikara/Ravel/internal/collectors/composer"
	"github.com/Pirikara/Ravel/internal/collectors/dpkg"
	"github.com/Pirikara/Ravel/internal/model"
)

const (
	maxImageSystemFiles     = 4096
	maxImageSystemFileBytes = 1 << 20
	maxImageSystemTotal     = 64 << 20
)

type imageSystemFile struct {
	data          []byte
	layer, status string
}

func isDPKGStatusFragment(name string) bool {
	leaf, ok := strings.CutPrefix(name, "var/lib/dpkg/status.d/")
	return ok && leaf != "" && !strings.Contains(leaf, "/") && !strings.HasSuffix(leaf, ".md5sums")
}

func isImageSystemFile(name string) bool {
	return isDPKGStatusFragment(name) || isJavaRuntimeMetadataPath(name) || isComposerPHARPath(name)
}

func isComposerPHARPath(name string) bool {
	return strings.HasSuffix(strings.ToLower(name), ".phar") || name == "usr/bin/composer" || name == "usr/local/bin/composer"
}

func imageSystemFileLimit(name string) int64 {
	if isComposerPHARPath(name) {
		return composer.MaxPHARBytes
	}
	return maxImageSystemFileBytes
}

func appendSystemDocument(doc *model.Document, source model.Document) {
	doc.Components = append(doc.Components, source.Components...)
	doc.Edges = append(doc.Edges, source.Edges...)
	doc.Origins = append(doc.Origins, source.Origins...)
	doc.Development = append(doc.Development, source.Development...)
	doc.Coverage.Issues = append(doc.Coverage.Issues, source.Coverage.Issues...)
}

func collectImageSystemMetadata(doc *model.Document, files map[string]imageSystemFile, hasStatus bool, releases map[string]osReleaseState, architecture string) error {
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	fragments := map[string][]byte{}
	for _, name := range names {
		state := files[name]
		if !isDPKGStatusFragment(name) || hasStatus {
			continue
		}
		if state.status != "" {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "dpkg_status_fragment_" + state.status, Name: name})
			continue
		}
		fragments["oci:"+state.layer+"!/"+name] = state.data
	}
	if len(fragments) > 0 {
		installed, err := dpkg.CollectFragments(fragments, doc.Source+"#var/lib/dpkg/status.d", doc.Project)
		if err != nil {
			return err
		}
		if release, ok := finalOSRelease(releases); ok {
			for i := range installed.Components {
				setOSPackagePURL(&installed.Components[i], statusPath, release)
			}
		}
		appendSystemDocument(doc, installed)
	}
	for _, name := range names {
		if !isComposerPHARPath(name) {
			continue
		}
		state := files[name]
		if state.status != "" {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "composer_phar_metadata_" + state.status, Name: name})
			continue
		}
		if !strings.HasSuffix(strings.ToLower(name), ".phar") && !strings.Contains(string(state.data[:min(len(state.data), 1<<20)]), "__HALT_COMPILER();") {
			continue
		}
		installed, err := composer.CollectPHAR(state.data, "oci:"+state.layer+"!/"+name, doc.Project, name)
		if err != nil {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "composer_phar_metadata_unavailable", Name: name})
			continue
		}
		appendSystemDocument(doc, installed)
	}
	for _, name := range names {
		if path.Base(name) != "release" || !isJavaRuntimeMetadataPath(name) {
			continue
		}
		state := files[name]
		marker := files[path.Join(path.Dir(name), "bin/java")]
		if state.status != "" || marker.status != "" || len(marker.data) == 0 {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "java_runtime_metadata_unverified", Name: name})
			continue
		}
		installed, err := javaRuntimeDocument(state.data, marker.data, "oci:"+state.layer+"!/"+name, "oci:"+marker.layer+"!/"+path.Join(path.Dir(name), "bin/java"), name, doc.Project, architecture)
		if err != nil {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "java_runtime_metadata_invalid", Name: name})
			continue
		}
		appendSystemDocument(doc, installed)
	}
	return nil
}
