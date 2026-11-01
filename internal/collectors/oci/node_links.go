package oci

import (
	"path"
	"sort"
	"strings"

	"github.com/Pirikara/Ravel/internal/model"
)

// resolveNodePackageLinks maps installed package symlinks to manifests in the
// final image. The link target is interpreted inside the image, never against
// the host filesystem. Missing and unsafe targets remain coverage issues.
func resolveNodePackageLinks(links map[string]string, metadata map[string]bool) (map[string]string, []model.Issue) {
	aliases := map[string]string{}
	var issues []model.Issue
	names := make([]string, 0, len(links))
	for name := range links {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		alias := path.Join(name, "package.json")
		physical, ok := resolveNodeManifestLink(alias, links)
		if !ok || !metadata[physical] {
			issues = append(issues, model.Issue{Code: "node_installed_link_unresolved", Name: name})
			continue
		}
		aliases[alias] = physical
	}
	return aliases, issues
}

func resolveNodeManifestLink(name string, links map[string]string) (string, bool) {
	seen := map[string]bool{}
	for hops := 0; hops < 16; hops++ {
		if seen[name] {
			return "", false
		}
		seen[name] = true
		prefix := ""
		target := ""
		for ancestor := path.Dir(name); ancestor != "."; ancestor = path.Dir(ancestor) {
			if value, found := links[ancestor]; found {
				prefix, target = ancestor, value
				break
			}
		}
		if prefix == "" {
			return name, true
		}
		if target == "" || len(target) > 4096 || strings.ContainsAny(target, "\\\x00\r\n") {
			return "", false
		}
		var resolved string
		if strings.HasPrefix(target, "/") {
			resolved = path.Clean(strings.TrimPrefix(target, "/"))
		} else {
			resolved = path.Clean(path.Join(path.Dir(prefix), target))
		}
		if resolved == "." || resolved == ".." || strings.HasPrefix(resolved, "../") {
			return "", false
		}
		name = path.Join(resolved, strings.TrimPrefix(name[len(prefix):], "/"))
	}
	return "", false
}
