package oci

import (
	"encoding/json"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/Pirikara/Ravel/internal/model"
	packageurl "github.com/package-url/packageurl-go"
)

var imagePythonNameSeparators = regexp.MustCompile(`[-_.]+`)

func installedImageEcosystem(c model.Component) string {
	for _, e := range c.Evidence {
		switch e.Collector {
		case "node-package-json":
			return "npm"
		case "python-dist-info", "python-egg-info":
			return "pypi"
		case "ruby-installed-gemspec":
			return "gem"
		case "composer-installed":
			return "composer"
		case "nuget-deps":
			if c.Kind == "package" && strings.HasPrefix(c.PURL, "pkg:nuget/") {
				return "nuget"
			}
		case "java-archive":
			if strings.HasPrefix(c.PURL, "pkg:maven/") {
				return "maven"
			}
		case "go-buildinfo":
			if c.Kind == "package" && c.Name != "stdlib" {
				return "golang"
			}
		case "cargo-auditable-elf":
			if c.Kind == "package" {
				return "cargo"
			}
		case "r-installed-description":
			return "r"
		case "conda-meta":
			return "conda"
		}
	}
	return ""
}

func lockedImageEcosystem(manager string, c model.Component) string {
	switch manager {
	case "npm", "pnpm", "yarn", "bun":
		return "npm"
	case "deno":
		if strings.HasPrefix(c.PURL, "pkg:npm/") {
			return "npm"
		}
		return ""
	case "uv", "poetry", "pipenv", "pdm", "pylock", "requirements":
		return "pypi"
	case "bundler":
		return "gem"
	case "composer":
		return "composer"
	case "nuget", "nuget-assets", "nuget-config":
		return "nuget"
	case "cargo":
		return "cargo"
	case "go":
		return "golang"
	case "gradle", "maven", "sbt":
		return "maven"
	case "renv":
		return "r"
	case "conda-lock", "pixi":
		if imageContextValue(c.Context, "manager") == "pip" || imageContextValue(c.Context, "manager") == "pypi" {
			return "pypi"
		}
		return "conda"
	}
	return ""
}

func imageCoordinateKey(ecosystem, name, version string) string {
	if ecosystem == "pypi" {
		name = imagePythonNameSeparators.ReplaceAllString(strings.ToLower(name), "-")
	}
	if ecosystem == "nuget" || ecosystem == "composer" {
		name = strings.ToLower(name)
	}
	if ecosystem == "composer" {
		version = strings.TrimPrefix(version, "v")
	}
	return ecosystem + "\x00" + name + "\x00" + version
}

func imageContextValue(context, key string) string {
	for _, field := range strings.Split(context, ";") {
		if value, found := strings.CutPrefix(field, key+"="); found {
			return value
		}
	}
	return ""
}

func installedImagePath(c model.Component) string {
	for _, e := range c.Evidence {
		if strings.HasPrefix(e.InputPath, "oci:") {
			if _, name, ok := strings.Cut(e.InputPath, "!/"); ok {
				return name
			}
		}
	}
	return ""
}

func installedImageGroup(c model.Component, ecosystem string) string {
	name := installedImagePath(c)
	switch ecosystem {
	case "pypi":
		for _, marker := range []string{"/site-packages/", "/dist-packages/"} {
			if prefix, _, found := strings.Cut(name, marker); found {
				return prefix + strings.TrimSuffix(marker, "/")
			}
		}
	case "gem":
		if prefix, _, found := strings.Cut(name, "/specifications/"); found {
			return prefix
		}
	case "conda":
		return imageContextValue(c.Context, "environment")
	case "golang", "cargo":
		return name
	case "composer", "nuget":
		return name
	case "r":
		return path.Dir(path.Dir(name))
	}
	return ""
}

func imagePathWithin(scope, name string) bool {
	return scope == "." || name == scope || strings.HasPrefix(name, scope+"/")
}

type imageLockCandidate struct{ lock, component int }

func imageLockSignature(lock imageLockDocument, c model.Component) string {
	// Distribution hashes distinguish alternative artifacts, but are never
	// copied to installed bytes merely because names and versions match.
	parts := []string{c.PURL, c.Platform, c.Context}
	for _, h := range c.Hashes {
		parts = append(parts, h.Alg+"="+h.Content)
	}
	for _, o := range lock.origins[c.ID] {
		encoded, _ := json.Marshal([]string{o.Kind, o.SafeURL, o.LocalPath, o.Target, o.Revision, o.VCSType})
		parts = append(parts, string(encoded))
	}
	sort.Strings(parts)
	encoded, _ := json.Marshal(parts)
	return string(encoded)
}

func imageLockCompatible(lock imageLockDocument, candidate, installed model.Component, ecosystem string) bool {
	if candidate.Kind != installed.Kind && candidate.Kind != "package" {
		return false
	}
	if ecosystem == "nuget" && candidate.Platform != "" && installed.Platform != "" {
		framework := func(target string) (string, string) {
			name, rid, _ := strings.Cut(target, "/")
			for _, spec := range []struct{ prefix, replacement string }{{".NETCoreApp,Version=v", "net"}, {".NETStandard,Version=v", "netstandard"}, {".NETFramework,Version=v", "net"}} {
				if version, ok := strings.CutPrefix(name, spec.prefix); ok {
					if spec.prefix == ".NETFramework,Version=v" {
						version = strings.ReplaceAll(version, ".", "")
					}
					if spec.prefix == ".NETCoreApp,Version=v" && (strings.HasPrefix(version, "1.") || strings.HasPrefix(version, "2.") || strings.HasPrefix(version, "3.")) {
						return "netcoreapp" + version, rid
					}
					return spec.replacement + version, rid
				}
			}
			return name, rid
		}
		cf, cr := framework(candidate.Platform)
		inf, ir := framework(installed.Platform)
		if cf != inf || cr != "" && cr != ir {
			return false
		}
	}
	if lock.manager == "npm" {
		for _, e := range candidate.Evidence {
			if location, ok := strings.CutPrefix(e.Pointer, "/packages/"); ok {
				location = strings.NewReplacer("~1", "/", "~0", "~").Replace(location)
				if path.Join(lock.scope, location) != path.Dir(installedImagePath(installed)) {
					return false
				}
			}
		}
	}
	if ecosystem == "conda" {
		build, subdir := imageContextValue(installed.Context, "build"), imageContextValue(installed.Context, "subdir")
		for _, o := range lock.origins[candidate.ID] {
			if o.Occurrence == candidate.ID && o.Kind == "download_url" {
				stem := candidate.Name + "-" + candidate.Version + "-" + build
				if path.Base(o.SafeURL) != stem+".conda" && path.Base(o.SafeURL) != stem+".tar.bz2" {
					continue
				}
				if subdir == "" || path.Base(path.Dir(o.SafeURL)) == subdir {
					return true
				}
			}
		}
		return false
	}
	// A registry crate and a same-name Git crate are different identities.
	if ecosystem == "cargo" {
		switch imageContextValue(installed.Context, "source") {
		case "crates.io":
			return candidate.PURL == packageurl.NewPackageURL("cargo", "", candidate.Name, candidate.Version, nil, "").ToString()
		case "git":
			for _, o := range lock.origins[candidate.ID] {
				if o.Kind == "vcs" {
					return true
				}
			}
			return false
		case "registry":
			for _, o := range lock.origins[candidate.ID] {
				if o.Kind == "declared_registry" {
					return true
				}
			}
			return false
		default:
			return false
		}
	}
	return true
}

// correlateImageLocks enriches observed occurrences only. The lockfile is a
// declaration: it never establishes installed package presence or artifact
// hashes, and correlated edges retain an explicit unverified condition.
func correlateImageLocks(doc *model.Document, files map[string]imageProjectFile) error {
	locks, issues, err := parseImageLocks(files, doc.Project)
	if err != nil {
		return err
	}
	doc.Coverage.Issues = append(doc.Coverage.Issues, issues...)
	index := map[string][]imageLockCandidate{}
	installedOrigins := map[string][]model.Origin{}
	for _, origin := range doc.Origins {
		installedOrigins[origin.Occurrence] = append(installedOrigins[origin.Occurrence], origin)
	}
	scopes, groups := map[string]map[string]bool{}, map[string]map[string]bool{}
	for li, lock := range locks {
		for ci, c := range lock.doc.Components {
			eco := lockedImageEcosystem(lock.manager, c)
			if eco == "" || c.Version == "" {
				continue
			}
			key := imageCoordinateKey(eco, c.Name, c.Version)
			index[key] = append(index[key], imageLockCandidate{li, ci})
			if scopes[eco] == nil {
				scopes[eco] = map[string]bool{}
			}
			scopes[eco][lock.scope] = true
		}
	}
	for _, c := range doc.Components {
		eco := installedImageEcosystem(c)
		key := imageCoordinateKey(eco, c.Name, c.Version)
		if groups[key] == nil {
			groups[key] = map[string]bool{}
		}
		groups[key][installedImageGroup(c, eco)] = true
	}
	mapped := make([]map[string][]int, len(locks))
	for i := range mapped {
		mapped[i] = map[string][]int{}
	}
	correlated := false
	for i := range doc.Components {
		installed := &doc.Components[i]
		eco := installedImageEcosystem(*installed)
		if eco == "" || installed.Version == "" {
			continue
		}
		candidates := append([]imageLockCandidate{}, index[imageCoordinateKey(eco, installed.Name, installed.Version)]...)
		if eco == "gem" {
			if platform := imageContextValue(installed.Context, "gem_platform"); platform != "" {
				candidates = append([]imageLockCandidate{}, index[imageCoordinateKey(eco, installed.Name, installed.Version+"-"+platform)]...)
			}
		}
		var matches []imageLockCandidate
		sourceConflict := false
		nearest := -1
		for _, candidate := range candidates {
			lock := locks[candidate.lock]
			if !imageLockCompatible(lock, lock.doc.Components[candidate.component], *installed, eco) {
				continue
			}
			local := imagePathWithin(lock.scope, installedImagePath(*installed))
			distance := 0
			if local {
				distance = len(lock.scope) + 1
			}
			distance *= 2
			if eco == "nuget" && strings.Contains(lock.doc.Components[candidate.component].Platform, "/") {
				distance++
			}
			globalAllowed := eco == "pypi" || eco == "gem" || eco == "r" || eco == "conda" || eco == "golang" || eco == "cargo"
			if !local && (!globalAllowed || len(scopes[eco]) != 1 || len(groups[imageCoordinateKey(eco, installed.Name, installed.Version)]) != 1) {
				continue
			}
			if distance > nearest {
				matches = nil
				nearest = distance
				sourceConflict = false
			}
			if distance < nearest {
				continue
			}
			conflicting := false
			for _, known := range installedOrigins[installed.ID] {
				for _, declared := range lock.origins[lock.doc.Components[candidate.component].ID] {
					vcsConflict := known.Kind == "vcs" && (len(known.Revision) >= 40 && len(known.Revision) == len(declared.Revision) && known.Revision != declared.Revision ||
						known.VCSType != "" && declared.VCSType != "" && known.VCSType != declared.VCSType)
					if known.Kind == declared.Kind && (known.Kind == "download_url" || known.Kind == "declared_registry" || known.Kind == "vcs") && known.SafeURL != "" && declared.SafeURL != "" && (known.SafeURL != declared.SafeURL || vcsConflict) {
						conflicting = true
					}
				}
			}
			if conflicting {
				sourceConflict = true
				continue
			}
			matches = append(matches, candidate)
		}
		if sourceConflict {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "image_lockfile_source_conflict", Name: installed.Name, Scope: installedImagePath(*installed)})
		}
		if len(matches) == 0 {
			continue
		}
		first := matches[0]
		lock, c := locks[first.lock], locks[first.lock].doc.Components[first.component]
		signature := imageLockSignature(lock, c)
		ambiguous := false
		seenLock := map[int]bool{}
		for _, match := range matches {
			other := locks[match.lock]
			if seenLock[match.lock] || imageLockSignature(other, other.doc.Components[match.component]) != signature {
				ambiguous = true
			}
			seenLock[match.lock] = true
		}
		if ambiguous {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "image_lockfile_match_ambiguous", Name: installed.Name, Scope: installedImagePath(*installed)})
			continue
		}
		for _, match := range matches {
			mapped[match.lock][locks[match.lock].doc.Components[match.component].ID] = append(mapped[match.lock][locks[match.lock].doc.Components[match.component].ID], i)
		}
		for _, e := range c.Evidence {
			if e.InputPath != "" {
				installed.Evidence = append(installed.Evidence, e)
			}
		}
		// A public-looking PURL in a lock is still only inferred for these
		// installed bytes; never promote the registry or transfer lock hashes.
		if installed.PURL == "" && c.PURL != "" && c.Version == installed.Version {
			installed.PURL, installed.PURLBasis = c.PURL, "ecosystem_inferred"
		}
		for _, origin := range lock.origins[c.ID] {
			if len(installedOrigins[installed.ID]) > 0 {
				continue
			}
			if origin.Occurrence != c.ID || origin.Evidence.InputPath == "" {
				continue
			}
			origin.Occurrence, origin.Status = installed.ID, "correlated_from_lockfile"
			doc.Origins = append(doc.Origins, origin)
		}
		for _, development := range lock.development[c.ID] {
			if len(installedOrigins[installed.ID]) > 0 {
				continue
			}
			if development.Occurrence != c.ID || development.Evidence.InputPath == "" {
				continue
			}
			development.Occurrence, development.Status = installed.ID, "correlated_from_lockfile"
			doc.Development = append(doc.Development, development)
		}
		correlated = true
	}
	seenEdges := map[string]bool{}
	for li, lock := range locks {
		if len(mapped[li]) == 0 && len(lock.doc.Components) > 0 {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "image_lockfile_no_installed_match", Name: lock.name})
		}
		for _, edge := range lock.doc.Edges {
			from, to := mapped[li][edge.From], mapped[li][edge.To]
			if len(from) != 1 || len(to) != 1 || from[0] == to[0] || edge.Evidence.InputPath == "" {
				continue
			}
			parent, child := doc.Components[from[0]], doc.Components[to[0]]
			eco := installedImageEcosystem(parent)
			if eco != installedImageEcosystem(child) || installedImageGroup(parent, eco) != installedImageGroup(child, eco) {
				continue
			}
			edge.From, edge.To = parent.ID, child.ID
			if edge.Condition != "" {
				edge.Condition += ";"
			}
			edge.Condition += "lockfile_installation=unverified"
			key := edge.From + "\x00" + edge.To + "\x00" + edge.Kind + "\x00" + edge.Condition
			if !seenEdges[key] {
				doc.Edges = append(doc.Edges, edge)
				seenEdges[key] = true
			}
		}
	}
	if correlated {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "image_lockfile_installation_unverified"})
	}
	return nil
}
