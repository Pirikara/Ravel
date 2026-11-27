package common

import (
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"

	packageurl "github.com/package-url/packageurl-go"

	"github.com/Pirikara/Ravel/internal/model"
	"github.com/Pirikara/Ravel/internal/safeurl"
)

var originPythonSeparators = regexp.MustCompile(`[-_.]+`)
var sourceRevision = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$`)

func originVCSType(o model.Origin) string {
	if o.VCSType != "" {
		return o.VCSType
	}
	if strings.HasPrefix(o.SafeURL, "git://") {
		return "git"
	}
	switch o.Evidence.Collector {
	case "bundler-lock", "cargo-lock", "cargo-metadata", "uv-lock", "poetry-lock", "pdm-lock", "pipenv-lock", "pip-requirements", "npm-lock", "npm-lock-v1", "node-package-json", "bun-lock", "yarn-lock", "yarn-classic", "yarn-berry", "pnpm-lock", "github-actions-workflow":
		return "git"
	}
	return ""
}

// VCSLocation uses the SPDX/PURL VCS locator syntax. A development repository
// is not a package source; callers must supply an actual VCS origin record.
func VCSLocation(o model.Origin) string {
	clean := safeurl.Clean(o.SafeURL)
	if clean == "" {
		return ""
	}
	vcs := originVCSType(o)
	switch vcs {
	case "git", "hg", "svn", "bzr":
	default:
		return ""
	}
	if o.Revision != "" && (!sourceRevision.MatchString(o.Revision) || strings.Contains(o.Revision, "..")) {
		return ""
	}
	location := vcs + "+" + clean
	if o.Revision != "" {
		location += "@" + o.Revision
	}
	if subdir, ok := strings.CutPrefix(o.Target, "subdirectory="); ok && subdir != "" {
		if path.IsAbs(subdir) || path.Clean(subdir) != subdir || subdir == ".." || strings.HasPrefix(subdir, "../") || strings.ContainsAny(subdir, "\\\x00\r\n") {
			return ""
		}
		parts := strings.Split(subdir, "/")
		for i := range parts {
			parts[i] = url.PathEscape(parts[i])
		}
		location += "#" + strings.Join(parts, "/")
	}
	return location
}

func baseOriginPURL(manager string, c model.Component) packageurl.PackageURL {
	if c.PURL != "" {
		value := c.PURL
		// packageurl-go's golang adapter lowercases module paths. Preserve
		// Go's case-sensitive coordinate when adding source qualifiers.
		goModule := strings.HasPrefix(value, "pkg:golang/")
		if goModule {
			value = "pkg:generic/" + strings.TrimPrefix(value, "pkg:golang/")
		}
		p, err := packageurl.FromString(value)
		if err == nil {
			if goModule {
				p.Type = "golang"
			}
			return p
		}
	}
	if c.Kind != "package" || c.Name == "" || c.Version == "" {
		return packageurl.PackageURL{}
	}
	typ, namespace, name := "", "", c.Name
	switch manager {
	case "npm", "npm-installed", "pnpm", "yarn", "bun":
		typ = "npm"
		if strings.HasPrefix(name, "@") {
			namespace, name, _ = strings.Cut(name, "/")
		}
	case "uv", "pylock", "poetry", "pdm", "pipenv", "requirements", "python-installed":
		typ = "pypi"
		name = originPythonSeparators.ReplaceAllString(strings.ToLower(name), "-")
	case "bundler", "ruby-installed":
		typ = "gem"
	case "composer", "composer-installed":
		typ = "composer"
		namespace, name, _ = strings.Cut(strings.ToLower(name), "/")
	case "nuget":
		typ = "nuget"
	case "cargo":
		typ = "cargo"
	case "maven", "gradle", "sbt", "java-archive":
		typ = "maven"
		namespace, name, _ = strings.Cut(name, ":")
	case "conda":
		typ = "conda"
	case "conda-lock", "pixi":
		if strings.Contains(c.Context, "manager=conda_source") {
			return packageurl.PackageURL{}
		}
		if strings.Contains(c.Context, "manager=pip") {
			typ = "pypi"
			name = originPythonSeparators.ReplaceAllString(strings.ToLower(name), "-")
		} else {
			typ = "conda"
		}
	}
	if typ == "" || name == "" || (typ == "composer" || typ == "maven") && namespace == "" {
		return packageurl.PackageURL{}
	}
	return *packageurl.NewPackageURL(typ, namespace, name, c.Version, nil, "")
}

func defaultOriginRepository(typ, raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Port() != "" && u.Port() != "443" {
		return false
	}
	host, p := strings.ToLower(u.Hostname()), strings.TrimRight(u.Path, "/")
	switch typ {
	case "npm":
		return host == "registry.npmjs.org" && p == ""
	case "pypi":
		return (host == "pypi.org" || host == "pypi.python.org") && (p == "" || p == "/simple")
	case "gem":
		return host == "rubygems.org" && p == ""
	case "nuget":
		return host == "www.nuget.org" && (p == "" || p == "/api/v2") || host == "api.nuget.org" && p == "/v3/index.json"
	case "composer":
		return (host == "packagist.org" || host == "repo.packagist.org") && p == ""
	case "cargo":
		return host == "crates.io" && p == "" || host == "index.crates.io" && p == "" || host == "github.com" && p == "/rust-lang/crates.io-index"
	case "maven":
		return (host == "repo.maven.apache.org" || host == "repo1.maven.org") && p == "/maven2"
	case "cran":
		return host == "cran.r-project.org" && p == ""
	case "pub":
		return (host == "pub.dev" || host == "pub.dartlang.org") && p == ""
	case "cocoapods":
		return host == "cdn.cocoapods.org" && p == ""
	case "hackage":
		return host == "hackage.haskell.org" && p == ""
	case "hex":
		return host == "repo.hex.pm" && p == ""
	case "julia":
		return host == "github.com" && p == "/JuliaRegistries/General"
	case "conan":
		return host == "center.conan.io" && p == ""
	}
	return false
}

func defaultOriginDownload(p packageurl.PackageURL, raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Port() != "" && u.Port() != "443" {
		return false
	}
	if p.Type == "npm" && strings.EqualFold(u.Hostname(), "registry.npmjs.org") {
		name := p.Name
		if p.Namespace != "" {
			name = p.Namespace + "/" + name
		}
		return safeurl.CleanNpmTarball(raw, name, p.Version) != ""
	}
	if p.Type == "pypi" && strings.EqualFold(u.Hostname(), "files.pythonhosted.org") {
		base := path.Base(u.Path)
		parts := strings.Split(base, "-")
		if strings.HasSuffix(base, ".whl") && (len(parts) == 5 || len(parts) == 6) {
			return originPythonSeparators.ReplaceAllString(strings.ToLower(parts[0]), "-") == p.Name && parts[1] == p.Version
		}
	}
	return false
}

func genericOriginPURL(p packageurl.PackageURL) string {
	namespace := p.Type
	if p.Namespace != "" {
		namespace += "/" + p.Namespace
	}
	qualifiers := p.Qualifiers.Map()
	delete(qualifiers, "repository_url")
	delete(qualifiers, "download_url")
	delete(qualifiers, "vcs_url")
	return packageurl.NewPackageURL("generic", namespace, p.Name, p.Version, packageurl.QualifiersFromMap(qualifiers), p.Subpath).ToString()
}

// Qualify identities from occurrence-specific source records. A registry is
// preferred over a distribution file, which is preferred over a VCS checkout.
// A configured feed or a development repository is not an artifact origin.
// This preserves declared/recorded locations; it never verifies provenance.
func qualifyOriginPURLs(doc *model.Document) {
	byID := map[string][]model.Origin{}
	for i := range doc.Origins {
		o := &doc.Origins[i]
		if o.Kind == "vcs" {
			o.VCSType = originVCSType(*o)
		}
		byID[o.Occurrence] = append(byID[o.Occurrence], *o)
	}
	for i := range doc.Components {
		c := &doc.Components[i]
		origins := byID[c.ID]
		if len(origins) == 0 {
			continue
		}
		p := baseOriginPURL(doc.Coverage.Manager, *c)
		if p.Type == "" {
			continue
		}
		registries, downloads, vcs := map[string]bool{}, map[string]bool{}, map[string]bool{}
		local := false
		unrepresentedVCS := false
		for _, o := range origins {
			clean := safeurl.Clean(o.SafeURL)
			switch o.Kind {
			case "declared_registry", "registry_identity":
				if clean != "" {
					registries[clean] = true
				}
			case "download_url":
				if clean != "" {
					downloads[clean] = true
				}
			case "vcs":
				if location := VCSLocation(o); location != "" {
					vcs[location] = true
				} else {
					unrepresentedVCS = true
				}
			case "local":
				local = true
			}
		}
		one := func(values map[string]bool) string {
			if len(values) != 1 {
				return ""
			}
			for value := range values {
				return value
			}
			return ""
		}
		// Registry and download records can be alternative representations of the
		// same origin. Only conflicts at the chosen specificity are ambiguous.
		qualifiers := p.Qualifiers.Map()
		changed := false
		ambiguous := len(registries) > 1 || len(registries) == 0 && (len(downloads) > 1 || len(downloads) == 0 && len(vcs) > 1)
		if ambiguous {
			found := false
			for _, issue := range doc.Coverage.Issues {
				found = found || issue.Code == "purl_source_ambiguous" && issue.Scope == c.ID
			}
			if !found {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "purl_source_ambiguous", Name: c.Name, Scope: c.ID})
			}
			if p.Type != "generic" {
				c.PURL = genericOriginPURL(p)
				c.PURLBasis = "source_ambiguous"
			}
			continue
		}
		defaultLocation := false
		if registry := one(registries); registry != "" {
			if !defaultOriginRepository(p.Type, registry) {
				qualifiers["repository_url"] = registry
				changed = true
			} else {
				defaultLocation = true
			}
		} else if len(registries) == 0 {
			if download := one(downloads); download != "" {
				if !defaultOriginDownload(p, download) && !(p.Type == "conda" && qualifiers["channel"] != "") {
					qualifiers["download_url"] = download
					changed = true
				} else {
					defaultLocation = true
				}
			} else if len(downloads) == 0 {
				if location := one(vcs); location != "" {
					qualifiers["vcs_url"] = location
					changed = true
				}
			}
		}
		if changed {
			if c.Platform != "" && p.Type == "gem" && c.Platform != "ruby" {
				qualifiers["platform"] = c.Platform
			}
			p.Qualifiers = packageurl.QualifiersFromMap(qualifiers)
			c.PURL = p.ToString()
			c.PURLBasis = "source_qualified"
		} else if defaultLocation && c.PURL == "" {
			c.PURL = p.ToString()
			c.PURLBasis = "ecosystem_inferred"
		} else if (local || unrepresentedVCS) && len(registries)+len(downloads)+len(vcs) == 0 && c.PURL != "" && c.Kind == "package" && p.Type != "generic" && p.Type != "swift" && p.Type != "github" && p.Type != "golang" {
			c.PURL = genericOriginPURL(p)
		}
	}
}

// UniqueSourceLocations returns stable, sanitized direct download locations.
// Registry bases are not exact package download URLs.
func UniqueSourceLocations(origins []model.Origin) []string {
	set := map[string]bool{}
	for _, o := range origins {
		if o.Kind == "download_url" {
			if value := safeurl.Clean(o.SafeURL); value != "" {
				set[value] = true
			}
		}
	}
	values := make([]string, 0, len(set))
	for value := range set {
		values = append(values, value)
	}
	sort.Strings(values)
	return values
}
