package common

import (
	"net/url"
	"strings"

	"github.com/Pirikara/Ravel/internal/model"
	"github.com/Pirikara/Ravel/internal/safeurl"
)

// AddDevelopment records a metadata assertion, never a distribution origin.
func AddDevelopment(doc *model.Document, occurrence, raw, status string, evidence model.Evidence) {
	if strings.TrimSpace(raw) == "" {
		return
	}
	clean := safeurl.Clean(raw)
	if clean == "" {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unsafe_or_invalid_development_source", Scope: occurrence})
		return
	}
	doc.Development = append(doc.Development, model.Development{Occurrence: occurrence, SafeURL: clean, Status: status, Evidence: evidence})
}

// RepositoryHomepage recognizes repository-shaped links on known code forges.
// It is only a candidate, not a declaration that the homepage is the source.
func RepositoryHomepage(raw string) string {
	clean := safeurl.Clean(raw)
	u, err := url.Parse(clean)
	if err != nil || u == nil || u.Scheme != "https" && u.Scheme != "http" {
		return ""
	}
	switch strings.ToLower(u.Host) {
	case "github.com", "gitlab.com", "bitbucket.org", "codeberg.org":
	default:
		return ""
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return ""
	}
	for _, part := range parts {
		if part == "." || part == ".." || strings.ContainsAny(part, "% \\\t\r\n") {
			return ""
		}
	}
	switch strings.ToLower(parts[0]) {
	case "orgs", "users", "groups", "explore", "settings", "login", "help":
		return ""
	}
	return clean
}
