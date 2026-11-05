package safeurl

import (
	"net/url"
	"strings"
)

// Clean returns a locator suitable for output. Credentials and signed URL
// parameters are never retained in the in-memory document.
func Clean(raw string) string {
	raw = strings.TrimSpace(raw)
	raw = strings.TrimPrefix(raw, "git+")
	if strings.HasPrefix(raw, "git@") {
		host, repo, found := strings.Cut(strings.TrimPrefix(raw, "git@"), ":")
		if !found || host == "" || repo == "" || strings.HasPrefix(repo, "/") || strings.ContainsAny(host, "/? #@\t\r\n") {
			return ""
		}
		raw = "ssh://" + host + "/" + repo
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	switch strings.ToLower(u.Scheme) {
	case "https", "http", "ssh", "git":
	default:
		return ""
	}
	for _, segment := range strings.Split(strings.ToLower(u.Path), "/") {
		if sensitivePathSegment(segment) {
			return ""
		}
	}
	u.User = nil
	u.RawQuery = ""
	u.ForceQuery = false
	u.Fragment = ""
	u.RawFragment = ""
	return u.String()
}

// IsGitHubActionsRepository recognizes the fixed-host owner/repository URL
// constructed from a validated GitHub Actions uses reference. A repository
// name may contain words such as "token" without containing a secret. This
// exception is deliberately limited to two plain path segments.
func IsGitHubActionsRepository(raw, actionName string) bool {
	const prefix = "https://github.com/"
	if !strings.HasPrefix(raw, prefix) {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(raw, prefix), "/")
	if len(parts) != 2 {
		return false
	}
	nameParts := strings.Split(actionName, "/")
	if len(nameParts) < 2 || parts[0] != nameParts[0] || parts[1] != nameParts[1] {
		return false
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return false
		}
		for _, r := range part {
			if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '.' {
				continue
			}
			return false
		}
	}
	return true
}

func sensitivePathSegment(segment string) bool {
	for _, term := range []string{"token", "apikey", "api_key", "password"} {
		if strings.HasPrefix(segment, term) || strings.HasSuffix(segment, term) || strings.Contains(segment, "_"+term) || strings.Contains(segment, "-"+term) || strings.Contains(segment, "."+term) {
			return true
		}
	}
	return false
}
