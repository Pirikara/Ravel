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

func sensitivePathSegment(segment string) bool {
	for _, term := range []string{"token", "apikey", "api_key", "password"} {
		if strings.HasPrefix(segment, term) || strings.HasSuffix(segment, term) || strings.Contains(segment, "_"+term) || strings.Contains(segment, "-"+term) || strings.Contains(segment, "."+term) {
			return true
		}
	}
	return false
}
