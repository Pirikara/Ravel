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
	for _, segment := range strings.Split(strings.ToLower(u.EscapedPath()), "/") {
		if strings.Contains(segment, "token") || strings.Contains(segment, "apikey") || strings.Contains(segment, "api_key") || strings.Contains(segment, "password") {
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
