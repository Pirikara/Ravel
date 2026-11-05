package safeurl_test

import (
	"testing"

	"github.com/Pirikara/Ravel/internal/safeurl"
)

func TestClean(t *testing.T) {
	cases := map[string]string{
		"https://user:password@example.test/path?token=abc#frag":                   "https://example.test/path",
		"https://example.test/token/abc":                                           "",
		"https://example.test/%74oken/abc":                                         "",
		"https://example.test/auth_token/abc":                                      "",
		"https://example.test/token123/abc":                                        "",
		"https://prefix.dev/conda-forge/noarch/asttokens-3.0.2-pyhd8ed1ab_0.conda": "https://prefix.dev/conda-forge/noarch/asttokens-3.0.2-pyhd8ed1ab_0.conda",
		"file:///tmp/private":                                                      "",
		"not a url":                                                                "",
		"git@github.com:team/repo.git":                                             "ssh://github.com/team/repo.git",
		"git+ssh://git@github.com/team/repo.git?token=hidden":                      "ssh://github.com/team/repo.git",
		"git+https://user:secret@github.com/team/repo.git":                         "https://github.com/team/repo.git",
		"git@github.com:/absolute/repo.git":                                        "",
	}
	for input, want := range cases {
		if got := safeurl.Clean(input); got != want {
			t.Errorf("Clean(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestGitHubActionsRepositoryURL(t *testing.T) {
	for _, tc := range []struct {
		url  string
		name string
		want bool
	}{
		{"https://github.com/actions/create-github-app-token", "actions/create-github-app-token", true},
		{"https://github.com/owner/repository", "owner/repository/subpath", true},
		{"https://github.com/owner/repository", "owner/different", false},
		{"https://github.com/owner/repository/path", "owner/repository", false},
		{"https://github.com/owner/repository?token=secret", "owner/repository", false},
		{"https://user:secret@github.com/owner/repository", "owner/repository", false},
		{"https://github.com.evil.test/owner/repository", "owner/repository", false},
		{"https://github.com/owner/%74oken", "owner/token", false},
		{"https://github.com/owner/..", "owner/..", false},
	} {
		if got := safeurl.IsGitHubActionsRepository(tc.url, tc.name); got != tc.want {
			t.Errorf("IsGitHubActionsRepository(%q, %q) = %v, want %v", tc.url, tc.name, got, tc.want)
		}
	}
}
