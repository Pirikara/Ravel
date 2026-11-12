package merge

import (
	"testing"

	"github.com/Pirikara/Ravel/internal/collectors/common"
	"github.com/Pirikara/Ravel/internal/model"
)

func TestDocumentsValidateOfficialNpmTarballAgainstPackage(t *testing.T) {
	for _, test := range []struct {
		name, version, url string
		valid              bool
	}{
		{"js-tokens", "4.0.0", "https://registry.npmjs.org/js-tokens/-/js-tokens-4.0.0.tgz", true},
		{"@octokit/auth-token", "4.0.0", "https://registry.npmjs.org/@octokit/auth-token/-/auth-token-4.0.0.tgz", true},
		{"js-tokens", "4.0.0", "https://registry.npmjs.org/js-tokens/-/js-tokens-9.0.0.tgz", false},
		{"js-tokens", "4.0.0", "https://user:secret@registry.npmjs.org/js-tokens/-/js-tokens-4.0.0.tgz", false},
		{"js-tokens", "4.0.0", "https://example.test/js-tokens/-/js-tokens-4.0.0.tgz", false},
	} {
		t.Run(test.name+" "+test.url, func(t *testing.T) {
			first := common.NewDocument("npm.lock", "npm", "npm", nil)
			first.Components = []model.Component{{ID: "package", Kind: "package", Name: test.name, Version: test.version}}
			first.Origins = []model.Origin{{Occurrence: "package", SafeURL: test.url}}
			second := common.NewDocument("composer.lock", "composer", "composer", nil)
			merged, err := Documents("mixed", []model.Document{first, second})
			if (err == nil) != test.valid {
				t.Fatalf("merge URL validation: err=%v", err)
			}
			if test.valid && (len(merged.Origins) != 1 || merged.Origins[0].SafeURL != test.url) {
				t.Fatalf("validated origin lost: %#v", merged.Origins)
			}
		})
	}
}
