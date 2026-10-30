package npm

import (
	"strings"

	semver "github.com/Masterminds/semver/v3"
)

// matchesNpmRequirement checks ranges only when the lockfile gives enough
// information. Unknown selectors retain their edge with partial coverage.
func matchesNpmRequirement(required string, target *item) (matches, verified bool) {
	if required == "" {
		return true, false
	}
	if strings.HasPrefix(required, "npm:") {
		alias := strings.TrimPrefix(required, "npm:")
		at := strings.LastIndex(alias, "@")
		name, constraint := alias, ""
		if at > 0 {
			name, constraint = alias[:at], alias[at+1:]
		}
		if target.data.Name == "" {
			return true, false
		}
		if target.data.Name != name {
			return false, true
		}
		if constraint == "" {
			return true, false
		}
		return matchesNpmRange(constraint, target)
	}
	if required == target.data.Version || required == target.data.Resolved {
		return true, true
	}
	return matchesNpmRange(required, target)
}

func matchesNpmRange(required string, target *item) (matches, verified bool) {
	wanted, err := semver.NewConstraint(required)
	if err != nil {
		return true, false
	}
	selected, err := semver.StrictNewVersion(target.data.Version)
	if err != nil {
		return true, false
	}
	return wanted.Check(selected), true
}
