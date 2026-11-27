package npm

import (
	"path"
	"strings"

	semver "github.com/Masterminds/semver/v3"
)

func matchesNpmRequirementAt(required string, target *item, location string) (bool, bool) {
	if strings.HasPrefix(required, "file:") && localLockLocation(target.location) &&
		!strings.Contains("/"+target.location+"/", "/node_modules/") {
		return path.Join(location, strings.TrimPrefix(required, "file:")) == target.location, true
	}
	return matchesNpmRequirement(required, target)
}

// matchesNpmRequirement checks ranges only when the lockfile gives enough
// information. Unknown selectors retain their edge with partial coverage.
func matchesNpmRequirement(required string, target *item) (matches, verified bool) {
	if required == "" {
		return true, false
	}
	// npm accepts an already locked prerelease for an explicit wildcard.
	if strings.TrimSpace(required) == "*" {
		return true, target.data.Version != ""
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
