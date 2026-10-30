package apk

import (
	"regexp"
	"strings"
)

// This comparator deliberately covers only version orderings that follow
// directly from the numeric prefix or a simple package revision. APK has
// additional suffix ordering rules; callers retain an unverified constraint
// when those rules could affect the result.
var versionTail = regexp.MustCompile(`^(?:[a-z])?(?:_(?:alpha|beta|pre|rc|cvs|svn|git|hg|p)[0-9]*)*(?:~[0-9a-f]+)?(?:-r[0-9]+)?$`)

func matchesVersion(op, installed, required string) (bool, bool) {
	if op == "" {
		return true, true
	}
	if installed == "" { // An unversioned provide cannot satisfy a versioned dependency.
		return false, true
	}
	if op == "=" || op == "==" {
		return installed == required, true
	}
	if op == "~" {
		return false, false
	}
	comparison, verified := compareVersions(installed, required)
	if !verified {
		return false, false
	}
	switch op {
	case ">":
		return comparison > 0, true
	case ">=":
		return comparison >= 0, true
	case "<":
		return comparison < 0, true
	case "<=":
		return comparison <= 0, true
	}
	return false, false
}

func compareVersions(a, b string) (int, bool) {
	if a == b && a != "" {
		return 0, true
	}
	aParts, aTail, aValid := numericPrefix(a)
	bParts, bTail, bValid := numericPrefix(b)
	if !aValid || !bValid || !versionTail.MatchString(aTail) || !versionTail.MatchString(bTail) {
		return 0, false
	}
	for i := 0; i < len(aParts) && i < len(bParts); i++ {
		comparison := compareNumeric(aParts[i], bParts[i])
		if comparison != 0 {
			return comparison, true
		}
	}
	if len(aParts) != len(bParts) {
		if len(aParts) < len(bParts) && aTail == "" && simpleRevision(bTail) || len(bParts) < len(aParts) && bTail == "" && simpleRevision(aTail) {
			if len(aParts) < len(bParts) {
				return -1, true
			}
			return 1, true
		}
		return 0, false
	}
	if !simpleRevision(aTail) || !simpleRevision(bTail) {
		return 0, false
	}
	if aTail == bTail {
		return 0, true
	}
	if aTail == "" {
		return -1, true
	}
	if bTail == "" {
		return 1, true
	}
	return compareNumeric(strings.TrimPrefix(aTail, "-r"), strings.TrimPrefix(bTail, "-r")), true
}

func numericPrefix(version string) ([]string, string, bool) {
	if version == "" || version[0] < '0' || version[0] > '9' {
		return nil, "", false
	}
	i := 0
	for i < len(version) && (version[i] >= '0' && version[i] <= '9' || version[i] == '.') {
		i++
	}
	part := version[:i]
	if strings.HasSuffix(part, ".") {
		return nil, "", false
	}
	parts := strings.Split(part, ".")
	for _, value := range parts {
		if value == "" || len(value) > 1 && value[0] == '0' {
			return nil, "", false
		}
	}
	return parts, version[i:], true
}

func simpleRevision(tail string) bool {
	if tail == "" {
		return true
	}
	if !strings.HasPrefix(tail, "-r") {
		return false
	}
	value := strings.TrimPrefix(tail, "-r")
	if value == "" || len(value) > 1 && value[0] == '0' {
		return false
	}
	for _, c := range value {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func compareNumeric(a, b string) int {
	if len(a) < len(b) {
		return -1
	}
	if len(a) > len(b) {
		return 1
	}
	return strings.Compare(a, b)
}
