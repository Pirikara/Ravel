package rpm

import (
	"strconv"
	"strings"
)

// compareRPMEVR compares well-formed RPM epoch:version-release labels. When
// versions are equal but only one label has a release, the result is left
// undecided: RPM dependency matching can omit the release independently of
// how complete EVR labels sort.
// Version ordering: https://rpm.org/docs/6.0.x/man/rpm-version.7
func compareRPMEVR(a, b string) (int, bool) {
	aEpoch, aVersion, aRelease, aHasRelease, aOK := parseRPMEVR(a)
	bEpoch, bVersion, bRelease, bHasRelease, bOK := parseRPMEVR(b)
	if !aOK || !bOK {
		return 0, false
	}
	if aEpoch < bEpoch {
		return -1, true
	}
	if aEpoch > bEpoch {
		return 1, true
	}
	if comparison := compareRPMPart(aVersion, bVersion); comparison != 0 {
		return comparison, true
	}
	if aHasRelease != bHasRelease {
		return 0, false
	}
	if !aHasRelease {
		return 0, true
	}
	return compareRPMPart(aRelease, bRelease), true
}

// compareRPMProviderToRequirement accounts for RPM's dependency rule that a
// requirement without a release compares against the provider's version only.
// A provider without a release is wider than a single EVR, so that direction
// remains undecided here.
// https://rpm-software-management.github.io/rpm/man/rpm-dependencies.7
func compareRPMProviderToRequirement(provider, requirement string) (int, bool) {
	if comparison, comparable := compareRPMEVR(provider, requirement); comparable {
		return comparison, true
	}
	pEpoch, pVersion, _, pHasRelease, pOK := parseRPMEVR(provider)
	rEpoch, rVersion, _, rHasRelease, rOK := parseRPMEVR(requirement)
	if pOK && rOK && pHasRelease && !rHasRelease && pEpoch == rEpoch && compareRPMPart(pVersion, rVersion) == 0 {
		return 0, true
	}
	return 0, false
}

func parseRPMEVR(evr string) (uint64, string, string, bool, bool) {
	if evr == "" || len(evr) > 512 {
		return 0, "", "", false, false
	}
	epoch := uint64(0)
	if before, after, found := strings.Cut(evr, ":"); found {
		var err error
		epoch, err = strconv.ParseUint(before, 10, 32)
		if err != nil {
			return 0, "", "", false, false
		}
		evr = after
	}
	version, release, hasRelease := strings.Cut(evr, "-")
	if !validRPMVersionPart(version) || hasRelease && !validRPMVersionPart(release) {
		return 0, "", "", false, false
	}
	return epoch, version, release, hasRelease, true
}

func validRPMVersionPart(part string) bool {
	if part == "" || !rpmAlphaNumeric(part[0]) || !rpmAlphaNumeric(part[len(part)-1]) {
		return false
	}
	for i := 0; i < len(part); i++ {
		c := part[i]
		if !rpmAlphaNumeric(c) && c != '.' && c != '_' && c != '+' && c != '~' && c != '^' {
			return false
		}
		if (c == '~' || c == '^') && (i+1 == len(part) || !rpmAlphaNumeric(part[i+1])) {
			return false
		}
	}
	return true
}

func rpmAlphaNumeric(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func rpmNumeric(c byte) bool {
	return c >= '0' && c <= '9'
}

func rpmAlphabetic(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func skipRPMSeparators(part string, i int) int {
	for i < len(part) && (part[i] == '.' || part[i] == '_' || part[i] == '+') {
		i++
	}
	return i
}

func compareRPMPart(a, b string) int {
	for i, j := 0, 0; ; {
		i = skipRPMSeparators(a, i)
		j = skipRPMSeparators(b, j)
		aTilde, bTilde := i < len(a) && a[i] == '~', j < len(b) && b[j] == '~'
		if aTilde || bTilde {
			if aTilde && bTilde {
				i++
				j++
				continue
			}
			if aTilde {
				return -1
			}
			return 1
		}
		aCaret, bCaret := i < len(a) && a[i] == '^', j < len(b) && b[j] == '^'
		if aCaret || bCaret {
			if aCaret && bCaret {
				i++
				j++
				continue
			}
			if aCaret {
				if j == len(b) {
					return 1
				}
				return -1
			}
			if i == len(a) {
				return -1
			}
			return 1
		}
		if i == len(a) || j == len(b) {
			if i == len(a) && j == len(b) {
				return 0
			}
			if i == len(a) {
				return -1
			}
			return 1
		}
		aNumber, bNumber := rpmNumeric(a[i]), rpmNumeric(b[j])
		if aNumber != bNumber {
			if aNumber {
				return 1
			}
			return -1
		}
		aStart, bStart := i, j
		if aNumber {
			for i < len(a) && rpmNumeric(a[i]) {
				i++
			}
			for j < len(b) && rpmNumeric(b[j]) {
				j++
			}
			aSegment := strings.TrimLeft(a[aStart:i], "0")
			bSegment := strings.TrimLeft(b[bStart:j], "0")
			if len(aSegment) < len(bSegment) {
				return -1
			}
			if len(aSegment) > len(bSegment) {
				return 1
			}
			if comparison := strings.Compare(aSegment, bSegment); comparison != 0 {
				return comparison
			}
			continue
		}
		for i < len(a) && rpmAlphabetic(a[i]) {
			i++
		}
		for j < len(b) && rpmAlphabetic(b[j]) {
			j++
		}
		if comparison := strings.Compare(a[aStart:i], b[bStart:j]); comparison != 0 {
			return comparison
		}
	}
}
