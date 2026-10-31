package rpm

import (
	"strconv"
	"strings"
)

// compareNumericRPMEVR handles the subset whose version consists only of
// dot-separated decimal segments. A differing epoch or version decides the
// ordering without interpreting the release. Equal versions with different
// EVR strings stay undecided because release comparison needs full RPM rules.
// Numeric segment ordering: https://rpm.org/docs/6.0.x/man/rpm-version.7
func compareNumericRPMEVR(a, b string) (int, bool) {
	aEpoch, aVersion, aOK := numericRPMVersion(a)
	bEpoch, bVersion, bOK := numericRPMVersion(b)
	if !aOK || !bOK {
		return 0, false
	}
	if aEpoch < bEpoch {
		return -1, true
	}
	if aEpoch > bEpoch {
		return 1, true
	}
	for i := 0; i < len(aVersion) && i < len(bVersion); i++ {
		aPart := strings.TrimLeft(aVersion[i], "0")
		bPart := strings.TrimLeft(bVersion[i], "0")
		if len(aPart) < len(bPart) {
			return -1, true
		}
		if len(aPart) > len(bPart) {
			return 1, true
		}
		if aPart < bPart {
			return -1, true
		}
		if aPart > bPart {
			return 1, true
		}
	}
	if len(aVersion) < len(bVersion) {
		return -1, true
	}
	if len(aVersion) > len(bVersion) {
		return 1, true
	}
	return 0, false
}

func numericRPMVersion(evr string) (uint64, []string, bool) {
	if len(evr) == 0 || len(evr) > 512 {
		return 0, nil, false
	}
	epoch := uint64(0)
	if before, after, found := strings.Cut(evr, ":"); found {
		var err error
		epoch, err = strconv.ParseUint(before, 10, 32)
		if err != nil {
			return 0, nil, false
		}
		evr = after
	}
	version, _, _ := strings.Cut(evr, "-")
	segments := strings.Split(version, ".")
	for _, segment := range segments {
		if segment == "" {
			return 0, nil, false
		}
		for i := 0; i < len(segment); i++ {
			if segment[i] < '0' || segment[i] > '9' {
				return 0, nil, false
			}
		}
	}
	return epoch, segments, true
}
