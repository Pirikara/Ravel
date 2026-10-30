package dpkg

import "strings"

// compareVersions implements Debian's epoch, upstream, and revision ordering.
// It returns false for malformed values instead of guessing a relationship.
func compareVersions(a, b string) (int, bool) {
	aEpoch, aUpstream, aRevision, ok := splitVersion(a)
	if !ok {
		return 0, false
	}
	bEpoch, bUpstream, bRevision, ok := splitVersion(b)
	if !ok {
		return 0, false
	}
	if result := compareNumber(aEpoch, bEpoch); result != 0 {
		return result, true
	}
	if result := comparePart(aUpstream, bUpstream); result != 0 {
		return result, true
	}
	return comparePart(aRevision, bRevision), true
}

func splitVersion(value string) (epoch, upstream, revision string, ok bool) {
	if value == "" || strings.ContainsAny(value, " \t\r\n") {
		return "", "", "", false
	}
	epoch = "0"
	if i := strings.IndexByte(value, ':'); i >= 0 {
		epoch, value = value[:i], value[i+1:]
		if epoch == "" || !allDigits(epoch) {
			return "", "", "", false
		}
	}
	revision = "0"
	if i := strings.LastIndexByte(value, '-'); i >= 0 {
		value, revision = value[:i], value[i+1:]
		if revision == "" {
			return "", "", "", false
		}
	}
	if value == "" || value[0] < '0' || value[0] > '9' {
		return "", "", "", false
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if !isDigit(c) && !isLetter(c) && c != '.' && c != '+' && c != '~' && c != '-' {
			return "", "", "", false
		}
	}
	for i := 0; i < len(revision); i++ {
		c := revision[i]
		if !isDigit(c) && !isLetter(c) && c != '.' && c != '+' && c != '~' {
			return "", "", "", false
		}
	}
	return epoch, value, revision, true
}

func comparePart(a, b string) int {
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		for i < len(a) && !isDigit(a[i]) || j < len(b) && !isDigit(b[j]) {
			var x, y byte
			if i < len(a) && !isDigit(a[i]) {
				x = a[i]
				i++
			}
			if j < len(b) && !isDigit(b[j]) {
				y = b[j]
				j++
			}
			if result := orderChar(x) - orderChar(y); result != 0 {
				if result < 0 {
					return -1
				}
				return 1
			}
		}
		aStart, bStart := i, j
		for i < len(a) && isDigit(a[i]) {
			i++
		}
		for j < len(b) && isDigit(b[j]) {
			j++
		}
		if result := compareNumber(a[aStart:i], b[bStart:j]); result != 0 {
			return result
		}
	}
	return 0
}

func compareNumber(a, b string) int {
	a = strings.TrimLeft(a, "0")
	b = strings.TrimLeft(b, "0")
	if len(a) < len(b) {
		return -1
	}
	if len(a) > len(b) {
		return 1
	}
	return strings.Compare(a, b)
}

func orderChar(c byte) int {
	if c == '~' {
		return -1
	}
	if c == 0 {
		return 0
	}
	if isLetter(c) {
		return int(c)
	}
	return int(c) + 256
}

func allDigits(value string) bool {
	for i := 0; i < len(value); i++ {
		if !isDigit(value[i]) {
			return false
		}
	}
	return true
}

func isDigit(c byte) bool  { return c >= '0' && c <= '9' }
func isLetter(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }

func satisfies(comparison int, op string) bool {
	switch op {
	case "<<":
		return comparison < 0
	case "<=":
		return comparison <= 0
	case "=":
		return comparison == 0
	case ">=":
		return comparison >= 0
	case ">>":
		return comparison > 0
	}
	return false
}
