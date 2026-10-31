package rpm

import "strings"

type rpmGuardState uint8

const (
	rpmGuardAbsent rpmGuardState = iota
	rpmGuardPresent
	rpmGuardUnknown
)

// parseSimpleRPMIf accepts only one unnested implication. Rich dependencies
// with other operators or nested expressions need their own graph treatment.
// https://rpm.org/docs/latest/manual/boolean_dependencies
func parseSimpleRPMIf(expression string) (headerDependency, headerDependency, bool) {
	if len(expression) < 5 || expression[0] != '(' || expression[len(expression)-1] != ')' {
		return headerDependency{}, headerDependency{}, false
	}
	inner := strings.TrimSpace(expression[1 : len(expression)-1])
	left, right, found := strings.Cut(inner, " if ")
	if !found || strings.Contains(right, " if ") {
		return headerDependency{}, headerDependency{}, false
	}
	consequence, validLeft := parseRPMRichAtom(left)
	guard, validRight := parseRPMRichAtom(right)
	return consequence, guard, validLeft && validRight && packageName.MatchString(guard.name) && guard.name != "gpg-pubkey"
}

func parseRPMRichAtom(raw string) (headerDependency, bool) {
	fields := strings.Fields(raw)
	if len(fields) != 1 && len(fields) != 3 {
		return headerDependency{}, false
	}
	name := fields[0]
	if !validRPMRichName(name) {
		return headerDependency{}, false
	}
	atom := headerDependency{name: name}
	if len(fields) == 1 {
		return atom, true
	}
	if _, _, _, _, valid := parseRPMEVR(fields[2]); !valid {
		return headerDependency{}, false
	}
	atom.version = fields[2]
	switch fields[1] {
	case "<":
		atom.flags = rpmSenseLess
	case "<=":
		atom.flags = rpmSenseLess | rpmSenseEqual
	case "=":
		atom.flags = rpmSenseEqual
	case ">=":
		atom.flags = rpmSenseGreater | rpmSenseEqual
	case ">":
		atom.flags = rpmSenseGreater
	default:
		return headerDependency{}, false
	}
	return atom, true
}

func validRPMRichName(name string) bool {
	if name == "" || len(name) > 512 || strings.HasPrefix(name, "(") || strings.HasPrefix(name, "/") || strings.HasPrefix(name, "rpmlib(") || strings.ContainsAny(name, "\x00\r\n@#?") || strings.Contains(name, "://") {
		return false
	}
	depth := 0
	for _, char := range name {
		switch char {
		case '(':
			depth++
		case ')':
			depth--
			if depth < 0 {
				return false
			}
		}
	}
	return depth == 0
}

func evaluateRPMGuard(guard headerDependency, known, catalogComplete bool, providers map[string][]rpmProvider) rpmGuardState {
	possible := false
	for _, candidate := range providers[guard.name] {
		condition, matches := rpmConstraint(guard, known, candidate)
		if !matches {
			continue
		}
		if condition == "" {
			return rpmGuardPresent
		}
		possible = true
	}
	if possible || !catalogComplete || !known {
		return rpmGuardUnknown
	}
	return rpmGuardAbsent
}
