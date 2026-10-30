package maven

import (
	"strings"
	"testing"
)

func TestExpandPOMValue(t *testing.T) {
	properties := pomProperties{"release": "3.2.1", "alias": "${release}", "cycle": "${cycle}", "large": strings.Repeat("x", 5000)}
	for _, tc := range []struct {
		input string
		want  string
		ok    bool
	}{
		{"${alias}", "3.2.1", true},
		{"v${release}-final", "v3.2.1-final", true},
		{"${unknown}", "${unknown}", false},
		{"${cycle}", "${cycle}", false},
		{"${large}", "${large}", false},
	} {
		got, ok := expandPOMValue(tc.input, properties)
		if ok != tc.ok || got != tc.want {
			t.Errorf("expandPOMValue(%q) = %q, %t; want %q, %t", tc.input, got, ok, tc.want, tc.ok)
		}
	}
}
