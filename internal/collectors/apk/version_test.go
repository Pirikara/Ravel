package apk

import "testing"

func TestConservativeAPKVersionComparison(t *testing.T) {
	for _, tc := range []struct {
		a, b     string
		want     int
		verified bool
	}{
		{"1.2", "1.2", 0, true},
		{"1.2", "1.2.0", -1, true},
		{"1.2-r0", "1.2", 1, true},
		{"1.2-r1", "1.2-r0", 1, true},
		{"1.2.5-r1", "1.2.3_git20230424", 1, true},
		{"3.5.4-r0", "3.5", 1, true},
		{"1.2-r0", "1.2.0", 0, false},
		{"1.2_alpha", "1.2_beta", 0, false},
		{"01.2", "1.2", 0, false},
	} {
		got, verified := compareVersions(tc.a, tc.b)
		if got != tc.want || verified != tc.verified {
			t.Errorf("compareVersions(%q, %q) = (%d, %t); want (%d, %t)", tc.a, tc.b, got, verified, tc.want, tc.verified)
		}
	}
}

func TestAPKConstraintMatching(t *testing.T) {
	for _, tc := range []struct {
		op, installed, required string
		matched, verified       bool
	}{
		{">=", "1.2.5-r1", "1.2.3_git20230424", true, true},
		{">=", "3.5.4-r0", "3.5", true, true},
		{"<", "3.5.4-r0", "3.5", false, true},
		{"=", "1.2-r0", "1.2-r0", true, true},
		{"=", "1.2-r0", "1.2", false, true},
		{">=", "", "1.0", false, true},
		{"~", "1.2-r0", "1.2", false, false},
	} {
		matched, verified := matchesVersion(tc.op, tc.installed, tc.required)
		if matched != tc.matched || verified != tc.verified {
			t.Errorf("matchesVersion(%q, %q, %q) = (%t, %t); want (%t, %t)", tc.op, tc.installed, tc.required, matched, verified, tc.matched, tc.verified)
		}
	}
}
